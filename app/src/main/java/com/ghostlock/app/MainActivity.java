package com.ghostlock.app;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.ComponentName;
import android.content.ServiceConnection;
import android.content.pm.PackageManager;
import android.content.res.ColorStateList;
import android.graphics.Insets;
import android.graphics.drawable.GradientDrawable;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.ParcelFileDescriptor;
import android.text.SpannableStringBuilder;
import android.text.Spanned;
import android.text.style.ForegroundColorSpan;
import android.view.View;
import android.view.Window;
import android.view.WindowInsets;
import android.view.WindowInsetsController;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import rikka.shizuku.Shizuku;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

public class MainActivity extends Activity {
    private static final String TAG = "GhostLockApp";
    private static final String BINARY_NAME = "libghostlock.so";
    private static final String HELPER_NAME = "ghostlock-helper";
    private static final String KSUD_NAME = "ksud";
    private static final String HELPER_ASSET = HELPER_NAME;
    private static final String KSUD_ASSET = KSUD_NAME;
    private static final String RUN_LOG_NAME = "ghostlock-run.log";
    private static final int SHIZUKU_PERMISSION_REQUEST = 43499;
    private static final int COLOR_RED = 0xFFFF6B6B;
    private static final int COLOR_GREEN = 0xFF5FD68A;
    private static final int COLOR_YELLOW = 0xFFFFC94D;
    private final Handler ui = new Handler(Looper.getMainLooper());
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final StringBuilder logBuffer = new StringBuilder();
    private final Object logFileLock = new Object();
    private FileOutputStream logFileOut;
    private TextView deviceInfo;
    private TextView statusInfo;
    private TextView logView;
    private View statusDot;
    private View statusChip;
    private LinearLayout kernelChip;
    private TextView kernelChipText;
    private ScrollView logScroll;
    private Button runButton;
    private Button copyButton;
    private View rootView;
    private Shizuku.UserServiceArgs shellServiceArgs;
    private IGhostlockShell shellService;
    private boolean shellServiceBound;
    private boolean permissionRequestPending;
    private File stagedBinary;
    private File stagedHelper;
    private File stagedKsud;

    private final Shizuku.OnBinderReceivedListener binderListener =
            () -> appendLog("[app] Shizuku binder ready uid=" + safeShizukuUid());

    private final Shizuku.OnRequestPermissionResultListener permissionListener =
            (requestCode, grantResult) -> {
                if (requestCode != SHIZUKU_PERMISSION_REQUEST) {
                    return;
                }
                permissionRequestPending = false;
                if (grantResult == PackageManager.PERMISSION_GRANTED) {
                    appendLog("[+] Shizuku permission granted");
                    beginShellRun();
                } else {
                    appendLog("[-] Shizuku shell permission denied");
                }
            };

    private final ServiceConnection shellServiceConnection = new ServiceConnection() {
        @Override
        public void onServiceConnected(ComponentName name, IBinder service) {
            shellService = IGhostlockShell.Stub.asInterface(service);
            appendLog("[+] Shizuku shell user service connected uid=" + safeShizukuUid());
            worker.execute(() -> sendPayloadToShell(shellService));
        }

        @Override
        public void onServiceDisconnected(ComponentName name) {
            shellService = null;
            shellServiceBound = false;
            if (running.get()) {
                appendLog("[-] Shizuku shell user service disconnected");
                finishRun(1);
            }
        }
    };

    private final IGhostlockShellCallback shellCallback = new IGhostlockShellCallback.Stub() {
        @Override
        public void onOutput(String line) {
            appendLog(line);
        }

        @Override
        public void onExit(int code) {
            finishRun(code);
        }
    };

    /**
     * Mirrors the offset tables under src/devices: only these uname builds are supported.
     */
    private static boolean isKernelSupported() {
        String version = System.getProperty("os.version", "");
        for (String supported : SupportedKernels.UNAMES) {
            if (supported.equals(version)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Returns the value when it looks like a real device name, else null.
     */
    private static String validDeviceName(String value) {
        if (value == null) {
            return null;
        }
        String v = value.trim();
        if (v.isEmpty()) {
            return null;
        }
        String lower = v.toLowerCase(Locale.ROOT);
        if (lower.contains("unknown") || lower.contains("null")) {
            return null;
        }
        return v;
    }

    @SuppressLint("PrivateApi")
    private static String getSystemProperty(String key) {
        try {
            Class<?> props = Class.forName("android.os.SystemProperties");
            Object value = props.getMethod("get", String.class).invoke(null, key);
            return value instanceof String ? (String) value : "";
        } catch (Throwable ignored) {
            return "";
        }
    }

    /**
     * Color a whole log line by its leading marker. The native binary only
     * colors the "[..]" prefix (message text stays default) and the script log
     * is plain text, so per-line coloring is what makes the log readable.
     */
    private static CharSequence colorize(String line) {
        int color = markerColor(line);
        if (color == -1) {
            return line;
        }
        SpannableStringBuilder sb = new SpannableStringBuilder(line);
        sb.setSpan(new ForegroundColorSpan(color), 0, line.length(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
        return sb;
    }

    private static int markerColor(String line) {
        if (line.startsWith("[+]")) return COLOR_GREEN;
        if (line.startsWith("[-]") || line.startsWith("[!]")) return COLOR_RED;
        if (line.startsWith("[*]")) return COLOR_YELLOW;
        if (line.startsWith("error") || line.startsWith("Error")) return COLOR_RED;
        if (line.startsWith("warning")) return COLOR_YELLOW;
        return -1;
    }

    private static String stripAnsi(String input) {
        return input.replaceAll("\u001B\\[[;\\d]*m", "");
    }

    private static void copyStream(InputStream in, OutputStream out) throws IOException {
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) >= 0) {
            out.write(buf, 0, n);
        }
        out.flush();
    }

    private void copyAsset(String assetName, File dst) throws IOException {
        try (InputStream in = getAssets().open(assetName);
             OutputStream out = new FileOutputStream(dst, false)) {
            copyStream(in, out);
        }
    }

    private static void setViewColor(View view, int color) {
        if (view.getBackground() instanceof GradientDrawable) {
            ((GradientDrawable) view.getBackground().mutate()).setColor(color);
        } else {
            view.setBackgroundTintList(ColorStateList.valueOf(color));
        }
    }

    private static String firstValidProperty(String... keys) {
        for (String key : keys) {
            String value = validDeviceName(getSystemProperty(key));
            if (value != null) {
                return value;
            }
        }
        return null;
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        setupSystemBars();

        rootView = findViewById(R.id.root);
        deviceInfo = findViewById(R.id.deviceInfo);
        statusInfo = findViewById(R.id.statusInfo);
        statusDot = findViewById(R.id.statusDot);
        statusChip = findViewById(R.id.statusChip);
        logView = findViewById(R.id.logView);
        logScroll = findViewById(R.id.logScroll);
        runButton = findViewById(R.id.runButton);
        copyButton = findViewById(R.id.copyButton);
        kernelChip = findViewById(R.id.kernelChip);
        kernelChipText = findViewById(R.id.kernelChipText);

        applyWindowInsetsPadding();
        deviceInfo.setText(buildDeviceSummary());
        applyKernelStatus();
        setRunState(RunState.IDLE, getString(R.string.status_idle));
        loadPreviousRunLog();

        shellServiceArgs = new Shizuku.UserServiceArgs(
                new ComponentName(this, ShellUserService.class))
                .tag("ghostlock-shell")
                .version(1)
                .processNameSuffix("shell")
                .daemon(false);
        Shizuku.addBinderReceivedListenerSticky(binderListener);
        Shizuku.addRequestPermissionResultListener(permissionListener);

        runButton.setOnClickListener(v -> startExploit());
        copyButton.setOnClickListener(v -> copyLogs());
    }

    @Override
    protected void onDestroy() {
        Shizuku.removeBinderReceivedListener(binderListener);
        Shizuku.removeRequestPermissionResultListener(permissionListener);
        if (shellService != null) {
            try {
                shellService.stop();
            } catch (Throwable ignored) {
            }
        }
        if (shellServiceBound && shellServiceArgs != null) {
            try {
                Shizuku.unbindUserService(shellServiceArgs, shellServiceConnection, true);
            } catch (Throwable ignored) {
            }
        }
        worker.shutdownNow();
        super.onDestroy();
    }

    private void setupSystemBars() {
        Window window = getWindow();
        int barColor = getColor(R.color.status_bar);

        window.clearFlags(WindowManager.LayoutParams.FLAG_TRANSLUCENT_STATUS | WindowManager.LayoutParams.FLAG_TRANSLUCENT_NAVIGATION);
        window.addFlags(WindowManager.LayoutParams.FLAG_DRAWS_SYSTEM_BAR_BACKGROUNDS);
        window.setStatusBarColor(barColor);
        window.setNavigationBarColor(getColor(R.color.nav_bar));

        window.setStatusBarContrastEnforced(false);
        window.setNavigationBarContrastEnforced(false);

        WindowInsetsController controller = window.getInsetsController();
        if (controller != null) {
            int lightStatus = getResources().getBoolean(R.bool.window_light_status_bar) ? WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS : 0;
            int lightNav = getResources().getBoolean(R.bool.window_light_navigation_bar) ? WindowInsetsController.APPEARANCE_LIGHT_NAVIGATION_BARS : 0;
            controller.setSystemBarsAppearance(lightStatus | lightNav, WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS | WindowInsetsController.APPEARANCE_LIGHT_NAVIGATION_BARS);
        }
    }

    private void applyWindowInsetsPadding() {
        rootView.setOnApplyWindowInsetsListener((v, insets) -> {
            int top;
            int bottom;
            Insets bars = insets.getInsets(WindowInsets.Type.systemBars());
            top = bars.top;
            bottom = bars.bottom;
            int side = dp(20);
            v.setPadding(side, top + dp(12), side, bottom + dp(12));
            return insets;
        });
        rootView.requestApplyInsets();
    }

    private String buildDeviceSummary() {
        return getString(R.string.device_label) + ": " + resolveDeviceName() + "\n" + getString(R.string.kernel_label) + ": " + System.getProperty("os.version", "unknown");
    }

    private void applyKernelStatus() {
        boolean ok = isKernelSupported();
        int color = getColor(ok ? R.color.status_success : R.color.status_error);
        int bg = getColor(ok ? R.color.status_success_bg : R.color.status_error_bg);
        kernelChipText.setText(ok ? R.string.kernel_supported : R.string.kernel_unsupported);
        kernelChipText.setTextColor(color);
        setViewColor(kernelChip, bg);
    }

    /**
     * Sales/market name of the device, matching the language of the current region.
     */
    private String resolveDeviceName() {
        boolean cn = "CN".equalsIgnoreCase(Locale.getDefault().getCountry());
        String marketName = firstValidProperty(cn ? "ro.vendor.oplus.market.name" : "ro.vendor.oplus.market.enname", cn ? "ro.vendor.oplus.market.enname" : "ro.vendor.oplus.market.name", "ro.product.marketname");
        return marketName != null ? marketName : Build.MANUFACTURER + " " + Build.MODEL;
    }

    private void startExploit() {
        if (running.get() || permissionRequestPending) {
            return;
        }
        if (!isShizukuReady()) {
            return;
        }
        try {
            if (Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED) {
                beginShellRun();
                return;
            }
            if (Shizuku.shouldShowRequestPermissionRationale()) {
                appendLog("[!] Open Shizuku and allow GhostLock shell permission");
                return;
            }
            permissionRequestPending = true;
            appendLog("[*] requesting Shizuku shell permission");
            Shizuku.requestPermission(SHIZUKU_PERMISSION_REQUEST);
        } catch (Throwable t) {
            appendLog("[-] Shizuku permission check failed: " + message(t));
        }
    }

    private boolean isShizukuReady() {
        try {
            if (!Shizuku.pingBinder()) {
                appendLog("[!] Shizuku is not running; start it with wireless debugging first");
                return false;
            }
            if (Shizuku.isPreV11()) {
                appendLog("[-] Shizuku API is too old for the shell user service");
                return false;
            }
            return true;
        } catch (Throwable t) {
            appendLog("[-] Shizuku unavailable: " + message(t));
            return false;
        }
    }

    private int safeShizukuUid() {
        try {
            return Shizuku.getUid();
        } catch (Throwable ignored) {
            return -1;
        }
    }

    private void beginShellRun() {
        if (!running.compareAndSet(false, true)) {
            return;
        }
        setRunState(RunState.RUNNING, getString(R.string.status_running));
        appendLog("==== shell start ====");
        worker.execute(() -> {
            try {
                File workDir = getFilesDir();
                openRunLog(workDir);
                stagedBinary = resolveBinary();
                stagedHelper = preparePayload(workDir, HELPER_ASSET, HELPER_NAME);
                stagedKsud = preparePayload(workDir, KSUD_ASSET, KSUD_NAME);
                appendLog("[*] shell payloads ready; binding Shizuku user service");
                ui.post(this::bindShellUserService);
            } catch (Throwable t) {
                appendLog("[-] prepare shell payload failed: " + message(t));
                finishRun(1);
            }
        });
    }

    private void bindShellUserService() {
        if (!running.get()) {
            return;
        }
        try {
            shellServiceBound = true;
            Shizuku.bindUserService(shellServiceArgs, shellServiceConnection);
        } catch (Throwable t) {
            shellServiceBound = false;
            appendLog("[-] bind Shizuku shell service failed: " + message(t));
            finishRun(1);
        }
    }

    private void sendPayloadToShell(IGhostlockShell remote) {
        if (remote == null || !running.get()) {
            return;
        }
        try (ParcelFileDescriptor binary = ParcelFileDescriptor.open(
                stagedBinary, ParcelFileDescriptor.MODE_READ_ONLY);
             ParcelFileDescriptor helper = ParcelFileDescriptor.open(
                     stagedHelper, ParcelFileDescriptor.MODE_READ_ONLY);
             ParcelFileDescriptor ksud = ParcelFileDescriptor.open(
                     stagedKsud, ParcelFileDescriptor.MODE_READ_ONLY)) {
            remote.run(binary, helper, ksud, shellCallback);
            appendLog("[*] shell payloads sent; Samsung shell route running");
        } catch (Throwable t) {
            appendLog("[-] start shell route failed: " + message(t));
            finishRun(1);
        }
    }

    private void finishRun(int code) {
        ui.post(() -> {
            if (!running.compareAndSet(true, false)) {
                return;
            }
            appendLog("exit code=" + code);
            if (shellServiceBound && shellServiceArgs != null) {
                try {
                    Shizuku.unbindUserService(shellServiceArgs, shellServiceConnection, true);
                } catch (Throwable ignored) {
                }
                shellServiceBound = false;
                shellService = null;
            }
            closeRunLog();
            setRunState(code == 0 ? RunState.SUCCESS : RunState.FAILED,
                    code == 0 ? getString(R.string.status_success)
                            : getString(R.string.status_failed) + " (" + code + ")");
        });
    }

    /**
     * Persist every log line to files/ghostlock-run.log with an fsync per
     * line, so the log survives a kernel panic reboot (page cache alone
     * would lose it).  Reopening the app or
     * `adb shell run-as com.ghostlock.app cat files/ghostlock-run.log`
     * recovers the run up to the crash.
     */
    private void openRunLog(File workDir) {
        synchronized (logFileLock) {
            closeRunLog();
            try {
                logFileOut = new FileOutputStream(new File(workDir, RUN_LOG_NAME), false);
            } catch (IOException ignored) {
                logFileOut = null;
            }
        }
    }

    private void closeRunLog() {
        synchronized (logFileLock) {
            if (logFileOut != null) {
                try {
                    logFileOut.close();
                } catch (IOException ignored) {
                }
                logFileOut = null;
            }
        }
    }

    private void loadPreviousRunLog() {
        File prev = new File(getFilesDir(), RUN_LOG_NAME);
        if (!prev.isFile() || prev.length() == 0) {
            return;
        }
        appendLog("==== previous run log (recovered; last run may have crashed/rebooted the device) ====");
        try (BufferedReader r = new BufferedReader(new FileReader(prev))) {
            String line;
            while ((line = r.readLine()) != null) {
                appendLog(line);
            }
        } catch (IOException ignored) {
        }
    }

    private void setRunState(RunState state, String text) {
        statusInfo.setText(text);
        runButton.setEnabled(state != RunState.RUNNING);
        runButton.setText(state == RunState.RUNNING ? R.string.action_running : R.string.action_run);

        int color;
        int chipBg = switch (state) {
            case RUNNING -> {
                color = getColor(R.color.status_running);
                yield getColor(R.color.status_running_bg);
            }
            case SUCCESS -> {
                color = getColor(R.color.status_success);
                yield getColor(R.color.status_success_bg);
            }
            case FAILED -> {
                color = getColor(R.color.status_error);
                yield getColor(R.color.status_error_bg);
            }
            default -> {
                color = getColor(R.color.status_idle);
                yield getColor(R.color.status_idle_bg);
            }
        };

        statusInfo.setTextColor(color);
        if (statusDot.getBackground() instanceof GradientDrawable) {
            ((GradientDrawable) statusDot.getBackground().mutate()).setColor(color);
        } else {
            statusDot.setBackgroundTintList(ColorStateList.valueOf(color));
        }

        if (statusChip.getBackground() instanceof GradientDrawable) {
            ((GradientDrawable) statusChip.getBackground().mutate()).setColor(chipBg);
        } else {
            statusChip.setBackgroundTintList(ColorStateList.valueOf(chipBg));
        }
    }

    private File resolveBinary() throws IOException {
        File packaged = new File(getApplicationInfo().nativeLibraryDir, BINARY_NAME);
        if (packaged.isFile()) {
            appendLog("binary ready (" + packaged.length() + " bytes)");
            return packaged;
        }
        throw new IOException("missing native binary: " + packaged.getAbsolutePath());
    }

    private File preparePayload(File workDir, String assetName, String fileName)
            throws IOException {
        File out = new File(workDir, fileName);
        copyAsset(assetName, out);
        appendLog("[*] payload ready " + fileName + " (" + out.length() + " bytes)");
        return out;
    }

    private static String message(Throwable t) {
        String message = t.getMessage();
        return message == null ? t.getClass().getSimpleName() : message;
    }

    private void copyLogs() {
        ClipboardManager cm = getSystemService(ClipboardManager.class);
        if (cm == null) {
            return;
        }
        String text;
        synchronized (logBuffer) {
            text = logBuffer.toString();
        }
        cm.setPrimaryClip(ClipData.newPlainText("ghostlock-log", text));
        Toast.makeText(this, R.string.copied, Toast.LENGTH_SHORT).show();
    }

    private void appendLog(String line) {
        if (line == null) {
            return;
        }
        final String msg = line.endsWith("\n") ? line : line + "\n";
        final String plain = stripAnsi(msg);
        synchronized (logBuffer) {
            logBuffer.append(plain);
        }
        synchronized (logFileLock) {
            if (logFileOut != null) {
                try {
                    logFileOut.write(plain.getBytes(StandardCharsets.UTF_8));
                    logFileOut.flush();
                    logFileOut.getFD().sync();
                } catch (IOException ignored) {
                }
            }
        }
        final CharSequence display = colorize(plain);
        ui.post(() -> {
            logView.append(display);
            logScroll.post(() -> logScroll.fullScroll(View.FOCUS_DOWN));
        });
        android.util.Log.i(TAG, plain.trim());
    }

    private int dp(int value) {
        float density = getResources().getDisplayMetrics().density;
        return Math.round(value * density);
    }

    private enum RunState {
        IDLE, RUNNING, SUCCESS, FAILED
    }
}
