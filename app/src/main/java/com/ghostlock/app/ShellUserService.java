package com.ghostlock.app;

import android.os.ParcelFileDescriptor;
import android.os.RemoteException;
import android.system.ErrnoException;
import android.system.Os;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * Shizuku user service.  Shizuku starts this class as UID 2000 when its
 * backend is wireless ADB, so the native payload runs through the same shell
 * path as `adb shell /data/local/tmp/ghostlock`.
 */
public final class ShellUserService extends IGhostlockShell.Stub {
    private static final String STAGE_DIR = "/data/local/tmp/.ghostlock-app";
    private static final String BINARY_NAME = "ghostlock";
    private static final String HELPER_NAME = "ghostlock-helper";
    private static final String KSUD_NAME = "ksud";
    private static final String OUTPUT_END = "\u0000ghostlock-output-end\u0000";

    private final Object processLock = new Object();
    private volatile Process process;

    public ShellUserService() {
    }

    @Override
    public void run(ParcelFileDescriptor binary, ParcelFileDescriptor helper,
                    ParcelFileDescriptor ksud, IGhostlockShellCallback callback)
            throws RemoteException {
        synchronized (processLock) {
            if (process != null) {
                throw new RemoteException("GhostLock shell is already running");
            }
            try {
                File stage = new File(STAGE_DIR);
                if (stage.exists() && !stage.isDirectory()) {
                    throw new IOException(STAGE_DIR + " is not a directory");
                }
                if (!stage.exists() && !stage.mkdirs()) {
                    throw new IOException("cannot create " + STAGE_DIR);
                }
                stageFile(binary, new File(stage, BINARY_NAME));
                stageFile(helper, new File(stage, HELPER_NAME));
                stageFile(ksud, new File(stage, KSUD_NAME));
            } catch (Throwable t) {
                closeQuietly(binary);
                closeQuietly(helper);
                closeQuietly(ksud);
                throw new RemoteException("stage shell payload failed: " + message(t));
            }

            Thread worker = new Thread(() -> execute(callback), "ghostlock-shell");
            worker.setDaemon(true);
            worker.start();
        }
    }

    @Override
    public void stop() {
        Process current = process;
        if (current != null) {
            current.destroy();
        }
    }

    private void execute(IGhostlockShellCallback callback) {
        int exitCode = 1;
        File stage = new File(STAGE_DIR);
        try {
            ProcessBuilder builder = new ProcessBuilder(
                    new File(stage, BINARY_NAME).getAbsolutePath());
            builder.directory(stage);
            // Keep stdout/stderr as separate child descriptors, like adb shell.
            // The reader threads below drain both pipes immediately; forwarding
            // a line over Binder must never stall the native timing path.
            builder.redirectErrorStream(false);
            builder.environment().put("GHOSTLOCK_HOME", STAGE_DIR);
            builder.environment().put("TMPDIR", STAGE_DIR);
            builder.environment().put("HOME", STAGE_DIR);
            builder.environment().put("GHOSTLOCK_HELPER_PATH",
                    new File(stage, HELPER_NAME).getAbsolutePath());
            builder.environment().put("GHOSTLOCK_KSUD_PATH",
                    new File(stage, KSUD_NAME).getAbsolutePath());

            Process started = builder.start();
            process = started;

            BlockingQueue<String> output = new LinkedBlockingQueue<>();
            Thread forwarder = new Thread(() -> forwardOutput(callback, output),
                    "ghostlock-output");
            forwarder.setDaemon(true);
            forwarder.start();
            Thread stdoutReader = startOutputReader(started.getInputStream(), output,
                    "stdout");
            Thread stderrReader = startOutputReader(started.getErrorStream(), output,
                    "stderr");

            exitCode = started.waitFor();
            stdoutReader.join();
            stderrReader.join();
            output.offer(OUTPUT_END);
            forwarder.join();
            appendKernelSuLog(callback, new File(stage, ".ghostlock_ksu.log"));
        } catch (Throwable t) {
            sendOutput(callback, "[local] shell service error: " + message(t));
        } finally {
            process = null;
            sendExit(callback, exitCode);
        }
    }

    private static Thread startOutputReader(InputStream stream,
                                            BlockingQueue<String> output,
                                            String streamName) {
        Thread reader = new Thread(() -> {
            try (BufferedReader buffered = new BufferedReader(new InputStreamReader(
                    stream, StandardCharsets.UTF_8))) {
                String line;
                while ((line = buffered.readLine()) != null) {
                    output.offer(line);
                }
            } catch (IOException ignored) {
                // Process shutdown closes the pipe; no diagnostic is needed.
            }
        }, "ghostlock-output-" + streamName);
        reader.setDaemon(true);
        reader.start();
        return reader;
    }

    private static void forwardOutput(IGhostlockShellCallback callback,
                                      BlockingQueue<String> output) {
        try {
            for (;;) {
                String line = output.take();
                if (OUTPUT_END.equals(line)) {
                    return;
                }
                sendOutput(callback, line);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static void stageFile(ParcelFileDescriptor source, File destination)
            throws IOException {
        if (source == null) {
            throw new IOException("missing source fd for " + destination.getName());
        }
        File temporary = new File(destination.getParentFile(), "." + destination.getName() + ".tmp");
        try (ParcelFileDescriptor.AutoCloseInputStream input =
                     new ParcelFileDescriptor.AutoCloseInputStream(source);
             FileOutputStream output = new FileOutputStream(temporary, false)) {
            byte[] buffer = new byte[64 * 1024];
            int count;
            while ((count = input.read(buffer)) != -1) {
                output.write(buffer, 0, count);
            }
            output.getFD().sync();
        }
        chmodExecutable(temporary);
        if (destination.exists() && !destination.delete()) {
            temporary.delete();
            throw new IOException("cannot replace " + destination.getName());
        }
        if (!temporary.renameTo(destination)) {
            temporary.delete();
            throw new IOException("rename failed for " + destination.getName());
        }
        chmodExecutable(destination);
    }

    private static void chmodExecutable(File file) throws IOException {
        try {
            Os.chmod(file.getAbsolutePath(), 0755);
        } catch (ErrnoException e) {
            throw new IOException("chmod failed for " + file.getName(), e);
        }
    }

    private static void appendKernelSuLog(IGhostlockShellCallback callback, File log) {
        if (!log.isFile()) {
            return;
        }
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                new FileInputStream(log), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                sendOutput(callback, line);
            }
        } catch (IOException e) {
            sendOutput(callback, "[local] cannot read late-load log: " + message(e));
        }
    }

    private static void sendOutput(IGhostlockShellCallback callback, String line) {
        if (callback == null) {
            return;
        }
        try {
            callback.onOutput(line);
        } catch (RemoteException ignored) {
        }
    }

    private static void sendExit(IGhostlockShellCallback callback, int code) {
        if (callback == null) {
            return;
        }
        try {
            callback.onExit(code);
        } catch (RemoteException ignored) {
        }
    }

    private static void closeQuietly(ParcelFileDescriptor fd) {
        if (fd == null) {
            return;
        }
        try {
            fd.close();
        } catch (IOException ignored) {
        }
    }

    private static String message(Throwable t) {
        String message = t.getMessage();
        return message == null ? t.getClass().getSimpleName() : message;
    }
}
