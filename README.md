# GhostLock-Galaxy

> 中文: [README_ZH.md](README_ZH.md)

This is a separate repository because this route requires Android shell
permission, obtained through `adb shell` or Shizuku. The original
[YuKongA/ghostlock-app](https://github.com/YuKongA/ghostlock-app) does not use
shell permission and follows a different execution route; its requirements
and code path should not be assumed to be interchangeable with this project.

## Registered kernel profiles

| Device | Kernel |
| ------ | ------ |
| Samsung Galaxy Z Fold6 (SM-F9560 / q6q) | `6.1.145-android14-11-3254009-abF9560ZCS4DZI1` |
| Samsung Galaxy Z Fold6 (SM-F9560 / q6q) | `6.1.145-android14-11-3254009-abF9560ZCS4DZH5` |
| Samsung Galaxy Z Fold6 (SM-F9560 / q6q) | `6.1.145-android14-11-3254009-abF9560ZCS4DZG3` |

At startup the kernel is matched against the offset table via `uname -r`; unsupported kernels are rejected immediately.

## Quick Start

For the APK path, start Shizuku through wireless debugging, grant GhostLock permission, and tap **Run**. Shizuku starts the payload as the Android shell user; the APK itself is not the exploit execution context.

## Command-Line Debugging

The direct command-line path runs the same verified shell payload without requiring Shizuku:

```powershell
make ghostlock helper
adb push ghostlock /data/local/tmp/ghostlock
adb push ghostlock-helper /data/local/tmp/ghostlock-helper
adb push app/src/main/assets/ksud /data/local/tmp/ksud
adb shell chmod 755 /data/local/tmp/ghostlock
adb shell chmod 755 /data/local/tmp/ghostlock-helper
adb shell chmod 755 /data/local/tmp/ksud
adb shell /data/local/tmp/ghostlock
```

The helper is required by the UMH root and KernelSU late-load stages.

## KernelSU 6.1 build notes

On some Samsung/Exynos 6.1 kernels, a generic KernelSU module can trigger an
EL2 panic during `ksud late-load` because the module attempts live text
patching. For affected targets, build a module for the exact firmware release
and enable the target tree's no-patch-text option:

```text
CONFIG_KSU_SAMSUNG_NO_PATCH_TEXT=y
```

Pair the target-specific `kernelsu.ko` and `ksud`, and match the device's
complete `uname -r` rather than only the `6.1` KMI. A reboot during late-load
can come from the module's initialization, not necessarily from the `ksud`
loader. This is a Samsung/Exynos-specific precaution; the current SM-F9560
target is Snapdragon and must be validated separately. See
[Root-My-Galaxy-Payloads](https://github.com/BuSung-dev/Root-My-Galaxy-Payloads)
for target-specific build examples.

## Offset Extraction

On Qualcomm devices, `tools/extract_target.py` parses offsets from `boot.img` and `xbl_config.img`. Requires Python 3 and a kallsyms source (`--kallsyms` file or `--kallsyms-finder`). Passing `--llvm-objdump` (or having `llvm-objdump` on PATH/NDK) additionally disassembles the kernel to auto-derive `pselect_waiter_shift` and `off_slide_loggers_0_1`:

```powershell
python tools/extract_target.py `
  boot.img `
  --xbl-config xbl_config.img `
  --format c `
  --out offsets.h
```

### pselect route feasibility

`core_sys_select` copies only 3 x `FDS_BYTES(nfds)` of user fd_set data onto the kernel stack (qwords 0..14 for nfds=320). The futex waiter must land inside that controllable zone: waiter start word + 11 (lock field) <= 14, i.e. the derived shift (waiter offset from the fd_set in qwords) must be <= 3, or task/lock fall into the kernel-zeroed tail and the route cannot work. The script fails with a clear error when the layout is infeasible.

## Further details & contributions

More details about the payload research and supporting artifacts are available
in [Root-My-Galaxy-Payloads](https://github.com/BuSung-dev/Root-My-Galaxy-Payloads).
Pull requests are welcome.

## Credits & License

Based on the following projects, licensed under Apache License 2.0 (see [LICENSE](LICENSE)):

- [NebuSec/CyberMeowfia](https://github.com/NebuSec/CyberMeowfia)
- [JoinChang/ghostlock-oneplus](https://github.com/JoinChang/ghostlock-oneplus)
- [x-spy/CVE-2026-43499-popsicle](https://github.com/x-spy/CVE-2026-43499-popsicle)
- [YuKongA/ghostlock-app](https://github.com/YuKongA/ghostlock-app)
- [BuSung-dev/Root-My-Galaxy](https://github.com/BuSung-dev/Root-My-Galaxy)
