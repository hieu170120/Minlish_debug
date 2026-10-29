# Frida Server Binary

The `frida-server` binary exceeds GitHub's 100 MB file limit (~116 MB uncompressed) and is excluded from source control via `.gitignore`.

### Setup Instructions

1. Download Frida server version **17.19.0** matching your Android architecture from [Frida Releases](https://github.com/frida/frida/releases/tag/17.19.0):
   - For Android x86_64 emulator: `frida-server-17.19.0-android-x86_64.xz`
   - For Android arm64 device/emulator: `frida-server-17.19.0-android-arm64.xz`
2. Extract the `.xz` archive to get the `frida-server` binary.
3. Place `frida-server` into this directory (`frida-server/`).
4. Push and run the server on your target device or emulator:
   ```bash
   adb root
   adb push frida-server /data/local/tmp/
   adb shell chmod 755 /data/local/tmp/frida-server
   adb shell "/data/local/tmp/frida-server &"
   ```
5. Verify connectivity:
   ```bash
   frida-ps -U
   ```
