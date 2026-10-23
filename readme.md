# arm64-bridge-a7

ARM32-to-ARM64 compatibility bridge for Asphalt 7 on modern Android, with JNI, graphics, audio and touch input support.

The bridge builds an AArch64 `libAndroid.so` that executes the game's A32 native code through Dynarmic. It translates calls between the guest's 32-bit ABI and Android's 64-bit APIs. The native library name stays unchanged because the Android application loads `Android` through `System.loadLibrary`.

This repository contains bridge and control sources, Git submodule references to build dependencies, and Android compatibility patches. Game APKs, OBBs, guest libraries, decompiled application trees, signing keys, saves and device captures are excluded. Obtain the game inputs separately from your own copy.

## What is included

- A32 ELF loading, relocation, guest memory, threading and a Dynarmic execution host.
- JNI adaptation and thunks for libc, EGL/OpenGL ES and OpenSL ES.
- Asset/OBB access, graphics options, FXAA and compatibility fixes used by the bridge.
- Queued touch input, pointer IDs, accelerometer/gyroscope delivery and surface-coordinate handling.
- An Android multitouch patch and the custom graphics settings Java source.
- Dynarmic 6.7.0 and Boost 1.83.0 pinned as Git submodules. Their source code is fetched from upstream repositories rather than stored in this repository.

## Layout

```text
arm64_bridge/
  CMakeLists.txt
  src/                 Native bridge, input handling and compatibility hooks
  third_party/         Boost and Dynarmic Git submodules
  patches/             Android changes applied to a build copy of Dynarmic
controls/
  android-input.patch  Android touch and surface-axis integration changes
  GraphicsSettings.java
LICENSE
THIRD_PARTY_NOTICES.md
```

## Build the native bridge

Requirements: Git, Android NDK r27c (`27.2.12479018`), CMake 3.22 or newer, Ninja and a C++20 compiler supplied by the NDK. The target is `arm64-v8a`, Android API 24 or newer. Put Git, CMake and Ninja on `PATH` and set `ANDROID_NDK_HOME` to your local NDK directory.

Clone with nested dependencies:

```powershell
git clone --recurse-submodules --shallow-submodules https://github.com/phys-winner/arm64-bridge-a7.git
cd arm64-bridge-a7
```

For an existing checkout, run `git submodule update --init --recursive --depth 1 --jobs 8`.

Boost uses its upstream modular header layout; no B2 bootstrap or generated header links are needed. CMake applies `arm64_bridge/patches/dynarmic-android.patch` to a copy in the build directory, preserving the clean upstream submodule. This retains the Android code-cache and silent-logging changes. After submodules are initialized, configuration and compilation do not download dependencies.

From the repository root, in PowerShell:

```powershell
cmake -S arm64_bridge -B build/arm64 -G Ninja `
  "-DCMAKE_TOOLCHAIN_FILE=$env:ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake" `
  -DANDROID_ABI=arm64-v8a `
  -DANDROID_PLATFORM=android-24 `
  -DANDROID_STL=c++_shared `
  -DCMAKE_BUILD_TYPE=Release `
  -DASPHALT7_FINAL_SILENT=ON

cmake --build build/arm64 --parallel
```

The output is `build/arm64/libAndroid.so`. Package the matching NDK `libc++_shared.so` with it when integrating the library into an application. The linker requests 16 KB ELF segment alignment; APK ZIP alignment and device compatibility must also be checked on the final application.

`ASPHALT7_FINAL_SILENT=ON` disables bridge/guest diagnostic logging. The telemetry options in `CMakeLists.txt` are intended for local debugging.

## Android input integration

`controls/android-input.patch` contains the touch and surface-axis changes for the Asphalt 7 v1.1.2h / build 1124 smali baseline. It retains pointer IDs, releases active pointers on cancellation/pause/destruction, uses physical surface coordinates, and keeps renderer width/height in the same order as input coordinates. The C++ side queues delivery onto the guest execution thread.

Apply it to a separate, locally decoded application tree. From the repository root, with the decoded tree in the ignored `app` directory:

```powershell
git apply --check controls/android-input.patch
git apply controls/android-input.patch
```

Run the check first: other APK variants or an already patched tree can require manual integration. This patch covers input and surface dimensions; additional application integration is required to run the complete bridge.

`GraphicsSettings.java` is the custom Android graphics panel. It compiles in the game's application package and expects the adapted `GLGame.getActivityContext()` and `GLGame.getCurrencyResetLanguage()` methods. Its DEX/smali output is not included.

## Runtime scope

This is a compatibility layer for one game, with hooks and symbol addresses tied to its expected native build. The loader expects a separately supplied A32 image at `assets/guest_libs/libAndroid.so`. Embedded OBB lookup uses `assets/base-obb/`; the VFS also supports Android's external OBB directory.

Some hooks target the restored guest image used during development, which differs from the unmodified APK library. Supplying an arbitrary original library is not sufficient to reproduce the complete port. The repository builds the native bridge independently; it does not provide the original application, a complete APK packaging pipeline, or all asset/application patches needed for a playable installation.

Compilation does not establish gameplay correctness, performance, or compatibility with every Android device. Verify the final application on your target devices.

## License

Original bridge code, custom controls and project documentation are licensed under **GNU GPL version 3 or later** (`GPL-3.0-or-later`); see [LICENSE](LICENSE). The grant applies to this project's contributions. It does not relicense game code or the original context/removal lines in the input patch.

Dependencies fetched through submodules retain their own licenses and copyright notices; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). The Dynarmic patch retains the upstream 0BSD license. No rights to the original game's binaries, assets or trademarks are granted. Asphalt 7 is a trademark of its respective owner. This is an unofficial project.
