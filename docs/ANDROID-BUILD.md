# Android ARM64 build

RAVAN's Android command-line binary is cross-compiled for Rust target `aarch64-linux-android` using the Android NDK.

## Build configuration

- Rust toolchain: `1.100.0` (pinned in both GitHub Actions workflows)
- Rust target: `aarch64-linux-android`
- Android NDK: `30.0.16248370` (NDK r30 LTS)
- Native API level: 21
- NDK compiler: `aarch64-linux-android21-clang`
- Rust dependency resolution: `Cargo.lock` with `--locked`
- GitHub Actions are pinned to reviewed full commit SHAs; Dependabot checks for updates weekly

The API 21 toolchain choice is the 64-bit Android baseline. The project still needs to be tested on real Termux installations; a successful cross-build and ELF inspection do not prove that every Android device or Termux environment will execute it.

## GitHub Actions artifact

The `Android ARM64 Build` workflow compiles the release binary, checks that it is a 64-bit AArch64 ELF executable with Android's `/system/bin/linker64` interpreter, and uploads:

- `ravan-android-arm64`: executable
- `ravan-android-arm64.sha256`: SHA-256 checksum
- `ravan-android-arm64.tar.gz`: archive containing the executable

Artifacts are available from the matching GitHub Actions run for 30 days. They are CI artifacts, not a signed or tagged GitHub Release.

## Manual cross-build

On a Linux build host with the pinned Android NDK installed:

```sh
rustup toolchain install 1.100.0 --profile minimal
rustup target add --toolchain 1.100.0 aarch64-linux-android
export PATH="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=aarch64-linux-android21-clang
export CC_aarch64_linux_android=aarch64-linux-android21-clang
export AR_aarch64_linux_android=llvm-ar
cargo +1.100.0 build --locked --release --target aarch64-linux-android
```

## Device validation still required

The artifact must be copied to an actual ARM64 Termux environment, its SHA-256 checksum verified, and then its `doctor`, configuration, proxy startup, loopback listener, and local SOCKS5 data transfer behavior tested. Do not treat the GitHub build as a Termux runtime test.
