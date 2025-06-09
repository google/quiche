# MoQT Library Build Instructions for Android

This document provides instructions for building the MoQT library for Android platforms (x86_64 and ARM64).

## Prerequisites

### 1. Android NDK

Download and install the Android NDK:
```bash
# Download from: https://developer.android.com/ndk/downloads
# Or install via Android Studio SDK Manager

# Set the environment variable
export ANDROID_NDK_HOME=/path/to/android-ndk
```

### 2. Bazel

Install Bazelisk (same as Ubuntu/macOS instructions):
```bash
# For Linux x86_64
curl -L https://github.com/bazelbuild/bazelisk/releases/latest/download/bazelisk-linux-amd64 -o bazelisk

# For macOS
brew install bazelisk

# Make it executable and move to PATH
chmod +x bazelisk
sudo mv bazelisk /usr/local/bin/bazel
```

### 3. Development Tools

Ensure you have the following installed:
- Git
- Python 3
- C++ build tools (g++ or clang++)

## Building MoQT for Android

### Quick Build

Use the provided build script:

```bash
# Build for Android ARM64 (default)
./build_android_moqt.sh

# Build for Android x86_64
./build_android_moqt.sh --arch x86_64

# Build debug version
./build_android_moqt.sh --debug

# Specify number of parallel jobs
./build_android_moqt.sh --jobs 4
```

### Manual Build

If you prefer to run Bazel directly:

#### Android ARM64
```bash
bazel build //quiche:moqt \
    --config=android_arm64 \
    --compilation_mode=opt \
    --jobs=8
```

#### Android x86_64
```bash
bazel build //quiche:moqt \
    --config=android_x86_64 \
    --compilation_mode=opt \
    --jobs=8
```

## Build Output

After successful build:
- **Library location**: `bazel-bin/quiche/libmoqt.a`
- **Headers**: Source headers in `quiche/quic/moqt/`

### Verifying the Build

```bash
# Check the library architecture
file bazel-bin/quiche/libmoqt.a

# For more detailed information (requires Android NDK tools)
$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/*/bin/llvm-ar t bazel-bin/quiche/libmoqt.a | head
```

## Integration in Android Projects

### 1. Native Library Structure

Create the following structure in your Android project:
```
app/src/main/
├── cpp/
│   ├── CMakeLists.txt
│   └── native-lib.cpp
└── jniLibs/
    ├── arm64-v8a/
    │   └── libmoqt.a
    └── x86_64/
        └── libmoqt.a
```

### 2. CMakeLists.txt Example

```cmake
cmake_minimum_required(VERSION 3.10.2)

# Import the prebuilt MoQT library
add_library(moqt STATIC IMPORTED)
set_target_properties(moqt PROPERTIES IMPORTED_LOCATION
    ${CMAKE_SOURCE_DIR}/../jniLibs/${ANDROID_ABI}/libmoqt.a)

# Include MoQT headers
include_directories(/path/to/quiche)

# Your native library
add_library(native-lib SHARED native-lib.cpp)

# Link libraries
find_library(log-lib log)
target_link_libraries(native-lib
    moqt
    ${log-lib}
    # Add other dependencies as needed
)
```

### 3. Gradle Configuration

In your `app/build.gradle`:
```gradle
android {
    ...
    defaultConfig {
        ...
        externalNativeBuild {
            cmake {
                cppFlags "-std=c++20"
                abiFilters "arm64-v8a", "x86_64"
            }
        }
    }
    
    externalNativeBuild {
        cmake {
            path "src/main/cpp/CMakeLists.txt"
        }
    }
}
```

## Known Limitations

1. **Socket Operations**: Some Linux-specific socket features are not available on Android:
   - `sendmmsg()` is not available
   - TTL support may be limited
   - Linux timestamping is not supported

2. **File System**: Android's file system structure differs from standard Linux:
   - App-specific storage restrictions apply
   - External storage requires permissions

3. **Permissions**: Network operations require appropriate Android permissions:
   ```xml
   <uses-permission android:name="android.permission.INTERNET" />
   <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
   ```

## Troubleshooting

### NDK Not Found
```
Error: ANDROID_NDK_HOME environment variable is not set
```
Solution: Set the environment variable to your NDK installation:
```bash
export ANDROID_NDK_HOME=/path/to/android-ndk
```

### Build Errors

1. **Missing dependencies**: Ensure all required tools are installed
2. **ABI mismatch**: Make sure you're building for the correct architecture
3. **C++ standard**: The project requires C++20 support

### Linker Errors

When integrating into Android apps, you may need to link additional libraries:
- `-llog` for Android logging
- `-lz` for zlib compression
- SSL/TLS libraries as needed

## Additional Notes

- The Android build uses the same source code as other platforms
- Platform-specific adaptations are handled through conditional compilation
- For production use, consider stripping debug symbols to reduce library size

## Example Usage

Here's a simple JNI wrapper example:

```cpp
#include <jni.h>
#include "quiche/quic/moqt/moqt_session.h"

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_myapp_MoqtWrapper_getVersion(JNIEnv* env, jobject /* this */) {
    // Your MoQT implementation here
    return env->NewStringUTF("MoQT for Android");
}
```

## Support

For issues specific to Android builds, check:
1. The Android NDK is properly installed and configured
2. All dependencies are built for Android
3. The correct ABI is specified for your target device

For general MoQT questions, refer to the main documentation.