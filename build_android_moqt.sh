#!/bin/bash
# Script to build MoQT library for Android

set -e

# Check if ANDROID_NDK_HOME is set
if [ -z "$ANDROID_NDK_HOME" ]; then
    echo "Error: ANDROID_NDK_HOME environment variable is not set"
    echo "Please set it to your Android NDK installation path"
    echo "Example: export ANDROID_NDK_HOME=/path/to/android-ndk"
    exit 1
fi

# Default values
ARCH="arm64"
BUILD_TYPE="opt"
JOBS=8

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --arch)
            ARCH="$2"
            shift 2
            ;;
        --debug)
            BUILD_TYPE="dbg"
            shift
            ;;
        --jobs)
            JOBS="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [options]"
            echo "Options:"
            echo "  --arch <arch>    Target architecture (arm64 or x86_64, default: arm64)"
            echo "  --debug          Build debug version (default: optimized)"
            echo "  --jobs <n>       Number of parallel jobs (default: 8)"
            echo "  --help           Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Validate architecture
if [ "$ARCH" != "arm64" ] && [ "$ARCH" != "x86_64" ]; then
    echo "Error: Invalid architecture. Must be 'arm64' or 'x86_64'"
    exit 1
fi

# Set the build configuration
CONFIG="android_${ARCH}"

echo "Building MoQT for Android ${ARCH}..."
echo "Build type: ${BUILD_TYPE}"
echo "Jobs: ${JOBS}"
echo "Android NDK: ${ANDROID_NDK_HOME}"

# Clean previous builds (optional)
# bazel clean

# Build the library
bazel build //quiche:moqt \
    --config=${CONFIG} \
    --compilation_mode=${BUILD_TYPE} \
    --jobs=${JOBS} \
    --define=ANDROID_NDK_HOME="${ANDROID_NDK_HOME}" \
    --verbose_failures

# Check if build succeeded
if [ $? -eq 0 ]; then
    echo "Build successful!"
    echo "Library location: bazel-bin/quiche/libmoqt.a"
    
    # Display library info
    echo ""
    echo "Library information:"
    ls -la bazel-bin/quiche/libmoqt.a
    file bazel-bin/quiche/libmoqt.a
else
    echo "Build failed!"
    exit 1
fi