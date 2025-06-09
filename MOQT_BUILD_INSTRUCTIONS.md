# MoQT Library Build Instructions

このドキュメントでは、MoQTライブラリをmacOS ARM64およびUbuntu 24.04 ARM64でビルドする手順を説明します。

## macOS ARM64向けビルド手順

### 前提条件

- macOS (Apple Silicon/ARM64)
- Xcode Command Line Tools
- Homebrew

### Ubuntu 24.04 ARM64向けビルド手順

#### 前提条件

- Ubuntu 24.04 (ARM64)
- インターネット接続

### macOS向けビルド手順

#### 1. Bazelのインストール

Bazeliskを使用してBazelをインストールします：

```bash
# 既存のBazelがある場合はアンリンク
brew unlink bazel 2>/dev/null || true

# Bazeliskをインストール
brew install bazelisk
```

#### 2. ソースコードの準備

```bash
# リポジトリをクローン（既にある場合はスキップ）
git clone https://github.com/google/quiche.git
cd quiche
```

#### 3. BUILD.bazelファイルの修正

`quiche/BUILD.bazel`ファイルを編集して、MoQTライブラリのターゲットを追加します。

1. ファイルの先頭のload文に`moqt_hdrs`と`moqt_srcs`を追加：

```python
load(
    "//build:source_list.bzl",
    # ... 既存のインポート ...
    "moqt_hdrs",
    "moqt_srcs",
    # ... 残りのインポート ...
)
```

2. `masque_support`ライブラリの後に以下を追加：

```python
cc_library(
    name = "moqt",
    srcs = [src for src in moqt_srcs 
            if not src.endswith("_test.cc") 
            and not src.startswith("quic/moqt/test_tools/") 
            and not src.startswith("quic/moqt/tools/")],
    hdrs = [hdr for hdr in moqt_hdrs 
            if not hdr.startswith("quic/moqt/test_tools/") 
            and not hdr.startswith("quic/moqt/tools/")],
    deps = [
        ":io_tool_support",
        ":quiche_core",
        ":quiche_tool_support",
        "@com_google_absl//absl/algorithm:container",
        "@com_google_absl//absl/base",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/cleanup",
        "@com_google_absl//absl/container:btree",
        "@com_google_absl//absl/container:fixed_array",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/container:inlined_vector",
        "@com_google_absl//absl/container:node_hash_map",
        "@com_google_absl//absl/functional:bind_front",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/synchronization",
        "@com_google_absl//absl/types:span",
        "@com_google_absl//absl/types:variant",
    ],
    visibility = ["//visibility:public"],
)
```

3. ファイルの最後に以下のエイリアスを追加：

```python
alias(
    name = "moqt_unstable_api",
    actual = ":moqt",
    visibility = ["//visibility:public"],
)
```

#### 4. C++20の有効化

`.bazelrc`ファイルを編集して、C++17をC++20に変更：

```bash
# .bazelrcファイルを編集
sed -i '' 's/std=c++17/std=c++20/g' .bazelrc
```

#### 5. MoQTライブラリのビルド

```bash
# MoQTライブラリをビルド
bazel build //quiche:moqt --config=macos --jobs=8
```

ビルドには数分かかります。成功すると以下のようなメッセージが表示されます：

```
INFO: Found 1 target...
Target //quiche:moqt up-to-date:
  bazel-bin/quiche/libmoqt.a
INFO: Build completed successfully
```

### ビルド成果物（macOS）

ビルド後、以下の場所にライブラリが生成されます：

- **ライブラリファイル**: `bazel-bin/quiche/libmoqt.a`
- **アーキテクチャ**: arm64 (Apple Silicon)
- **サイズ**: 約6.8MB

アーキテクチャの確認：
```bash
lipo -info bazel-bin/quiche/libmoqt.a
# 出力: Non-fat file: bazel-bin/quiche/libmoqt.a is architecture: arm64
```

## Ubuntu 24.04 ARM64向けビルド手順

### 1. 必要なパッケージのインストール

```bash
# パッケージリストを更新
sudo apt update

# 基本的な開発ツールをインストール
sudo apt install -y build-essential python3 python3-pip git curl
```

### 2. Bazeliskのインストール

```bash
# Bazelisk (ARM64版) をダウンロード
curl -L https://github.com/bazelbuild/bazelisk/releases/latest/download/bazelisk-linux-arm64 -o bazelisk

# 実行権限を付与
chmod +x bazelisk

# システムパスに移動
sudo mv bazelisk /usr/local/bin/bazel

# バージョン確認
bazel version
```

### 3. ソースコードの準備

```bash
# リポジトリをクローン（既にある場合はスキップ）
git clone https://github.com/google/quiche.git
cd quiche
```

### 4. MoQTライブラリのビルド

Ubuntu版では、BUILD.bazelファイルとC++20の設定は既に適切に設定されているため、直接ビルドできます：

```bash
# MoQTライブラリをビルド
bazel build //quiche:moqt --jobs=8
```

ビルドには数分かかります。成功すると以下のようなメッセージが表示されます：

```
INFO: Found 1 target...
Target //quiche:moqt up-to-date:
  bazel-bin/quiche/libmoqt.a
INFO: Build completed successfully
```

### ビルド成果物（Ubuntu）

ビルド後、以下の場所にライブラリが生成されます：

- **ライブラリファイル**: `bazel-bin/quiche/libmoqt.a`
- **アーキテクチャ**: arm64
- **サイズ**: 約13.9MB

アーキテクチャの確認：
```bash
file bazel-bin/quiche/libmoqt.a
# 出力: bazel-bin/quiche/libmoqt.a: current ar archive
```

## ライブラリの使用方法

### 1. ヘッダファイルのインクルード

MoQTを使用するには、以下のヘッダファイルをインクルードしてください：

```cpp
#include "quiche/quic/moqt/moqt_session.h"
#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/quic/moqt/moqt_parser.h"
#include "quiche/quic/moqt/moqt_framer.h"
```

### 2. リンク時の設定

プロジェクトをビルドする際は、以下のライブラリをリンクする必要があります：

- `libmoqt.a` (ビルドしたMoQTライブラリ)
- 依存ライブラリ:
  - Abseil (absl)
  - BoringSSL
  - zlib

### 3. Bazelを使用する場合

`BUILD.bazel`ファイルで以下のように依存関係を追加してください：

```python
cc_binary(
    name = "my_moqt_app",
    srcs = ["main.cc"],
    deps = [
        "//quiche:moqt_unstable_api",
    ],
)
```

### 4. 他のビルドシステムを使用する場合

必要なインクルードパスとライブラリパスを設定してください：

```bash
# インクルードパス
-I/path/to/quiche

# ライブラリパス
-L/path/to/bazel-bin/quiche -lmoqt

# 依存ライブラリ（例）
-labsl_base -labsl_strings -lssl -lcrypto -lz
```

## 再ビルド方法

MoQTライブラリを再ビルドする場合：

**macOS:**
```bash
bazel build //quiche:moqt --config=macos --jobs=8
```

**Ubuntu:**
```bash
bazel build //quiche:moqt --jobs=8
```

## トラブルシューティング

### ビルドエラーの対処法

1. **Bazelバージョンエラー**

   ```text
   ERROR: The project you're trying to build requires Bazel 7.0.0
   ```

   → Bazeliskを使用することで自動的に適切なバージョンがダウンロードされます

2. **C++コンパイルエラー**
   - `constexpr`関連のエラー → C++20の有効化を確認
   - 依存関係のエラー → BUILD.bazelのdeps設定を確認

3. **タイムアウト**
   - `--jobs`オプションでビルド並列数を調整
   - より長いタイムアウトが必要な場合は`--local_cpu_resources`を使用

### Ubuntu固有のトラブルシューティング

1. **パッケージの依存関係エラー**
   - 必要に応じて追加のパッケージをインストール: `sudo apt install -y clang libc++-dev`

2. **メモリ不足**
   - `--jobs`オプションで並列ビルド数を減らす（例: `--jobs=4`）
   - スワップ領域を増やす

3. **ディスク容量不足**
   - Bazelキャッシュをクリア: `bazel clean`
   - 十分なディスク容量（最低10GB推奨）を確保

## 注意事項

- このライブラリはC++20でビルドされています
- macOS ARM64 (Apple Silicon) およびUbuntu 24.04 ARM64をサポートしています
- 依存関係が多いため、プロジェクトへの統合時は注意してください
- `.a`ファイルは静的ライブラリです
