load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
# -- load statements -- #

def _non_module_deps_impl(ctx):
    http_archive(
        name = "com_google_absl",
        sha256 = "bb5e84fc74362c546ab4193eeafd440a26487f4adf80587d2f2576f03c439c4b",  # Last updated 2024-03-06
        strip_prefix = "abseil-cpp-53e6dae02bf0d9a5a1d304a3d637c083376b86a1",
        urls = ["https://github.com/abseil/abseil-cpp/archive/53e6dae02bf0d9a5a1d304a3d637c083376b86a1.zip"],
    )
    http_archive(
        name = "com_google_googleurl",
        urls = [
            "https://storage.googleapis.com/quiche-envoy-integration/googleurl_9cdb1f4d1a365ebdbcbf179dadf7f8aa5ee802e7.tar.gz",
        ],
        sha256 = "a1bc96169d34dcc1406ffb750deef3bc8718bd1f9069a2878838e1bd905de989",
    )
    http_archive(
        name = "com_google_quic_trace",
        urls = [
            "https://github.com/google/quic-trace/archive/c7b993eb750e60c307e82f75763600d9c06a6de1.tar.gz",
        ],
        sha256 = "079331de8c3cbf145a3b57adb3ad4e73d733ecfa84d3486e1c5a9eaeef286549",
        strip_prefix = "quic-trace-c7b993eb750e60c307e82f75763600d9c06a6de1",
    )

# -- repo definitions -- #

non_module_deps = module_extension(implementation = _non_module_deps_impl)
