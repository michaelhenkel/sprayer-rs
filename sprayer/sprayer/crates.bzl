"""
@generated
cargo-raze generated Bazel file.

DO NOT EDIT! Replaced on runs of cargo-raze
"""

load("@bazel_tools//tools/build_defs/repo:git.bzl", "new_git_repository")  # buildifier: disable=load
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")  # buildifier: disable=load
load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")  # buildifier: disable=load

def raze_fetch_remote_crates():
    """This function defines a collection of repos and should be called in a WORKSPACE file"""
    maybe(
        http_archive,
        name = "raze__addr2line__0_21_0",
        url = "https://crates.io/api/v1/crates/addr2line/0.21.0/download",
        type = "tar.gz",
        sha256 = "8a30b2e23b9e17a9f90641c7ab1549cd9b44f296d3ccbf309d2863cfe398a0cb",
        strip_prefix = "addr2line-0.21.0",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.addr2line-0.21.0.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__adler__1_0_2",
        url = "https://crates.io/api/v1/crates/adler/1.0.2/download",
        type = "tar.gz",
        sha256 = "f26201604c87b1e01bd3d98f8d5d9a8fcbb815e8cedb41ffccbeb4bf593a35fe",
        strip_prefix = "adler-1.0.2",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.adler-1.0.2.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__ahash__0_8_3",
        url = "https://crates.io/api/v1/crates/ahash/0.8.3/download",
        type = "tar.gz",
        sha256 = "2c99f64d1e06488f620f932677e24bc6e2897582980441ae90a671415bd7ec2f",
        strip_prefix = "ahash-0.8.3",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.ahash-0.8.3.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__aho_corasick__1_0_5",
        url = "https://crates.io/api/v1/crates/aho-corasick/1.0.5/download",
        type = "tar.gz",
        sha256 = "0c378d78423fdad8089616f827526ee33c19f2fddbd5de1629152c9593ba4783",
        strip_prefix = "aho-corasick-1.0.5",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.aho-corasick-1.0.5.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__allocator_api2__0_2_16",
        url = "https://crates.io/api/v1/crates/allocator-api2/0.2.16/download",
        type = "tar.gz",
        sha256 = "0942ffc6dcaadf03badf6e6a2d0228460359d5e34b57ccdc720b7382dfbd5ec5",
        strip_prefix = "allocator-api2-0.2.16",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.allocator-api2-0.2.16.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__anstream__0_5_0",
        url = "https://crates.io/api/v1/crates/anstream/0.5.0/download",
        type = "tar.gz",
        sha256 = "b1f58811cfac344940f1a400b6e6231ce35171f614f26439e80f8c1465c5cc0c",
        strip_prefix = "anstream-0.5.0",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.anstream-0.5.0.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__anstyle__1_0_2",
        url = "https://crates.io/api/v1/crates/anstyle/1.0.2/download",
        type = "tar.gz",
        sha256 = "15c4c2c83f81532e5845a733998b6971faca23490340a418e9b72a3ec9de12ea",
        strip_prefix = "anstyle-1.0.2",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.anstyle-1.0.2.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__anstyle_parse__0_2_1",
        url = "https://crates.io/api/v1/crates/anstyle-parse/0.2.1/download",
        type = "tar.gz",
        sha256 = "938874ff5980b03a87c5524b3ae5b59cf99b1d6bc836848df7bc5ada9643c333",
        strip_prefix = "anstyle-parse-0.2.1",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.anstyle-parse-0.2.1.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__anstyle_query__1_0_0",
        url = "https://crates.io/api/v1/crates/anstyle-query/1.0.0/download",
        type = "tar.gz",
        sha256 = "5ca11d4be1bab0c8bc8734a9aa7bf4ee8316d462a08c6ac5052f888fef5b494b",
        strip_prefix = "anstyle-query-1.0.0",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.anstyle-query-1.0.0.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__anstyle_wincon__2_1_0",
        url = "https://crates.io/api/v1/crates/anstyle-wincon/2.1.0/download",
        type = "tar.gz",
        sha256 = "58f54d10c6dfa51283a066ceab3ec1ab78d13fae00aa49243a45e4571fb79dfd",
        strip_prefix = "anstyle-wincon-2.1.0",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.anstyle-wincon-2.1.0.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__anyhow__1_0_75",
        url = "https://crates.io/api/v1/crates/anyhow/1.0.75/download",
        type = "tar.gz",
        sha256 = "a4668cab20f66d8d020e1fbc0ebe47217433c1b6c8f2040faf858554e394ace6",
        strip_prefix = "anyhow-1.0.75",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.anyhow-1.0.75.bazel"),
    )

    maybe(
        new_git_repository,
        name = "raze__aya__0_11_0",
        remote = "https://github.com/aya-rs/aya",
        commit = "8d3fc49d68b5f75010451d8820a0239e538e41a7",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.aya-0.11.0.bazel"),
        init_submodules = True,
    )

    maybe(
        new_git_repository,
        name = "raze__aya_log__0_1_13",
        remote = "https://github.com/aya-rs/aya",
        commit = "8d3fc49d68b5f75010451d8820a0239e538e41a7",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.aya-log-0.1.13.bazel"),
        init_submodules = True,
    )

    maybe(
        new_git_repository,
        name = "raze__aya_log_common__0_1_13",
        remote = "https://github.com/aya-rs/aya",
        commit = "8d3fc49d68b5f75010451d8820a0239e538e41a7",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.aya-log-common-0.1.13.bazel"),
        init_submodules = True,
    )

    maybe(
        new_git_repository,
        name = "raze__aya_obj__0_1_0",
        remote = "https://github.com/aya-rs/aya",
        commit = "8d3fc49d68b5f75010451d8820a0239e538e41a7",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.aya-obj-0.1.0.bazel"),
        init_submodules = True,
    )

    maybe(
        http_archive,
        name = "raze__backtrace__0_3_69",
        url = "https://crates.io/api/v1/crates/backtrace/0.3.69/download",
        type = "tar.gz",
        sha256 = "2089b7e3f35b9dd2d0ed921ead4f6d318c27680d4a5bd167b3ee120edb105837",
        strip_prefix = "backtrace-0.3.69",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.backtrace-0.3.69.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__bitflags__2_4_0",
        url = "https://crates.io/api/v1/crates/bitflags/2.4.0/download",
        type = "tar.gz",
        sha256 = "b4682ae6287fcf752ecaabbfcc7b6f9b72aa33933dc23a554d853aea8eea8635",
        strip_prefix = "bitflags-2.4.0",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.bitflags-2.4.0.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__bytes__1_4_0",
        url = "https://crates.io/api/v1/crates/bytes/1.4.0/download",
        type = "tar.gz",
        sha256 = "89b2fd2a0dcf38d7971e2194b6b6eebab45ae01067456a7fd93d5547a61b70be",
        strip_prefix = "bytes-1.4.0",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.bytes-1.4.0.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__cc__1_0_83",
        url = "https://crates.io/api/v1/crates/cc/1.0.83/download",
        type = "tar.gz",
        sha256 = "f1174fb0b6ec23863f8b971027804a42614e347eafb0a95bf0b12cdae21fc4d0",
        strip_prefix = "cc-1.0.83",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.cc-1.0.83.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__cfg_if__1_0_0",
        url = "https://crates.io/api/v1/crates/cfg-if/1.0.0/download",
        type = "tar.gz",
        sha256 = "baf1de4339761588bc0619e3cbc0120ee582ebb74b53b4efbf79117bd2da40fd",
        strip_prefix = "cfg-if-1.0.0",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.cfg-if-1.0.0.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__clap__4_4_2",
        url = "https://crates.io/api/v1/crates/clap/4.4.2/download",
        type = "tar.gz",
        sha256 = "6a13b88d2c62ff462f88e4a121f17a82c1af05693a2f192b5c38d14de73c19f6",
        strip_prefix = "clap-4.4.2",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.clap-4.4.2.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__clap_builder__4_4_2",
        url = "https://crates.io/api/v1/crates/clap_builder/4.4.2/download",
        type = "tar.gz",
        sha256 = "2bb9faaa7c2ef94b2743a21f5a29e6f0010dff4caa69ac8e9d6cf8b6fa74da08",
        strip_prefix = "clap_builder-4.4.2",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.clap_builder-4.4.2.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__clap_derive__4_4_2",
        url = "https://crates.io/api/v1/crates/clap_derive/4.4.2/download",
        type = "tar.gz",
        sha256 = "0862016ff20d69b84ef8247369fabf5c008a7417002411897d40ee1f4532b873",
        strip_prefix = "clap_derive-4.4.2",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.clap_derive-4.4.2.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__clap_lex__0_5_1",
        url = "https://crates.io/api/v1/crates/clap_lex/0.5.1/download",
        type = "tar.gz",
        sha256 = "cd7cc57abe963c6d3b9d8be5b06ba7c8957a930305ca90304f24ef040aa6f961",
        strip_prefix = "clap_lex-0.5.1",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.clap_lex-0.5.1.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__colorchoice__1_0_0",
        url = "https://crates.io/api/v1/crates/colorchoice/1.0.0/download",
        type = "tar.gz",
        sha256 = "acbf1af155f9b9ef647e42cdc158db4b64a1b61f743629225fde6f3e0be2a7c7",
        strip_prefix = "colorchoice-1.0.0",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.colorchoice-1.0.0.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__core_error__0_0_0",
        url = "https://crates.io/api/v1/crates/core-error/0.0.0/download",
        type = "tar.gz",
        sha256 = "efcdb2972eb64230b4c50646d8498ff73f5128d196a90c7236eec4cbe8619b8f",
        strip_prefix = "core-error-0.0.0",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.core-error-0.0.0.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__env_logger__0_10_0",
        url = "https://crates.io/api/v1/crates/env_logger/0.10.0/download",
        type = "tar.gz",
        sha256 = "85cdab6a89accf66733ad5a1693a4dcced6aeff64602b634530dd73c1f3ee9f0",
        strip_prefix = "env_logger-0.10.0",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.env_logger-0.10.0.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__errno__0_3_3",
        url = "https://crates.io/api/v1/crates/errno/0.3.3/download",
        type = "tar.gz",
        sha256 = "136526188508e25c6fef639d7927dfb3e0e3084488bf202267829cf7fc23dbdd",
        strip_prefix = "errno-0.3.3",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.errno-0.3.3.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__errno_dragonfly__0_1_2",
        url = "https://crates.io/api/v1/crates/errno-dragonfly/0.1.2/download",
        type = "tar.gz",
        sha256 = "aa68f1b12764fab894d2755d2518754e71b4fd80ecfb822714a1206c2aab39bf",
        strip_prefix = "errno-dragonfly-0.1.2",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.errno-dragonfly-0.1.2.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__gimli__0_28_0",
        url = "https://crates.io/api/v1/crates/gimli/0.28.0/download",
        type = "tar.gz",
        sha256 = "6fb8d784f27acf97159b40fc4db5ecd8aa23b9ad5ef69cdd136d3bc80665f0c0",
        strip_prefix = "gimli-0.28.0",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.gimli-0.28.0.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__hashbrown__0_14_0",
        url = "https://crates.io/api/v1/crates/hashbrown/0.14.0/download",
        type = "tar.gz",
        sha256 = "2c6201b9ff9fd90a5a3bac2e56a830d0caa509576f0e503818ee82c181b3437a",
        strip_prefix = "hashbrown-0.14.0",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.hashbrown-0.14.0.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__heck__0_4_1",
        url = "https://crates.io/api/v1/crates/heck/0.4.1/download",
        type = "tar.gz",
        sha256 = "95505c38b4572b2d910cecb0281560f54b440a19336cbbcb27bf6ce6adc6f5a8",
        strip_prefix = "heck-0.4.1",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.heck-0.4.1.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__hermit_abi__0_3_2",
        url = "https://crates.io/api/v1/crates/hermit-abi/0.3.2/download",
        type = "tar.gz",
        sha256 = "443144c8cdadd93ebf52ddb4056d257f5b52c04d3c804e657d19eb73fc33668b",
        strip_prefix = "hermit-abi-0.3.2",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.hermit-abi-0.3.2.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__humantime__2_1_0",
        url = "https://crates.io/api/v1/crates/humantime/2.1.0/download",
        type = "tar.gz",
        sha256 = "9a3a5bfb195931eeb336b2a7b4d761daec841b97f947d34394601737a7bba5e4",
        strip_prefix = "humantime-2.1.0",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.humantime-2.1.0.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__is_terminal__0_4_9",
        url = "https://crates.io/api/v1/crates/is-terminal/0.4.9/download",
        type = "tar.gz",
        sha256 = "cb0889898416213fab133e1d33a0e5858a48177452750691bde3666d0fdbaf8b",
        strip_prefix = "is-terminal-0.4.9",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.is-terminal-0.4.9.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__lazy_static__1_4_0",
        url = "https://crates.io/api/v1/crates/lazy_static/1.4.0/download",
        type = "tar.gz",
        sha256 = "e2abad23fbc42b3700f2f279844dc832adb2b2eb069b2df918f455c4e18cc646",
        strip_prefix = "lazy_static-1.4.0",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.lazy_static-1.4.0.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__libc__0_2_147",
        url = "https://crates.io/api/v1/crates/libc/0.2.147/download",
        type = "tar.gz",
        sha256 = "b4668fb0ea861c1df094127ac5f1da3409a82116a4ba74fca2e58ef927159bb3",
        strip_prefix = "libc-0.2.147",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.libc-0.2.147.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__linux_raw_sys__0_4_5",
        url = "https://crates.io/api/v1/crates/linux-raw-sys/0.4.5/download",
        type = "tar.gz",
        sha256 = "57bcfdad1b858c2db7c38303a6d2ad4dfaf5eb53dfeb0910128b2c26d6158503",
        strip_prefix = "linux-raw-sys-0.4.5",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.linux-raw-sys-0.4.5.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__log__0_4_20",
        url = "https://crates.io/api/v1/crates/log/0.4.20/download",
        type = "tar.gz",
        sha256 = "b5e6163cb8c49088c2c36f57875e58ccd8c87c7427f7fbd50ea6710b2f3f2e8f",
        strip_prefix = "log-0.4.20",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.log-0.4.20.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__memchr__2_6_2",
        url = "https://crates.io/api/v1/crates/memchr/2.6.2/download",
        type = "tar.gz",
        sha256 = "5486aed0026218e61b8a01d5fbd5a0a134649abb71a0e53b7bc088529dced86e",
        strip_prefix = "memchr-2.6.2",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.memchr-2.6.2.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__miniz_oxide__0_7_1",
        url = "https://crates.io/api/v1/crates/miniz_oxide/0.7.1/download",
        type = "tar.gz",
        sha256 = "e7810e0be55b428ada41041c41f32c9f1a42817901b4ccf45fa3d4b6561e74c7",
        strip_prefix = "miniz_oxide-0.7.1",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.miniz_oxide-0.7.1.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__mio__0_8_8",
        url = "https://crates.io/api/v1/crates/mio/0.8.8/download",
        type = "tar.gz",
        sha256 = "927a765cd3fc26206e66b296465fa9d3e5ab003e651c1b3c060e7956d96b19d2",
        strip_prefix = "mio-0.8.8",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.mio-0.8.8.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__num_cpus__1_16_0",
        url = "https://crates.io/api/v1/crates/num_cpus/1.16.0/download",
        type = "tar.gz",
        sha256 = "4161fcb6d602d4d2081af7c3a45852d875a03dd337a6bfdd6e06407b61342a43",
        strip_prefix = "num_cpus-1.16.0",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.num_cpus-1.16.0.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__num_enum__0_7_0",
        url = "https://crates.io/api/v1/crates/num_enum/0.7.0/download",
        type = "tar.gz",
        sha256 = "70bf6736f74634d299d00086f02986875b3c2d924781a6a2cb6c201e73da0ceb",
        strip_prefix = "num_enum-0.7.0",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.num_enum-0.7.0.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__num_enum_derive__0_7_0",
        url = "https://crates.io/api/v1/crates/num_enum_derive/0.7.0/download",
        type = "tar.gz",
        sha256 = "56ea360eafe1022f7cc56cd7b869ed57330fb2453d0c7831d99b74c65d2f5597",
        strip_prefix = "num_enum_derive-0.7.0",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.num_enum_derive-0.7.0.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__object__0_32_0",
        url = "https://crates.io/api/v1/crates/object/0.32.0/download",
        type = "tar.gz",
        sha256 = "77ac5bbd07aea88c60a577a1ce218075ffd59208b2d7ca97adf9bfc5aeb21ebe",
        strip_prefix = "object-0.32.0",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.object-0.32.0.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__once_cell__1_18_0",
        url = "https://crates.io/api/v1/crates/once_cell/1.18.0/download",
        type = "tar.gz",
        sha256 = "dd8b5dd2ae5ed71462c540258bedcb51965123ad7e7ccf4b9a8cafaa4a63576d",
        strip_prefix = "once_cell-1.18.0",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.once_cell-1.18.0.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__pin_project_lite__0_2_13",
        url = "https://crates.io/api/v1/crates/pin-project-lite/0.2.13/download",
        type = "tar.gz",
        sha256 = "8afb450f006bf6385ca15ef45d71d2288452bc3683ce2e2cacc0d18e4be60b58",
        strip_prefix = "pin-project-lite-0.2.13",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.pin-project-lite-0.2.13.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__proc_macro2__1_0_66",
        url = "https://crates.io/api/v1/crates/proc-macro2/1.0.66/download",
        type = "tar.gz",
        sha256 = "18fb31db3f9bddb2ea821cde30a9f70117e3f119938b5ee630b7403aa6e2ead9",
        strip_prefix = "proc-macro2-1.0.66",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.proc-macro2-1.0.66.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__quote__1_0_33",
        url = "https://crates.io/api/v1/crates/quote/1.0.33/download",
        type = "tar.gz",
        sha256 = "5267fca4496028628a95160fc423a33e8b2e6af8a5302579e322e4b520293cae",
        strip_prefix = "quote-1.0.33",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.quote-1.0.33.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__regex__1_9_4",
        url = "https://crates.io/api/v1/crates/regex/1.9.4/download",
        type = "tar.gz",
        sha256 = "12de2eff854e5fa4b1295edd650e227e9d8fb0c9e90b12e7f36d6a6811791a29",
        strip_prefix = "regex-1.9.4",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.regex-1.9.4.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__regex_automata__0_3_7",
        url = "https://crates.io/api/v1/crates/regex-automata/0.3.7/download",
        type = "tar.gz",
        sha256 = "49530408a136e16e5b486e883fbb6ba058e8e4e8ae6621a77b048b314336e629",
        strip_prefix = "regex-automata-0.3.7",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.regex-automata-0.3.7.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__regex_syntax__0_7_5",
        url = "https://crates.io/api/v1/crates/regex-syntax/0.7.5/download",
        type = "tar.gz",
        sha256 = "dbb5fb1acd8a1a18b3dd5be62d25485eb770e05afb408a9627d14d451bae12da",
        strip_prefix = "regex-syntax-0.7.5",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.regex-syntax-0.7.5.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__rustc_demangle__0_1_23",
        url = "https://crates.io/api/v1/crates/rustc-demangle/0.1.23/download",
        type = "tar.gz",
        sha256 = "d626bb9dae77e28219937af045c257c28bfd3f69333c512553507f5f9798cb76",
        strip_prefix = "rustc-demangle-0.1.23",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.rustc-demangle-0.1.23.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__rustix__0_38_11",
        url = "https://crates.io/api/v1/crates/rustix/0.38.11/download",
        type = "tar.gz",
        sha256 = "c0c3dde1fc030af041adc40e79c0e7fbcf431dd24870053d187d7c66e4b87453",
        strip_prefix = "rustix-0.38.11",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.rustix-0.38.11.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__signal_hook_registry__1_4_1",
        url = "https://crates.io/api/v1/crates/signal-hook-registry/1.4.1/download",
        type = "tar.gz",
        sha256 = "d8229b473baa5980ac72ef434c4415e70c4b5e71b423043adb4ba059f89c99a1",
        strip_prefix = "signal-hook-registry-1.4.1",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.signal-hook-registry-1.4.1.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__socket2__0_5_3",
        url = "https://crates.io/api/v1/crates/socket2/0.5.3/download",
        type = "tar.gz",
        sha256 = "2538b18701741680e0322a2302176d3253a35388e2e62f172f64f4f16605f877",
        strip_prefix = "socket2-0.5.3",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.socket2-0.5.3.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__strsim__0_10_0",
        url = "https://crates.io/api/v1/crates/strsim/0.10.0/download",
        type = "tar.gz",
        sha256 = "73473c0e59e6d5812c5dfe2a064a6444949f089e20eec9a2e5506596494e4623",
        strip_prefix = "strsim-0.10.0",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.strsim-0.10.0.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__syn__2_0_29",
        url = "https://crates.io/api/v1/crates/syn/2.0.29/download",
        type = "tar.gz",
        sha256 = "c324c494eba9d92503e6f1ef2e6df781e78f6a7705a0202d9801b198807d518a",
        strip_prefix = "syn-2.0.29",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.syn-2.0.29.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__termcolor__1_2_0",
        url = "https://crates.io/api/v1/crates/termcolor/1.2.0/download",
        type = "tar.gz",
        sha256 = "be55cf8942feac5c765c2c993422806843c9a9a45d4d5c407ad6dd2ea95eb9b6",
        strip_prefix = "termcolor-1.2.0",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.termcolor-1.2.0.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__thiserror__1_0_47",
        url = "https://crates.io/api/v1/crates/thiserror/1.0.47/download",
        type = "tar.gz",
        sha256 = "97a802ec30afc17eee47b2855fc72e0c4cd62be9b4efe6591edde0ec5bd68d8f",
        strip_prefix = "thiserror-1.0.47",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.thiserror-1.0.47.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__thiserror_impl__1_0_47",
        url = "https://crates.io/api/v1/crates/thiserror-impl/1.0.47/download",
        type = "tar.gz",
        sha256 = "6bb623b56e39ab7dcd4b1b98bb6c8f8d907ed255b18de254088016b27a8ee19b",
        strip_prefix = "thiserror-impl-1.0.47",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.thiserror-impl-1.0.47.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__tokio__1_32_0",
        url = "https://crates.io/api/v1/crates/tokio/1.32.0/download",
        type = "tar.gz",
        sha256 = "17ed6077ed6cd6c74735e21f37eb16dc3935f96878b1fe961074089cc80893f9",
        strip_prefix = "tokio-1.32.0",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.tokio-1.32.0.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__tokio_macros__2_1_0",
        url = "https://crates.io/api/v1/crates/tokio-macros/2.1.0/download",
        type = "tar.gz",
        sha256 = "630bdcf245f78637c13ec01ffae6187cca34625e8c63150d424b59e55af2675e",
        strip_prefix = "tokio-macros-2.1.0",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.tokio-macros-2.1.0.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__unicode_ident__1_0_11",
        url = "https://crates.io/api/v1/crates/unicode-ident/1.0.11/download",
        type = "tar.gz",
        sha256 = "301abaae475aa91687eb82514b328ab47a211a533026cb25fc3e519b86adfc3c",
        strip_prefix = "unicode-ident-1.0.11",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.unicode-ident-1.0.11.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__utf8parse__0_2_1",
        url = "https://crates.io/api/v1/crates/utf8parse/0.2.1/download",
        type = "tar.gz",
        sha256 = "711b9620af191e0cdc7468a8d14e709c3dcdb115b36f838e601583af800a370a",
        strip_prefix = "utf8parse-0.2.1",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.utf8parse-0.2.1.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__version_check__0_9_4",
        url = "https://crates.io/api/v1/crates/version_check/0.9.4/download",
        type = "tar.gz",
        sha256 = "49874b5167b65d7193b8aba1567f5c7d93d001cafc34600cee003eda787e483f",
        strip_prefix = "version_check-0.9.4",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.version_check-0.9.4.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__wasi__0_11_0_wasi_snapshot_preview1",
        url = "https://crates.io/api/v1/crates/wasi/0.11.0+wasi-snapshot-preview1/download",
        type = "tar.gz",
        sha256 = "9c8d87e72b64a3b4db28d11ce29237c246188f4f51057d65a7eab63b7987e423",
        strip_prefix = "wasi-0.11.0+wasi-snapshot-preview1",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.wasi-0.11.0+wasi-snapshot-preview1.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__winapi__0_3_9",
        url = "https://crates.io/api/v1/crates/winapi/0.3.9/download",
        type = "tar.gz",
        sha256 = "5c839a674fcd7a98952e593242ea400abe93992746761e38641405d28b00f419",
        strip_prefix = "winapi-0.3.9",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.winapi-0.3.9.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__winapi_i686_pc_windows_gnu__0_4_0",
        url = "https://crates.io/api/v1/crates/winapi-i686-pc-windows-gnu/0.4.0/download",
        type = "tar.gz",
        sha256 = "ac3b87c63620426dd9b991e5ce0329eff545bccbbb34f3be09ff6fb6ab51b7b6",
        strip_prefix = "winapi-i686-pc-windows-gnu-0.4.0",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.winapi-i686-pc-windows-gnu-0.4.0.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__winapi_util__0_1_5",
        url = "https://crates.io/api/v1/crates/winapi-util/0.1.5/download",
        type = "tar.gz",
        sha256 = "70ec6ce85bb158151cae5e5c87f95a8e97d2c0c4b001223f33a334e3ce5de178",
        strip_prefix = "winapi-util-0.1.5",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.winapi-util-0.1.5.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__winapi_x86_64_pc_windows_gnu__0_4_0",
        url = "https://crates.io/api/v1/crates/winapi-x86_64-pc-windows-gnu/0.4.0/download",
        type = "tar.gz",
        sha256 = "712e227841d057c1ee1cd2fb22fa7e5a5461ae8e48fa2ca79ec42cfc1931183f",
        strip_prefix = "winapi-x86_64-pc-windows-gnu-0.4.0",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.winapi-x86_64-pc-windows-gnu-0.4.0.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__windows_sys__0_48_0",
        url = "https://crates.io/api/v1/crates/windows-sys/0.48.0/download",
        type = "tar.gz",
        sha256 = "677d2418bec65e3338edb076e806bc1ec15693c5d0104683f2efe857f61056a9",
        strip_prefix = "windows-sys-0.48.0",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.windows-sys-0.48.0.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__windows_targets__0_48_5",
        url = "https://crates.io/api/v1/crates/windows-targets/0.48.5/download",
        type = "tar.gz",
        sha256 = "9a2fa6e2155d7247be68c096456083145c183cbbbc2764150dda45a87197940c",
        strip_prefix = "windows-targets-0.48.5",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.windows-targets-0.48.5.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__windows_aarch64_gnullvm__0_48_5",
        url = "https://crates.io/api/v1/crates/windows_aarch64_gnullvm/0.48.5/download",
        type = "tar.gz",
        sha256 = "2b38e32f0abccf9987a4e3079dfb67dcd799fb61361e53e2882c3cbaf0d905d8",
        strip_prefix = "windows_aarch64_gnullvm-0.48.5",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.windows_aarch64_gnullvm-0.48.5.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__windows_aarch64_msvc__0_48_5",
        url = "https://crates.io/api/v1/crates/windows_aarch64_msvc/0.48.5/download",
        type = "tar.gz",
        sha256 = "dc35310971f3b2dbbf3f0690a219f40e2d9afcf64f9ab7cc1be722937c26b4bc",
        strip_prefix = "windows_aarch64_msvc-0.48.5",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.windows_aarch64_msvc-0.48.5.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__windows_i686_gnu__0_48_5",
        url = "https://crates.io/api/v1/crates/windows_i686_gnu/0.48.5/download",
        type = "tar.gz",
        sha256 = "a75915e7def60c94dcef72200b9a8e58e5091744960da64ec734a6c6e9b3743e",
        strip_prefix = "windows_i686_gnu-0.48.5",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.windows_i686_gnu-0.48.5.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__windows_i686_msvc__0_48_5",
        url = "https://crates.io/api/v1/crates/windows_i686_msvc/0.48.5/download",
        type = "tar.gz",
        sha256 = "8f55c233f70c4b27f66c523580f78f1004e8b5a8b659e05a4eb49d4166cca406",
        strip_prefix = "windows_i686_msvc-0.48.5",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.windows_i686_msvc-0.48.5.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__windows_x86_64_gnu__0_48_5",
        url = "https://crates.io/api/v1/crates/windows_x86_64_gnu/0.48.5/download",
        type = "tar.gz",
        sha256 = "53d40abd2583d23e4718fddf1ebec84dbff8381c07cae67ff7768bbf19c6718e",
        strip_prefix = "windows_x86_64_gnu-0.48.5",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.windows_x86_64_gnu-0.48.5.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__windows_x86_64_gnullvm__0_48_5",
        url = "https://crates.io/api/v1/crates/windows_x86_64_gnullvm/0.48.5/download",
        type = "tar.gz",
        sha256 = "0b7b52767868a23d5bab768e390dc5f5c55825b6d30b86c844ff2dc7414044cc",
        strip_prefix = "windows_x86_64_gnullvm-0.48.5",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.windows_x86_64_gnullvm-0.48.5.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__windows_x86_64_msvc__0_48_5",
        url = "https://crates.io/api/v1/crates/windows_x86_64_msvc/0.48.5/download",
        type = "tar.gz",
        sha256 = "ed94fce61571a4006852b7389a063ab983c02eb1bb37b47f8272ce92d06d9538",
        strip_prefix = "windows_x86_64_msvc-0.48.5",
        build_file = Label("//tc-egress/tc-egress/remote:BUILD.windows_x86_64_msvc-0.48.5.bazel"),
    )
