# Third-party notices

The project's original code is licensed under `GPL-3.0-or-later`. Dependencies are referenced by Git submodules and fetched from their upstream repositories; their source files are not stored in this repository. Preserve their own copyright and license notices when redistributing them. The table lists dependencies used by the AArch64 build.

| Component | Submodule location | License |
| --- | --- | --- |
| Dynarmic 6.7.0 | `arm64_bridge/third_party/dynarmic` | 0BSD; see `LICENSE.txt` and per-file notices |
| Boost 1.83 headers | `arm64_bridge/third_party/boost` | Boost Software License 1.0; see `LICENSE_1_0.txt` and per-file notices |
| {fmt} | `arm64_bridge/third_party/dynarmic/externals/fmt` | MIT, with the upstream optional object-code exception; see `LICENSE` |
| mcl | `arm64_bridge/third_party/dynarmic/externals/mcl` | MIT; see `LICENSE` |
| oaknut | `arm64_bridge/third_party/dynarmic/externals/oaknut` | MIT; see `LICENSE` |
| robin-map | `arm64_bridge/third_party/dynarmic/externals/robin-map` | MIT; see `LICENSE` |

The upstream dependency trees contain their source notices, including any notices for individual algorithms. Other packages fetched by recursive submodule initialization retain the licenses supplied in their own repositories.

`arm64_bridge/patches/dynarmic-android.patch` preserves the upstream 0BSD licensing for the modified Dynarmic files. It is applied to a build copy and does not modify the checked-out submodule.

The custom input patch contains small original context/removal excerpts to identify the application changes. Those excerpts retain their original ownership; GPL licensing covers this project's additions. No complete original game source files or game binaries are included.
