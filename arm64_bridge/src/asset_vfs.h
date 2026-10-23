// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <vector>

struct AAssetManager;

namespace AssetVfs {

// A read-only stream backed by an OBB entry. In release mode the backing
// bytes stay in the APK AssetManager; only bounded caller buffers are used.
// The definition is intentionally opaque so libc thunks cannot depend on the
// container implementation.
struct ReadHandle {
    ReadHandle() = default;
    ~ReadHandle();
    ReadHandle(const ReadHandle&) = delete;
    ReadHandle& operator=(const ReadHandle&) = delete;
    void* state = nullptr;
};

// Prefer the release whole-container base-obb reader. If no embedded
// containers are present, use the original whole external OBB containers from
// Context.getObbDir() without extracting them. Retain the legacy
// assets/data materialization path only for development diagnostics; the
// release source does not contain that flattened tree.
bool Prepare(AAssetManager* manager, const std::string& external_files_dir,
             const std::string& external_obb_dir);

// Translate a read-only guest path to the published extraction root. The
// caller owns the fallback to the original path when the translated file is
// absent; this keeps mixed embedded/external content working. Installer
// metadata reads prefer the writable sidecar copy when it exists.
bool TranslateReadPath(const char* guest_path, std::string& host_path);

// Translate the small set of installer-generated metadata files that the
// native game opens for read/write into app-private sidecars. Other guest
// paths remain read-only so save-game writes cannot be redirected into the
// embedded resource tree.
bool TranslateMutablePath(const char* guest_path, std::string& host_path);

// Direct whole-container reader used by the release base-obb/split-obb
// layout. The guest path uses the legacy OBB roots; the returned handle owns
// only an index entry and a cursor, never a materialized cache file.
std::shared_ptr<ReadHandle> OpenReadHandle(const char* guest_path);
ssize_t Read(ReadHandle* handle, void* output, size_t count);
ssize_t PRead(ReadHandle* handle, void* output, size_t count, off64_t offset);
off64_t Seek(ReadHandle* handle, off64_t offset, int whence);
off64_t Tell(ReadHandle* handle);
off64_t Size(ReadHandle* handle);
int StatReadPath(const char* guest_path, struct stat* output);
bool ListReadDirectory(const char* guest_path, std::vector<std::string>& names,
                       std::vector<bool>& directories);
bool DirectEnabled();

bool Enabled();

}  // namespace AssetVfs
