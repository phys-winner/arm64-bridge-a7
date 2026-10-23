// SPDX-License-Identifier: GPL-3.0-or-later
#include "asset_vfs.h"

#include <android/asset_manager.h>
#include <android/log.h>

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <mutex>
#include <array>
#include <limits>
#include <memory>
#include <string_view>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unordered_map>
#include <unordered_set>
#include <unistd.h>
#include <vector>

#define LOG_TAG "Asphalt7Bridge_AssetVfs"
#if defined(ASPHALT7_FINAL_SILENT)
#define LOGI(...) ((void)0)
#define LOGW(...) ((void)0)
#define LOGE(...) ((void)0)
#else
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#endif

namespace {

constexpr std::string_view kGuestRoots[] = {
    "/sdcard/Android/obb/com.gameloft.android.ANMP.GloftA7HM",
    "/mnt/sdcard/Android/obb/com.gameloft.android.ANMP.GloftA7HM",
    "/storage/emulated/0/Android/obb/com.gameloft.android.ANMP.GloftA7HM",
    "/storage/self/primary/Android/obb/com.gameloft.android.ANMP.GloftA7HM",
};
// Game::Init changes the legacy filesystem working directory to the app's
// private files/data directory before opening the embedded resource graph.
// Keep this mapping read-only and disjoint from the metadata sidecar rule so
// save-game writes cannot be redirected into the immutable asset generation.
constexpr std::string_view kGuestAppDataRoots[] = {
    "/data/data/com.gameloft.android.ANMP.GloftA7HM/files",
    "/data/user/0/com.gameloft.android.ANMP.GloftA7HM/files",
    "/data/user_de/0/com.gameloft.android.ANMP.GloftA7HM/files",
};
constexpr size_t kMaxPath = 4096;
constexpr size_t kMaxManifest = 8 * 1024 * 1024;
constexpr size_t kMaxAssets = 100000;
constexpr size_t kCopyChunk = 256 * 1024;
constexpr std::string_view kManifestHeader = "ASSET_VFS_MANIFEST=1\n";
// Version 2 separates immutable extracted assets from installer-generated
// metadata. This invalidates version-1 generations, whose metadata files
// could be truncated by native fopen("w") calls.
constexpr std::string_view kMarkerPrefix = "ASSET_VFS_VERSION=2\nROOT=";

struct AssetFile {
    std::string name;
    int64_t size = 0;
};

std::mutex g_mutex;
bool g_initialized = false;
bool g_prepare_ok = false;
bool g_enabled = false;
bool g_direct_enabled = false;
std::string g_extracted_root;
std::string g_sidecar_root;
// The original filesystem exposes the files selected by BaseCarManager from
// the data root (for example, "Abarth_695TributoFerrari.car"). The shipped
// OBB keeps those files below data/Car/<model>/ and data/TrafficCar/<model>/.
// Build this index from the exact APK asset manifest so the bridge can expose
// only unique, immutable files that are actually present in the generation.
std::unordered_map<std::string, std::string> g_legacy_file_aliases;

constexpr std::string_view kEmbeddedMainObb =
    "base-obb/main.1060.com.gameloft.android.ANMP.GloftA7HM.obb";
constexpr std::string_view kEmbeddedPatchObb =
    "base-obb/patch.1110.com.gameloft.android.ANMP.GloftA7HM.obb";
constexpr std::string_view kExternalMainObb =
    "main.1060.com.gameloft.android.ANMP.GloftA7HM.obb";
constexpr std::string_view kExternalPatchObb =
    "patch.1110.com.gameloft.android.ANMP.GloftA7HM.obb";
constexpr uint64_t kExpectedMainObbSize = 1130474955ull;
constexpr uint64_t kExpectedPatchObbSize = 67953096ull;
constexpr std::string_view kExpectedMainObbSha256 =
    "c883f01bd72af2f2dc8f8f4b577978f806d2977fb0d71cc7c691236b49fa50ef";
constexpr std::string_view kExpectedPatchObbSha256 =
    "799c4be0fd80387b7dbe18259d3a7961f23406032242328c335ecacc4d3b6bf0";
// The original native resource graph registers cars.zip even though the
// shipped OBB pair contains the car packs as data/Car/<model>/*.car and
// *.bdae, not as a cars.zip container. Keep this tiny compatibility asset
// separate from the immutable OBBs so the lookup can be satisfied without
// inventing or duplicating car content. Its runtime usefulness is accepted
// only after the selected-device trace proves that the archive is opened but
// no payload entries are requested from it.
constexpr std::string_view kEmbeddedCarsCompatZip = "data/cars.zip";
constexpr size_t kMaxZipEntries = 100000;
constexpr size_t kMaxZipCentralDirectory = 64 * 1024 * 1024;
constexpr size_t kZipEndRecordSize = 22;
constexpr size_t kZipMaxComment = 0xffff;

struct ArchiveEntry {
    std::string name;
    uint64_t data_offset = 0;
    uint64_t size = 0;
    uint16_t method = 0;
    bool directory = false;
};

struct Archive {
    AAsset* asset = nullptr;
    int fd = -1;
    std::string asset_name;
    uint64_t length = 0;
    std::unordered_map<std::string, ArchiveEntry> entries;
    std::unordered_set<std::string> directories;
    mutable std::mutex mutex;

    ~Archive() {
        if (asset) AAsset_close(asset);
        if (fd >= 0) ::close(fd);
    }
};

struct DirectReadState {
    std::shared_ptr<Archive> archive;
    ArchiveEntry entry;
    std::mutex cursor_mutex;
    uint64_t position = 0;
};

struct IndexedEntry {
    std::shared_ptr<Archive> archive;
    ArchiveEntry entry;
};

std::vector<std::shared_ptr<Archive>> g_archives;
std::unordered_map<std::string, IndexedEntry> g_direct_entries;
std::unordered_set<std::string> g_direct_directories;
std::unordered_map<std::string, std::string> g_direct_aliases;

bool HasPrefix(std::string_view value, std::string_view prefix) {
    return value.size() >= prefix.size() && value.substr(0, prefix.size()) == prefix;
}

bool ValidComponent(std::string_view component) {
    if (component.empty() || component == "." || component == ".." ||
        component.find('/') != std::string_view::npos) {
        return false;
    }
    for (const unsigned char character : component) {
        if (character < 0x20 || character == 0x7f || character == '\\') return false;
    }
    return true;
}

bool ValidRelative(std::string_view relative) {
    if (relative.empty() || relative.size() > kMaxPath || relative.front() == '/' || relative.back() == '/') {
        return relative.empty();
    }
    size_t start = 0;
    while (start < relative.size()) {
        size_t end = relative.find('/', start);
        if (end == std::string_view::npos) end = relative.size();
        if (!ValidComponent(relative.substr(start, end - start))) return false;
        start = end == relative.size() ? end : end + 1;
    }
    return true;
}

bool ValidAbsolutePath(const std::string& path) {
    if (path.empty() || path.size() > kMaxPath || path.front() != '/') return false;
    size_t start = 1;
    while (start < path.size()) {
        size_t end = path.find('/', start);
        if (end == std::string::npos) end = path.size();
        if (!ValidComponent(std::string_view(path).substr(start, end - start))) return false;
        start = end == path.size() ? end : end + 1;
    }
    return true;
}

bool ValidGenerationName(std::string_view name) {
    if (!HasPrefix(name, "gen-") || name.size() > 128) return false;
    for (const unsigned char character : name) {
        if (!((character >= 'a' && character <= 'z') ||
              (character >= 'A' && character <= 'Z') ||
              (character >= '0' && character <= '9') ||
              character == '-' || character == '_')) {
            return false;
        }
    }
    return true;
}

std::string Join(const std::string& parent, std::string_view child) {
    std::string result = parent;
    if (!result.empty() && result.back() != '/') result.push_back('/');
    result.append(child.data(), child.size());
    return result;
}

bool EnsureDirectory(const std::string& path) {
    if (::mkdir(path.c_str(), 0700) == 0) return true;
    if (errno != EEXIST) return false;
    struct stat value{};
    return ::lstat(path.c_str(), &value) == 0 && S_ISDIR(value.st_mode);
}

bool WriteAll(int fd, const void* data, size_t size) {
    const auto* bytes = static_cast<const uint8_t*>(data);
    while (size) {
        const ssize_t written = ::write(fd, bytes, size);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) {
            if (written == 0) errno = EIO;
            return false;
        }
        bytes += written;
        size -= static_cast<size_t>(written);
    }
    return true;
}

uint16_t ReadLe16(const uint8_t* bytes) {
    return static_cast<uint16_t>(bytes[0]) |
           static_cast<uint16_t>(bytes[1]) << 8;
}

uint32_t ReadLe32(const uint8_t* bytes) {
    return static_cast<uint32_t>(bytes[0]) |
           static_cast<uint32_t>(bytes[1]) << 8 |
           static_cast<uint32_t>(bytes[2]) << 16 |
           static_cast<uint32_t>(bytes[3]) << 24;
}

bool ReadAssetBytes(AAsset* asset, uint64_t asset_length, uint64_t offset,
                    void* output, size_t size) {
    if (!asset || offset > asset_length || size > asset_length - offset ||
        offset > static_cast<uint64_t>(std::numeric_limits<off64_t>::max())) {
        errno = EIO;
        return false;
    }
    if (AAsset_seek64(asset, static_cast<off64_t>(offset), SEEK_SET) < 0) {
        errno = EIO;
        return false;
    }
    auto* bytes = static_cast<uint8_t*>(output);
    while (size) {
        const int request = static_cast<int>(std::min<size_t>(size, INT_MAX));
        const int count = AAsset_read(asset, bytes, request);
        if (count <= 0) {
            errno = EIO;
            return false;
        }
        bytes += count;
        size -= static_cast<size_t>(count);
    }
    return true;
}

bool ReadFdBytes(int fd, uint64_t file_length, uint64_t offset,
                 void* output, size_t size) {
    if (fd < 0 || offset > file_length || size > file_length - offset ||
        offset > static_cast<uint64_t>(std::numeric_limits<off64_t>::max())) {
        errno = EIO;
        return false;
    }
    auto* bytes = static_cast<uint8_t*>(output);
    while (size) {
        const size_t request = std::min<size_t>(size, 256 * 1024);
        const ssize_t count = ::pread64(fd, bytes, request, static_cast<off64_t>(offset));
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) {
            errno = count == 0 ? EIO : errno;
            return false;
        }
        bytes += count;
        size -= static_cast<size_t>(count);
        offset += static_cast<uint64_t>(count);
    }
    return true;
}

bool ReadArchiveBytes(const Archive& archive, uint64_t offset,
                      void* output, size_t size) {
    if (archive.asset) {
        return ReadAssetBytes(archive.asset, archive.length, offset, output, size);
    }
    return ReadFdBytes(archive.fd, archive.length, offset, output, size);
}

class Sha256 {
public:
    Sha256() {
        m_state = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
                   0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};
    }

    void Update(const uint8_t* input, size_t size) {
        while (size) {
            const size_t available = m_block.size() - m_block_size;
            const size_t count = std::min(available, size);
            memcpy(m_block.data() + m_block_size, input, count);
            m_block_size += count;
            input += count;
            size -= count;
            if (m_block_size == m_block.size()) {
                Transform(m_block.data());
                m_bit_count += 512;
                m_block_size = 0;
            }
        }
    }

    std::array<uint8_t, 32> Final() {
        const uint64_t total_bits = m_bit_count + static_cast<uint64_t>(m_block_size) * 8;
        m_block[m_block_size++] = 0x80;
        if (m_block_size > 56) {
            while (m_block_size < m_block.size()) m_block[m_block_size++] = 0;
            Transform(m_block.data());
            m_block_size = 0;
        }
        while (m_block_size < 56) m_block[m_block_size++] = 0;
        for (int index = 7; index >= 0; --index) {
            m_block[m_block_size++] = static_cast<uint8_t>(total_bits >> (index * 8));
        }
        Transform(m_block.data());

        std::array<uint8_t, 32> result{};
        for (size_t index = 0; index < m_state.size(); ++index) {
            result[index * 4] = static_cast<uint8_t>(m_state[index] >> 24);
            result[index * 4 + 1] = static_cast<uint8_t>(m_state[index] >> 16);
            result[index * 4 + 2] = static_cast<uint8_t>(m_state[index] >> 8);
            result[index * 4 + 3] = static_cast<uint8_t>(m_state[index]);
        }
        return result;
    }

private:
    static uint32_t RotateRight(uint32_t value, uint32_t count) {
        return (value >> count) | (value << (32 - count));
    }

    static uint32_t Ch(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) ^ (~x & z);
    }

    static uint32_t Maj(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }

    static uint32_t Sigma0(uint32_t value) {
        return RotateRight(value, 2) ^ RotateRight(value, 13) ^ RotateRight(value, 22);
    }

    static uint32_t Sigma1(uint32_t value) {
        return RotateRight(value, 6) ^ RotateRight(value, 11) ^ RotateRight(value, 25);
    }

    static uint32_t Gamma0(uint32_t value) {
        return RotateRight(value, 7) ^ RotateRight(value, 18) ^ (value >> 3);
    }

    static uint32_t Gamma1(uint32_t value) {
        return RotateRight(value, 17) ^ RotateRight(value, 19) ^ (value >> 10);
    }

    void Transform(const uint8_t* block) {
        static constexpr uint32_t kRoundConstants[] = {
            0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
            0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
            0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
            0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
            0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
            0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
            0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
            0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
            0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
            0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
            0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
            0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
            0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
            0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
            0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
            0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
        };
        std::array<uint32_t, 64> schedule{};
        for (size_t index = 0; index < 16; ++index) {
            const size_t offset = index * 4;
            schedule[index] = static_cast<uint32_t>(block[offset]) << 24 |
                              static_cast<uint32_t>(block[offset + 1]) << 16 |
                              static_cast<uint32_t>(block[offset + 2]) << 8 |
                              static_cast<uint32_t>(block[offset + 3]);
        }
        for (size_t index = 16; index < schedule.size(); ++index) {
            schedule[index] = Gamma1(schedule[index - 2]) + schedule[index - 7] +
                              Gamma0(schedule[index - 15]) + schedule[index - 16];
        }

        uint32_t a = m_state[0];
        uint32_t b = m_state[1];
        uint32_t c = m_state[2];
        uint32_t d = m_state[3];
        uint32_t e = m_state[4];
        uint32_t f = m_state[5];
        uint32_t g = m_state[6];
        uint32_t h = m_state[7];
        for (size_t index = 0; index < schedule.size(); ++index) {
            const uint32_t t1 = h + Sigma1(e) + Ch(e, f, g) + kRoundConstants[index] + schedule[index];
            const uint32_t t2 = Sigma0(a) + Maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }
        m_state[0] += a;
        m_state[1] += b;
        m_state[2] += c;
        m_state[3] += d;
        m_state[4] += e;
        m_state[5] += f;
        m_state[6] += g;
        m_state[7] += h;
    }

    std::array<uint32_t, 8> m_state{};
    std::array<uint8_t, 64> m_block{};
    size_t m_block_size = 0;
    uint64_t m_bit_count = 0;
};

std::string HexDigest(const std::array<uint8_t, 32>& digest) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string result;
    result.reserve(digest.size() * 2);
    for (const uint8_t value : digest) {
        result.push_back(kHex[value >> 4]);
        result.push_back(kHex[value & 0x0f]);
    }
    return result;
}

bool HashFileSha256(int fd, uint64_t length, std::string& digest) {
    if (fd < 0 || length == 0) {
        errno = EINVAL;
        return false;
    }
    Sha256 sha256;
    std::array<uint8_t, 256 * 1024> buffer{};
    uint64_t offset = 0;
    while (offset < length) {
        const size_t request = static_cast<size_t>(std::min<uint64_t>(buffer.size(), length - offset));
        const ssize_t count = ::pread64(fd, buffer.data(), request, static_cast<off64_t>(offset));
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) {
            errno = count == 0 ? EIO : errno;
            return false;
        }
        sha256.Update(buffer.data(), static_cast<size_t>(count));
        offset += static_cast<uint64_t>(count);
    }
    digest = HexDigest(sha256.Final());
    return true;
}

void AddArchiveDirectoryParents(const std::string& name,
                                std::unordered_set<std::string>& directories) {
    directories.insert("");
    size_t slash = name.find('/');
    while (slash != std::string::npos) {
        directories.insert(name.substr(0, slash));
        slash = name.find('/', slash + 1);
    }
}

bool ValidArchiveName(std::string_view name, bool directory) {
    if (name.empty() || name.front() == '/' || name.find('\\') != std::string_view::npos) {
        return false;
    }
    while (!name.empty() && name.back() == '/') name.remove_suffix(1);
    if (name.empty()) return directory;
    return ValidRelative(name);
}

bool ParseArchive(const std::shared_ptr<Archive>& archive) {
    if (!archive || (!archive->asset && archive->fd < 0) || archive->length == 0) {
        errno = EINVAL;
        return false;
    }
    const size_t tail_size = static_cast<size_t>(std::min<uint64_t>(archive->length,
                                                                     kZipEndRecordSize + kZipMaxComment));
    if (tail_size < kZipEndRecordSize) {
        LOGE("archive has no room for a ZIP end record source='%s'", archive->asset_name.c_str());
        errno = EINVAL;
        return false;
    }
    std::vector<uint8_t> tail(tail_size);
    if (!ReadArchiveBytes(*archive, archive->length - tail_size, tail.data(), tail.size())) {
        LOGE("cannot read OBB tail source='%s' errno=%d", archive->asset_name.c_str(), errno);
        return false;
    }

    size_t eocd = std::string::npos;
    for (size_t index = tail.size() - kZipEndRecordSize + 1; index-- > 0;) {
        if (ReadLe32(tail.data() + index) != 0x06054b50u) continue;
        if (index + kZipEndRecordSize > tail.size()) continue;
        const uint16_t comment_size = ReadLe16(tail.data() + index + 20);
        if (index + kZipEndRecordSize + comment_size == tail.size()) {
            eocd = index;
            break;
        }
    }
    if (eocd == std::string::npos) {
        LOGE("OBB has no regular ZIP end record source='%s'", archive->asset_name.c_str());
        errno = EINVAL;
        return false;
    }

    const uint16_t disk = ReadLe16(tail.data() + eocd + 4);
    const uint16_t central_disk = ReadLe16(tail.data() + eocd + 6);
    const uint16_t disk_entries = ReadLe16(tail.data() + eocd + 8);
    const uint16_t total_entries = ReadLe16(tail.data() + eocd + 10);
    const uint32_t central_size = ReadLe32(tail.data() + eocd + 12);
    const uint32_t central_offset = ReadLe32(tail.data() + eocd + 16);
    if (disk || central_disk || disk_entries != total_entries ||
        total_entries == 0xffff || central_size == 0xffffffffu ||
        central_offset == 0xffffffffu ||
        central_size > kMaxZipCentralDirectory ||
        static_cast<uint64_t>(central_offset) + central_size > archive->length) {
        LOGE("OBB uses unsupported ZIP64/multi-disk layout source='%s' entries=%u",
             archive->asset_name.c_str(), total_entries);
        errno = ENOTSUP;
        return false;
    }

    std::vector<uint8_t> central(central_size);
    if (!ReadArchiveBytes(*archive, central_offset, central.data(), central.size())) {
        LOGE("cannot read OBB central directory source='%s' errno=%d",
             archive->asset_name.c_str(), errno);
        return false;
    }
    size_t cursor = 0;
    for (uint32_t index = 0; index < total_entries; ++index) {
        if (cursor + 46 > central.size() || ReadLe32(central.data() + cursor) != 0x02014b50u) {
            LOGE("invalid central directory entry source='%s' index=%u",
                 archive->asset_name.c_str(), index);
            errno = EINVAL;
            return false;
        }
        const uint16_t flags = ReadLe16(central.data() + cursor + 8);
        const uint16_t method = ReadLe16(central.data() + cursor + 10);
        const uint32_t compressed_size = ReadLe32(central.data() + cursor + 20);
        const uint32_t uncompressed_size = ReadLe32(central.data() + cursor + 24);
        const uint16_t name_size = ReadLe16(central.data() + cursor + 28);
        const uint16_t extra_size = ReadLe16(central.data() + cursor + 30);
        const uint16_t comment_size = ReadLe16(central.data() + cursor + 32);
        const uint32_t local_offset = ReadLe32(central.data() + cursor + 42);
        const size_t record_size = 46ull + name_size + extra_size + comment_size;
        if (cursor + record_size > central.size()) {
            LOGE("truncated central directory entry source='%s' index=%u",
                 archive->asset_name.c_str(), index);
            errno = EINVAL;
            return false;
        }
        std::string name(reinterpret_cast<const char*>(central.data() + cursor + 46), name_size);
        const bool directory = !name.empty() && name.back() == '/';
        while (!name.empty() && name.back() == '/') name.pop_back();
        if (!ValidArchiveName(name, directory) || (flags & 1u) ||
            compressed_size != uncompressed_size || method != 0 ||
            local_offset > archive->length || compressed_size > archive->length - local_offset) {
            LOGE("OBB entry is not STORED/readable source='%s' name='%s' method=%u flags=0x%x",
                 archive->asset_name.c_str(), name.c_str(), method, flags);
            errno = ENOTSUP;
            return false;
        }

        uint8_t local_header[30]{};
        if (!ReadArchiveBytes(*archive, local_offset, local_header, sizeof(local_header)) ||
            ReadLe32(local_header) != 0x04034b50u) {
            LOGE("invalid local header source='%s' name='%s'", archive->asset_name.c_str(), name.c_str());
            errno = EINVAL;
            return false;
        }
        const uint16_t local_name_size = ReadLe16(local_header + 26);
        const uint16_t local_extra_size = ReadLe16(local_header + 28);
        const uint64_t data_offset = static_cast<uint64_t>(local_offset) + 30u +
                                     local_name_size + local_extra_size;
        if (data_offset > archive->length || compressed_size > archive->length - data_offset) {
            LOGE("entry payload outside OBB source='%s' name='%s'",
                 archive->asset_name.c_str(), name.c_str());
            errno = EINVAL;
            return false;
        }

        if (directory) {
            AddArchiveDirectoryParents(name, archive->directories);
        } else {
            archive->entries[name] = ArchiveEntry{name, data_offset, uncompressed_size, method, false};
            AddArchiveDirectoryParents(name, archive->directories);
        }
        cursor += record_size;
    }
    archive->directories.insert("");
    LOGI("OBB indexed source='%s' bytes=%llu entries=%zu directories=%zu",
         archive->asset_name.c_str(), static_cast<unsigned long long>(archive->length),
         archive->entries.size(), archive->directories.size());
    return true;
}

std::shared_ptr<Archive> LoadArchive(AAssetManager* manager, std::string_view asset_name) {
    if (!manager) return {};
    AAsset* asset = AAssetManager_open(manager, std::string(asset_name).c_str(), AASSET_MODE_RANDOM);
    if (!asset) return {};
    const off64_t length = AAsset_getLength64(asset);
    if (length <= 0) {
        AAsset_close(asset);
        errno = EINVAL;
        return {};
    }

    auto archive = std::make_shared<Archive>();
    archive->asset = asset;
    archive->asset_name.assign(asset_name.data(), asset_name.size());
    archive->length = static_cast<uint64_t>(length);
    if (!ParseArchive(archive)) return {};
    return archive;
}

std::shared_ptr<Archive> LoadFileArchive(const std::string& path, uint64_t expected_size,
                                         std::string_view expected_sha256) {
    if (!ValidAbsolutePath(path)) {
        errno = EINVAL;
        return {};
    }
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return {};
    struct stat value{};
    if (::fstat(fd, &value) != 0 || !S_ISREG(value.st_mode) || value.st_size <= 0 ||
        static_cast<uint64_t>(value.st_size) != expected_size) {
        const int saved = errno ? errno : EINVAL;
        ::close(fd);
        errno = saved;
        return {};
    }

    std::string actual_sha256;
    if (!HashFileSha256(fd, static_cast<uint64_t>(value.st_size), actual_sha256) ||
        actual_sha256 != expected_sha256) {
        LOGE("external OBB hash mismatch path='%s' expected='%.*s' actual='%s'",
             path.c_str(), static_cast<int>(expected_sha256.size()), expected_sha256.data(),
             actual_sha256.c_str());
        const int saved = errno ? errno : EINVAL;
        ::close(fd);
        errno = saved;
        return {};
    }

    auto archive = std::make_shared<Archive>();
    archive->fd = fd;
    archive->asset_name = path;
    archive->length = static_cast<uint64_t>(value.st_size);
    if (!ParseArchive(archive)) return {};
    return archive;
}

std::shared_ptr<Archive> LoadLooseAsset(AAssetManager* manager, std::string_view asset_name) {
    if (!manager) return {};
    AAsset* asset = AAssetManager_open(manager, std::string(asset_name).c_str(), AASSET_MODE_RANDOM);
    if (!asset) return {};
    const off64_t length = AAsset_getLength64(asset);
    if (length <= 0) {
        AAsset_close(asset);
        errno = EINVAL;
        return {};
    }

    auto asset_view = std::make_shared<Archive>();
    asset_view->asset = asset;
    asset_view->asset_name.assign(asset_name.data(), asset_name.size());
    asset_view->length = static_cast<uint64_t>(length);
    return asset_view;
}

bool CopyHostFile(const std::string& input_path, const std::string& output_path) {
    const int input = ::open(input_path.c_str(), O_RDONLY | O_CLOEXEC);
    if (input < 0) return false;
    const int output = ::open(output_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (output < 0) {
        const int saved = errno;
        ::close(input);
        errno = saved;
        return false;
    }

    std::array<uint8_t, kCopyChunk> buffer{};
    int error = 0;
    while (true) {
        const ssize_t count = ::read(input, buffer.data(), buffer.size());
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) {
            error = errno ? errno : EIO;
            break;
        }
        if (count == 0) break;
        if (!WriteAll(output, buffer.data(), static_cast<size_t>(count))) {
            error = errno ? errno : EIO;
            break;
        }
    }
    if (!error && ::fsync(output) != 0) error = errno ? errno : EIO;
    const int output_close = ::close(output) == 0 ? 0 : errno;
    const int input_close = ::close(input) == 0 ? 0 : errno;
    if (!error && output_close) error = output_close;
    if (!error && input_close) error = input_close;
    if (error) {
        ::unlink(output_path.c_str());
        errno = error;
        return false;
    }
    return true;
}

bool ReadWhole(const std::string& path, std::string& output) {
    int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;

    struct stat value{};
    if (::fstat(fd, &value) != 0 || value.st_size < 0 ||
        static_cast<uint64_t>(value.st_size) > kMaxManifest) {
        const int saved = errno ? errno : EIO;
        ::close(fd);
        errno = saved;
        return false;
    }

    output.clear();
    output.resize(static_cast<size_t>(value.st_size));
    size_t offset = 0;
    while (offset < output.size()) {
        const ssize_t count = ::read(fd, output.data() + offset, output.size() - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) {
            const int saved = count == 0 ? EIO : errno;
            ::close(fd);
            errno = saved;
            return false;
        }
        offset += static_cast<size_t>(count);
    }
    const int saved = errno;
    const bool ok = ::close(fd) == 0;
    if (!ok) errno = saved;
    return ok;
}

void SyncDirectoryBestEffort(const std::string& path) {
    int fd = ::open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) {
        LOGW("directory fsync open failed path='%s' errno=%d", path.c_str(), errno);
        return;
    }
    if (::fsync(fd) != 0) {
        LOGW("directory fsync failed path='%s' errno=%d", path.c_str(), errno);
    }
    ::close(fd);
}

class ExclusiveLock {
public:
    ExclusiveLock() = default;

    bool Acquire(const std::string& path) {
        m_fd = ::open(path.c_str(), O_CREAT | O_RDWR | O_CLOEXEC, 0600);
        return m_fd >= 0 && ::flock(m_fd, LOCK_EX) == 0;
    }

    ~ExclusiveLock() {
        if (m_fd >= 0) {
            ::flock(m_fd, LOCK_UN);
            ::close(m_fd);
        }
    }

    ExclusiveLock(const ExclusiveLock&) = delete;
    ExclusiveLock& operator=(const ExclusiveLock&) = delete;

private:
    int m_fd = -1;
};

bool CollectDirectory(AAssetManager* manager, const std::string& prefix, AAssetDir* directory,
                      std::vector<AssetFile>& files) {
    const char* raw_name = nullptr;
    while ((raw_name = AAssetDir_getNextFileName(directory)) != nullptr) {
        const std::string name(raw_name);
        if (!ValidComponent(name)) {
            LOGE("unsafe asset component under '%s'", prefix.c_str());
            return false;
        }
        if (files.size() >= kMaxAssets) {
            errno = EOVERFLOW;
            LOGE("assets/data contains too many files");
            return false;
        }

        const std::string child = Join(prefix, name);
        AAsset* asset = AAssetManager_open(manager, child.c_str(), AASSET_MODE_RANDOM);
        if (asset) {
            const off64_t length = AAsset_getLength64(asset);
            AAsset_close(asset);
            if (length < 0) {
                errno = EIO;
                return false;
            }
            files.push_back({child, static_cast<int64_t>(length)});
            continue;
        }

        AAssetDir* child_directory = AAssetManager_openDir(manager, child.c_str());
        if (!child_directory) {
            errno = EIO;
            LOGE("asset entry is neither file nor directory: '%s'", child.c_str());
            return false;
        }
        const bool ok = CollectDirectory(manager, child, child_directory, files);
        AAssetDir_close(child_directory);
        if (!ok) return false;
    }
    return true;
}

bool CollectDataAssets(AAssetManager* manager, std::vector<AssetFile>& files) {
    AAsset* manifest_asset = AAssetManager_open(manager, "data_manifest.csv", AASSET_MODE_BUFFER);
    if (manifest_asset) {
        const off64_t length = AAsset_getLength64(manifest_asset);
        if (length <= 0 || static_cast<uint64_t>(length) > kMaxManifest) {
            AAsset_close(manifest_asset);
            errno = EOVERFLOW;
            return false;
        }

        std::string manifest(static_cast<size_t>(length), '\0');
        size_t offset = 0;
        while (offset < manifest.size()) {
            const int count = AAsset_read(manifest_asset, manifest.data() + offset,
                                          static_cast<int>(manifest.size() - offset));
            if (count <= 0) {
                AAsset_close(manifest_asset);
                errno = EIO;
                return false;
            }
            offset += static_cast<size_t>(count);
        }
        AAsset_close(manifest_asset);

        bool first_line = true;
        size_t line_start = 0;
        while (line_start <= manifest.size()) {
            size_t line_end = manifest.find('\n', line_start);
            if (line_end == std::string::npos) line_end = manifest.size();
            std::string_view line(manifest.data() + line_start, line_end - line_start);
            if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
            if (first_line) {
                first_line = false;
                if (line != "\"source\",\"path\",\"size\",\"sha256\"") {
                    errno = EINVAL;
                    return false;
                }
            } else if (!line.empty()) {
                std::array<std::string, 4> fields;
                size_t cursor = 0;
                bool valid = true;
                for (size_t field = 0; field < fields.size(); ++field) {
                    if (cursor >= line.size() || line[cursor] != '"') {
                        valid = false;
                        break;
                    }
                    ++cursor;
                    while (cursor < line.size()) {
                        const char character = line[cursor++];
                        if (character != '"') {
                            fields[field].push_back(character);
                            continue;
                        }
                        if (cursor < line.size() && line[cursor] == '"') {
                            fields[field].push_back('"');
                            ++cursor;
                            continue;
                        }
                        break;
                    }
                    if (cursor > line.size() || (field + 1 < fields.size() &&
                                                  (cursor >= line.size() || line[cursor++] != ','))) {
                        valid = false;
                        break;
                    }
                }
                if (!valid || cursor != line.size() || fields[0].empty() || fields[1].empty()) {
                    errno = EINVAL;
                    return false;
                }

                const std::string asset_name = Join("data", fields[1]);
                if (!ValidRelative(fields[1]) || !ValidRelative(asset_name)) {
                    errno = EINVAL;
                    return false;
                }
                AAsset* asset = AAssetManager_open(manager, asset_name.c_str(), AASSET_MODE_RANDOM);
                if (!asset) {
                    errno = ENOENT;
                    LOGE("manifest entry missing from APK assets: '%s'", asset_name.c_str());
                    return false;
                }
                const off64_t actual_length = AAsset_getLength64(asset);
                AAsset_close(asset);
                if (actual_length < 0) {
                    errno = EIO;
                    return false;
                }
                const auto duplicate = std::find_if(files.begin(), files.end(),
                                                    [&asset_name](const AssetFile& file) {
                                                        return file.name == asset_name;
                                                    });
                if (duplicate == files.end()) {
                    files.push_back({asset_name, static_cast<int64_t>(actual_length)});
                }
            }
            if (line_end == manifest.size()) break;
            line_start = line_end + 1;
        }
        if (files.empty()) {
            errno = EINVAL;
            return false;
        }
        return true;
    }

    AAssetDir* directory = AAssetManager_openDir(manager, "data");
    if (!directory) {
        LOGI("assets/data not present; embedded data VFS disabled");
        return true;
    }
    const bool ok = CollectDirectory(manager, "data", directory, files);
    AAssetDir_close(directory);
    return ok;
}

bool BuildManifest(const std::vector<AssetFile>& files, std::string& manifest) {
    manifest.assign(kManifestHeader);
    for (const AssetFile& file : files) {
        manifest.append(file.name);
        manifest.push_back('\t');
        manifest.append(std::to_string(file.size));
        manifest.push_back('\n');
        if (manifest.size() > kMaxManifest) {
            errno = EOVERFLOW;
            return false;
        }
    }
    return true;
}

bool BuildLegacyFileAliases(const std::vector<AssetFile>& files,
                            std::unordered_map<std::string, std::string>& aliases) {
    constexpr std::string_view kDataPrefix = "data/data/";
    constexpr std::string_view kCarPrefix = "data/data/Car/";
    constexpr std::string_view kTrafficCarPrefix = "data/data/TrafficCar/";
    constexpr std::string_view kTrackPrefix = "data/data/Track/";
    std::unordered_map<std::string, std::string> candidates;
    std::unordered_set<std::string> ambiguous;

    const auto add_alias = [&candidates, &ambiguous](std::string_view leaf,
                                                      const std::string& source) {
        if (leaf.empty() || !ValidComponent(leaf)) return;
        const std::string guest_relative = Join("data", leaf);
        const auto existing = candidates.find(guest_relative);
        if (existing != candidates.end() && existing->second != source) {
            ambiguous.insert(guest_relative);
            return;
        }
        candidates.emplace(guest_relative, source);
    };

    for (const AssetFile& file : files) {
        if (HasPrefix(file.name, kDataPrefix)) {
            const std::string_view leaf = std::string_view(file.name).substr(kDataPrefix.size());
            // Top-level OBB files are addressed by the game from its data/
            // working directory, while the APK asset tree contains data/data/.
            // Only expose a manifest-backed one-component alias.
            if (leaf.find('/') == std::string_view::npos) {
                add_alias(leaf, file.name);
                continue;
            }
        }

        std::string_view nested;
        if (HasPrefix(file.name, kCarPrefix)) {
            nested = std::string_view(file.name).substr(kCarPrefix.size());
        } else if (HasPrefix(file.name, kTrafficCarPrefix)) {
            nested = std::string_view(file.name).substr(kTrafficCarPrefix.size());
        } else if (HasPrefix(file.name, kTrackPrefix)) {
            nested = std::string_view(file.name).substr(kTrackPrefix.size());
        } else {
            continue;
        }

        const size_t model_separator = nested.find('/');
        if (model_separator == std::string_view::npos || model_separator == 0 ||
            model_separator + 1 >= nested.size()) {
            continue;
        }
        const std::string_view leaf = nested.substr(model_separator + 1);
        // These directories are intentionally one level deep in the source
        // OBB. Reject anything else rather than turning a nested path into a
        // wider alias surface.
        if (leaf.find('/') != std::string_view::npos || !ValidComponent(leaf)) continue;
        add_alias(leaf, file.name);
    }

    aliases.clear();
    for (auto& entry : candidates) {
        if (ambiguous.find(entry.first) == ambiguous.end()) {
            aliases.emplace(std::move(entry));
        }
    }
    LOGI("embedded legacy file aliases prepared unique=%zu ambiguous=%zu",
         aliases.size(), ambiguous.size());
    return true;
}

uint64_t Fnv1a(std::string_view value) {
    uint64_t hash = 1469598103934665603ull;
    for (const unsigned char byte : value) {
        hash ^= byte;
        hash *= 1099511628211ull;
    }
    return hash;
}

std::string Hex(uint64_t value) {
    constexpr char digits[] = "0123456789abcdef";
    std::string output(16, '0');
    for (size_t i = output.size(); i-- > 0;) {
        output[i] = digits[value & 0xf];
        value >>= 4;
    }
    return output;
}

bool ParseMarker(const std::string& marker, const std::string& manifest, std::string& root_name) {
    if (!HasPrefix(marker, kMarkerPrefix)) return false;
    const size_t root_end = marker.find('\n', kMarkerPrefix.size());
    if (root_end == std::string::npos) return false;
    root_name.assign(marker, kMarkerPrefix.size(), root_end - kMarkerPrefix.size());
    if (!ValidGenerationName(root_name)) return false;
    return marker.compare(root_end + 1, std::string::npos, manifest) == 0;
}

bool ValidateExtracted(const std::string& root, const std::vector<AssetFile>& files) {
    struct stat root_stat{};
    if (::lstat(root.c_str(), &root_stat) != 0 || !S_ISDIR(root_stat.st_mode)) return false;
    for (const AssetFile& file : files) {
        const std::string path = Join(root, file.name);
        struct stat value{};
        if (::lstat(path.c_str(), &value) != 0 || !S_ISREG(value.st_mode) ||
            static_cast<int64_t>(value.st_size) != file.size) {
            return false;
        }
    }
    return true;
}

bool CopyAsset(AAssetManager* manager, const AssetFile& file, const std::string& output_path) {
    std::vector<uint8_t> buffer(kCopyChunk);
    AAsset* asset = AAssetManager_open(manager, file.name.c_str(), AASSET_MODE_STREAMING);
    if (!asset) {
        errno = ENOENT;
        return false;
    }
    int fd = ::open(output_path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) {
        const int saved = errno;
        AAsset_close(asset);
        errno = saved;
        return false;
    }

    int error = 0;
    int64_t total = 0;
    while (true) {
        const int count = AAsset_read(asset, buffer.data(), static_cast<int>(buffer.size()));
        if (count < 0) {
            error = EIO;
            break;
        }
        if (count == 0) break;
        if (count > file.size - total) {
            error = EIO;
            break;
        }
        if (!WriteAll(fd, buffer.data(), static_cast<size_t>(count))) {
            error = errno ? errno : EIO;
            break;
        }
        total += count;
    }
    if (!error && total != file.size) error = EIO;
    if (!error && ::fsync(fd) != 0) error = errno;

    const int close_error = ::close(fd) == 0 ? 0 : errno;
    AAsset_close(asset);
    if (!error && close_error) error = close_error;
    if (error) {
        ::unlink(output_path.c_str());
        errno = error;
        return false;
    }
    return true;
}

bool EnsureParents(const std::string& root, std::string_view relative) {
    size_t slash = relative.find('/');
    while (slash != std::string_view::npos) {
        const std::string directory = Join(root, relative.substr(0, slash));
        if (!EnsureDirectory(directory)) return false;
        slash = relative.find('/', slash + 1);
    }
    return true;
}

bool CreateGeneration(const std::string& base, const std::string& token,
                      std::string& staging, std::string& final_root) {
    const std::string pid = std::to_string(static_cast<long long>(::getpid()));
    for (unsigned attempt = 0; attempt != 100000; ++attempt) {
        const std::string suffix = token + "-" + pid + "-" + std::to_string(attempt);
        staging = Join(base, ".staging-" + suffix);
        final_root = Join(base, "gen-" + suffix);
        if (::mkdir(staging.c_str(), 0700) == 0) return true;
        if (errno != EEXIST) return false;
    }
    errno = EEXIST;
    return false;
}

bool PublishMarker(const std::string& base, const std::string& marker_path, const std::string& body) {
    const std::string pid = std::to_string(static_cast<long long>(::getpid()));
    for (unsigned attempt = 0; attempt != 100000; ++attempt) {
        const std::string temporary = marker_path + ".tmp-" + pid + "-" + std::to_string(attempt);
        const int fd = ::open(temporary.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (fd < 0) {
            if (errno == EEXIST) continue;
            return false;
        }
        int error = 0;
        if (!WriteAll(fd, body.data(), body.size())) {
            error = errno ? errno : EIO;
        } else if (::fsync(fd) != 0) {
            error = errno ? errno : EIO;
        }
        if (::close(fd) != 0 && !error) error = errno ? errno : EIO;
        if (error) {
            ::unlink(temporary.c_str());
            errno = error;
            return false;
        }
        if (::rename(temporary.c_str(), marker_path.c_str()) == 0) {
            SyncDirectoryBestEffort(base);
            return true;
        }
        const int rename_error = errno;
        ::unlink(temporary.c_str());
        errno = rename_error;
        return false;
    }
    errno = EEXIST;
    return false;
}

bool PrepareSidecars(const std::string& base, const std::string& extracted_root,
                     std::string& sidecar_root);
bool PrepareDirectSidecars(AAssetManager* manager, const std::string& base,
                           std::string& sidecar_root);
bool BuildDirectAliases();

bool PrepareImpl(AAssetManager* manager, const std::string& external_files_dir,
                 std::string& extracted_root, std::string& sidecar_root,
                 std::unordered_map<std::string, std::string>& legacy_file_aliases) {
    std::vector<AssetFile> files;
    if (!CollectDataAssets(manager, files)) return false;
    if (files.empty()) return true;

    std::sort(files.begin(), files.end(), [](const AssetFile& left, const AssetFile& right) {
        return left.name < right.name;
    });
    for (size_t i = 1; i < files.size(); ++i) {
        if (files[i - 1].name == files[i].name) {
            errno = EEXIST;
            return false;
        }
    }
    if (!ValidAbsolutePath(external_files_dir)) {
        errno = EINVAL;
        LOGE("invalid getExternalFilesDir path");
        return false;
    }

    std::string manifest;
    if (!BuildManifest(files, manifest)) return false;
    const std::string base = Join(external_files_dir, ".asphalt7_asset_vfs");
    const std::string marker_path = Join(base, ".complete");
    if (!EnsureDirectory(external_files_dir) || !EnsureDirectory(base)) return false;

    ExclusiveLock lock;
    if (!lock.Acquire(Join(base, ".lock"))) {
        LOGE("cannot lock embedded-data cache errno=%d", errno);
        return false;
    }

    std::string marker;
    std::string root_name;
    if (ReadWhole(marker_path, marker) && ParseMarker(marker, manifest, root_name)) {
        const std::string root = Join(base, root_name);
        if (ValidateExtracted(root, files)) {
            if (!PrepareSidecars(base, root, sidecar_root)) return false;
            if (!BuildLegacyFileAliases(files, legacy_file_aliases)) return false;
            extracted_root = root;
            LOGI("embedded data cache hit root='%s' sidecars='%s' files=%zu",
                 root.c_str(), sidecar_root.c_str(), files.size());
            return true;
        }
        LOGW("embedded data marker points to incomplete root; rebuilding");
    }

    const std::string token = Hex(Fnv1a(manifest));
    std::string staging;
    std::string final_root;
    if (!CreateGeneration(base, token, staging, final_root)) {
        LOGE("cannot create embedded-data staging directory errno=%d", errno);
        return false;
    }
    for (const AssetFile& file : files) {
        if (!EnsureParents(staging, file.name)) {
            LOGE("cannot create parents for '%s' errno=%d", file.name.c_str(), errno);
            return false;
        }
        if (!CopyAsset(manager, file, Join(staging, file.name))) {
            LOGE("cannot extract '%s' errno=%d", file.name.c_str(), errno);
            return false;
        }
    }
    SyncDirectoryBestEffort(staging);
    if (::rename(staging.c_str(), final_root.c_str()) != 0) {
        LOGE("cannot publish embedded-data generation errno=%d", errno);
        return false;
    }
    SyncDirectoryBestEffort(base);

    const std::string marker_body = std::string("ASSET_VFS_VERSION=2\nROOT=") +
                                    final_root.substr(base.size() + 1) + "\n" + manifest;
    if (!PublishMarker(base, marker_path, marker_body)) {
        LOGE("cannot publish embedded-data marker errno=%d", errno);
        return false;
    }
    if (!PrepareSidecars(base, final_root, sidecar_root)) return false;
    if (!BuildLegacyFileAliases(files, legacy_file_aliases)) return false;
    extracted_root = final_root;
    LOGI("embedded data extracted root='%s' sidecars='%s' files=%zu",
         final_root.c_str(), sidecar_root.c_str(), files.size());
    return true;
}

bool PrepareDirectImpl(AAssetManager* manager, const std::string& external_files_dir,
                       const std::string& external_obb_dir, std::string& sidecar_root) {
    auto main_archive = LoadArchive(manager, kEmbeddedMainObb);
    auto patch_archive = LoadArchive(manager, kEmbeddedPatchObb);
    bool external_source = false;
    if (!main_archive || !patch_archive) {
        // Never combine a main and patch from different releases. If the
        // embedded pair is incomplete or corrupt, select a complete external
        // pair instead; the embedded pair remains authoritative when complete.
        if (main_archive || patch_archive) {
            LOGW("embedded OBB pair is incomplete; refusing mixed source and trying external pair");
        }
        if (!ValidAbsolutePath(external_obb_dir)) {
            LOGE("embedded OBB pair unavailable and getObbDir path is invalid");
            errno = ENOENT;
            return false;
        }
        auto external_main = LoadFileArchive(Join(external_obb_dir, kExternalMainObb),
                                             kExpectedMainObbSize, kExpectedMainObbSha256);
        auto external_patch = LoadFileArchive(Join(external_obb_dir, kExternalPatchObb),
                                              kExpectedPatchObbSize, kExpectedPatchObbSha256);
        if (!external_main || !external_patch) {
            LOGE("whole-container reader requires a complete embedded or external OBB pair "
                 "dir='%s' main=%s patch=%s", external_obb_dir.c_str(),
                 external_main ? "ok" : "missing-or-corrupt",
                 external_patch ? "ok" : "missing-or-corrupt");
            errno = ENOENT;
            return false;
        }
        main_archive = std::move(external_main);
        patch_archive = std::move(external_patch);
        external_source = true;
    }
    auto cars_compat_asset = LoadLooseAsset(manager, kEmbeddedCarsCompatZip);
    if (!cars_compat_asset) {
        LOGE("whole-container release layout requires compatibility asset='%s'",
             std::string(kEmbeddedCarsCompatZip).c_str());
        errno = ENOENT;
        return false;
    }

    g_archives.clear();
    g_archives.push_back(std::move(main_archive));
    g_archives.push_back(std::move(patch_archive));
    const ArchiveEntry cars_compat_entry{
        std::string(kEmbeddedCarsCompatZip), 0, cars_compat_asset->length, 0, false};
    g_archives.push_back(std::move(cars_compat_asset));
    g_direct_entries.clear();
    g_direct_directories.clear();
    for (const std::shared_ptr<Archive>& archive : g_archives) {
        for (const auto& [name, entry] : archive->entries) {
            // The patch OBB is applied after main by the original installer;
            // later assignment intentionally gives it overlay precedence.
            g_direct_entries[name] = IndexedEntry{archive, entry};
        }
        g_direct_directories.insert(archive->directories.begin(), archive->directories.end());
    }
    g_direct_entries[std::string(kEmbeddedCarsCompatZip)] =
        IndexedEntry{g_archives.back(), cars_compat_entry};
    if (!BuildDirectAliases()) return false;
    if (!ValidAbsolutePath(external_files_dir)) {
        errno = EINVAL;
        LOGE("invalid getExternalFilesDir path for direct OBB reader");
        return false;
    }

    const std::string base = Join(external_files_dir, ".asphalt7_asset_vfs");
    if (!EnsureDirectory(external_files_dir) || !EnsureDirectory(base)) return false;
    if (!PrepareDirectSidecars(manager, base, sidecar_root)) return false;
    LOGI("whole-container direct OBB reader enabled source=%s main+patch entries=%zu "
         "directories=%zu compat_cars_zip_bytes=%llu sidecars='%s'",
         external_source ? "external" : "embedded", g_direct_entries.size(),
         g_direct_directories.size(),
         static_cast<unsigned long long>(cars_compat_entry.size), sidecar_root.c_str());
    return true;
}

bool RelativeForGuestSuffix(std::string_view suffix, std::string& relative) {
    if (suffix.empty() || suffix == "/") {
        relative.clear();
        return true;
    }
    if (suffix.front() != '/') return false;
    std::string candidate(suffix.substr(1));
    while (!candidate.empty() && candidate.back() == '/') candidate.pop_back();
    if (candidate.empty()) {
        relative.clear();
        return true;
    }

    const auto data_relative = [&relative](std::string_view value) {
        if (value == "data" || HasPrefix(value, "data/")) {
            relative.assign(value.data(), value.size());
            return true;
        }
        if (value == "assets/data" || HasPrefix(value, "assets/data/")) {
            const std::string_view stripped = value.substr(7);
            relative.assign(stripped.data(), stripped.size());
            return true;
        }
        return false;
    };

    if (data_relative(candidate)) return ValidRelative(relative);

    const std::string_view candidate_view(candidate);
    const size_t slash = candidate_view.find('/');
    const std::string_view first = candidate_view.substr(0, slash);
    if (slash != std::string::npos && HasPrefix(first, "main.") && first.size() > 4 &&
        first.substr(first.size() - 4) == ".obb") {
        if (!data_relative(candidate_view.substr(slash + 1))) return false;
        return ValidRelative(relative);
    }
    if (slash != std::string::npos && HasPrefix(first, "patch.") && first.size() > 5 &&
        first.substr(first.size() - 4) == ".obb") {
        if (!data_relative(candidate_view.substr(slash + 1))) return false;
        return ValidRelative(relative);
    }
    if (!ValidRelative(candidate_view)) return false;
    relative = "data/" + candidate;
    return ValidRelative(relative);
}

bool RelativeForEmbeddedPath(std::string_view value, std::string& relative) {
    if (value == "data" || HasPrefix(value, "data/")) {
        relative.assign(value.data(), value.size());
    } else if (value == "assets/data" || HasPrefix(value, "assets/data/")) {
        const std::string_view stripped = value.substr(7);
        relative.assign(stripped.data(), stripped.size());
    } else if (ValidRelative(value)) {
        // FileStreamImpl may receive a path already resolved against the
        // legacy working directory as a relative string. Only publish it if
        // the corresponding immutable embedded file or directory exists.
        relative = "data/";
        relative.append(value.data(), value.size());
    } else {
        return false;
    }
    return ValidRelative(relative);
}

bool BuildDirectAliases() {
    g_direct_aliases.clear();
    const auto add_fixed = [](std::string_view guest, std::string_view archive) {
        if (g_direct_entries.find(std::string(archive)) != g_direct_entries.end()) {
            g_direct_aliases.emplace(std::string(guest), std::string(archive));
        }
    };
    add_fixed("data/aswfTextures.zip", "data/Textures/aswfTextures.zip");
    add_fixed("data/carTextures.zip", "data/Textures/carTextures.zip");
    add_fixed("data/loadingTextures.zip", "data/Textures/loadingTextures.zip");
    add_fixed("data/objectsTextures.zip", "data/Textures/objectsTextures.zip");
    add_fixed("data/particleTextures.zip", "data/Textures/particleTextures.zip");
    add_fixed("data/sceneTextures.zip", "data/Textures/sceneTextures.zip");
    add_fixed("data/swfTextures.zip", "data/Textures/swfTextures.zip");
    add_fixed("data/trackTextures.zip", "data/Textures/trackTextures.zip");
    add_fixed("data/trafficTextures.zip", "data/Textures/trafficTextures.zip");
    add_fixed("data/gameswf_effects.bdae", "data/SWF/gameswf_effects.bdae");
    add_fixed("DefaultEffects.bdae", "data/Glitch/DefaultEffects.bdae");
    add_fixed("data/DefaultEffects.bdae", "data/Glitch/DefaultEffects.bdae");
    add_fixed("data/loadingSplash.swf", "data/SWF/loadingSplash.swf");
    // The ultra-menu profile requests the HD logical name, but the shipped OBB
    // contains only this vector movie. Resolve both legacy roots to the bundled
    // source instead of letting the startup movie lookup fail.
    add_fixed("data/loadingSplash_hd.swf", "data/SWF/loadingSplash.swf");
    add_fixed("data/SWF/loadingSplash_hd.swf", "data/SWF/loadingSplash.swf");
    // Ultra-resolution mode also requests HD variants of other SWF movies
    // (for example LanguageSelection_hd.swf). Reuse the real HD file if the
    // package has one; otherwise resolve the missing movie to its base SWF.
    // This keeps the high-resolution texture profile enabled without letting
    // an absent optional movie leave the game with a null timeline object.
    for (const auto& [name, indexed] : g_direct_entries) {
        (void)indexed;
        constexpr std::string_view kSwfPrefix = "data/SWF/";
        constexpr std::string_view kSwfSuffix = ".swf";
        if (!HasPrefix(name, kSwfPrefix) || name.size() <= kSwfPrefix.size() + kSwfSuffix.size() ||
            std::string_view(name).substr(name.size() - kSwfSuffix.size()) != kSwfSuffix) continue;
        const std::string_view leaf = std::string_view(name).substr(kSwfPrefix.size());
        const std::string_view stem = leaf.substr(0, leaf.size() - kSwfSuffix.size());
        if (stem.ends_with("_hd")) continue;

        const std::string guest_hd = Join("data", std::string(stem) + "_hd.swf");
        const std::string nested_hd = Join("data/SWF", std::string(stem) + "_hd.swf");
        std::string_view preferred = name;
        if (g_direct_entries.find(nested_hd) != g_direct_entries.end()) preferred = nested_hd;
        else if (g_direct_entries.find(guest_hd) != g_direct_entries.end()) preferred = guest_hd;
        add_fixed(guest_hd, preferred);
        add_fixed(nested_hd, preferred);
    }
    add_fixed("data/DeviceConfig.xml", "data/DeviceConfig/DeviceConfig.xml");
    // SoundManager::Init in the retained ARM32 build asks the legacy
    // filesystem for the pack by basename (VOX_SDD.xml).  The release OBB
    // keeps the immutable pack under data/Audio; resolve that lookup in the
    // index so audio stays container-backed and no cache extraction is needed.
    add_fixed("data/VOX_SDD.xml", "data/Audio/VOX_SDD.xml");

    // VoxSoundPackXML stores the bank filename (for example m_title.mpc)
    // without its Audio directory. The legacy resolver consequently asks
    // for data/<leaf>; keep that lookup inside the immutable OBB index.
    for (const auto& [name, indexed] : g_direct_entries) {
        (void)indexed;
        constexpr std::string_view kAudioPrefix = "data/Audio/";
        if (!HasPrefix(name, kAudioPrefix)) continue;
        const std::string_view leaf = std::string_view(name).substr(kAudioPrefix.size());
        if (leaf.empty() || leaf.find('/') != std::string_view::npos ||
            !ValidComponent(leaf)) continue;
        add_fixed(Join("data", leaf), name);
    }

    const auto add_legacy = [](std::string_view prefix) {
        for (const auto& [name, indexed] : g_direct_entries) {
            (void)indexed;
            if (!HasPrefix(name, prefix)) continue;
            const std::string_view nested = std::string_view(name).substr(prefix.size());
            const size_t model_separator = nested.find('/');
            if (model_separator == std::string_view::npos || model_separator == 0 ||
                model_separator + 1 >= nested.size()) continue;
            const std::string_view leaf = nested.substr(model_separator + 1);
            if (leaf.find('/') != std::string_view::npos || !ValidComponent(leaf)) continue;
            const std::string guest = Join("data", leaf);
            auto existing = g_direct_aliases.find(guest);
            if (existing != g_direct_aliases.end() && existing->second != name) {
                g_direct_aliases.erase(existing);
                continue;
            }
            g_direct_aliases.emplace(guest, name);
        }
    };
    add_legacy("data/Car/");
    add_legacy("data/TrafficCar/");
    add_legacy("data/Track/");
    // MenuScene requests GOC_Floor.bdae by basename when the lottery spin
    // creates its scene. The complete original container stores that model
    // under data/Scene/Lottery/. Resolve scene basenames from the index just
    // like car and track models; no file is extracted or duplicated.
    add_legacy("data/Scene/");
    LOGI("whole-container legacy aliases prepared aliases=%zu", g_direct_aliases.size());
    return true;
}

bool DirectRelativeLocked(const char* guest_path, std::string& relative) {
    if (!guest_path || g_archives.empty()) return false;
    const size_t length = strnlen(guest_path, kMaxPath + 1);
    if (length > kMaxPath) return false;
    const std::string_view raw_value(guest_path, length);
    std::string normalized;
    std::string_view value = raw_value;
    if (HasPrefix(raw_value, "./") &&
        (HasPrefix(raw_value, "./sdcard/") || HasPrefix(raw_value, "./mnt/") ||
         HasPrefix(raw_value, "./storage/"))) {
        normalized.assign(raw_value.substr(1));
        value = normalized;
    }
    for (const std::string_view root : kGuestAppDataRoots) {
        if (!HasPrefix(value, root)) continue;
        if (value.size() != root.size() && value[root.size()] != '/') return false;
        return RelativeForGuestSuffix(value.substr(root.size()), relative);
    }
    for (const std::string_view root : kGuestRoots) {
        if (!HasPrefix(value, root)) continue;
        if (value.size() != root.size() && value[root.size()] != '/') return false;
        return RelativeForGuestSuffix(value.substr(root.size()), relative);
    }
    std::string relative_input;
    if (HasPrefix(raw_value, "./")) relative_input.assign(raw_value.substr(2));
    else relative_input.assign(raw_value.data(), raw_value.size());
    if (relative_input.empty() || relative_input.front() == '/') return false;
    return RelativeForEmbeddedPath(relative_input, relative);
}

bool FindDirectEntryLocked(std::string_view relative, IndexedEntry& output) {
    const auto find = [&output](std::string_view candidate) {
        const auto it = g_direct_entries.find(std::string(candidate));
        if (it == g_direct_entries.end()) return false;
        output = it->second;
        return true;
    };
    // TrackScene asks for geometry under Data/<leaf> and <track>/<leaf> at
    // the OBB root. The container stores it under data/Track/<track>/<leaf>.
    // Resolve only names backed by the indexed container; the basename alias
    // exists only when it is unique across tracks.
    if (find(relative)) return true;
    constexpr std::string_view kDataDirectory = "data/Data/";
    if (HasPrefix(relative, kDataDirectory)) {
        const std::string_view leaf = relative.substr(kDataDirectory.size());
        if (!leaf.empty() && leaf.find('/') == std::string_view::npos) {
            const auto track_alias = g_direct_aliases.find(Join("data", leaf));
            if (track_alias != g_direct_aliases.end() &&
                HasPrefix(track_alias->second, "data/Track/") &&
                find(track_alias->second)) return true;
        }
    }
    constexpr std::string_view kDataRoot = "data/";
    if (HasPrefix(relative, kDataRoot)) {
        const std::string_view nested = relative.substr(kDataRoot.size());
        const size_t separator = nested.find('/');
        if (separator != std::string_view::npos && separator != 0 &&
            separator + 1 < nested.size() && nested.find('/', separator + 1) == std::string_view::npos &&
            nested.substr(0, separator) != "Data") {
            if (find(Join("data/Track", nested))) return true;
        }
    }
    // Preserve the previous missing-HD fallback for Hawaii.
    if ((relative == "data/Data/IPAD2a_Hawaii.bdae" ||
         relative == "data/Hawaii/IPAD2a_Hawaii.bdae" ||
         relative == "data/Track/Hawaii/IPAD2a_Hawaii.bdae") &&
        (find("data/Track/Hawaii/IPAD2a_Hawaii.bdae") ||
         find("data/Track/Hawaii/Hawaii.bdae"))) return true;
    const auto alias = g_direct_aliases.find(std::string(relative));
    if (alias != g_direct_aliases.end() && find(alias->second)) return true;
    if (HasPrefix(relative, "data/data/") && find(relative.substr(5))) return true;
    if (HasPrefix(relative, "data/") && find(relative.substr(5))) return true;
    // Patch cars keep loose textures outside carTextures.zip. The retained
    // search paths request their basenames and name the high variant _hd.
    // Resolve only existing, immutable entries; stock fallback handles misses.
    if (HasPrefix(relative, "data/")) {
        std::string leaf(relative.substr(relative.find_last_of('/') + 1));
        for (char& c : leaf) if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
        if (leaf.ends_with(".tga")) {
            if (find(Join("data/Textures/Cars", leaf))) return true;
            if (leaf.ends_with("_hd.tga")) {
                leaf.replace(leaf.size() - 7, 7, "_high.tga");
                if (find(Join("data/Textures/Cars", leaf))) return true;
            } else if (leaf.ends_with("_hd_high.tga") || leaf.ends_with("_hd_low.tga")) {
                // RaceCar appends another quality suffix to the logical HD name.
                leaf.erase(leaf.size() - (leaf.ends_with("_hd_high.tga") ? 12 : 11), 3);
                if (find(Join("data/Textures/Cars", leaf))) return true;
            }
        }
    }
    // MyHostInterface::getFont receives a legacy OBB-root basename such as
    // "orbitron-zero-bold.ttf". The original filesystem resolved that name
    // relative to its Fonts directory, while the embedded whole-container VFS
    // first normalizes an OBB-root suffix to data/<basename>. Preserve that
    // lookup contract without extracting or duplicating the font asset.
    if (HasPrefix(relative, "data/") && relative.find('/', 5) == std::string_view::npos) {
        const std::string_view leaf = relative.substr(5);
        if (find(Join("data/Fonts", leaf))) return true;
        if (find(Join("data/data/Fonts", leaf))) return true;
    }
    return false;
}

bool DirectPathStatLocked(std::string_view relative, struct stat* output) {
    if (!output) {
        errno = EFAULT;
        return false;
    }
    IndexedEntry entry;
    if (FindDirectEntryLocked(relative, entry)) {
        memset(output, 0, sizeof(*output));
        output->st_mode = S_IFREG | 0400;
        output->st_size = static_cast<off_t>(entry.entry.size);
        return true;
    }
    std::string directory(relative);
    while (!directory.empty() && directory.back() == '/') directory.pop_back();
    if (g_direct_directories.find(directory) != g_direct_directories.end()) {
        memset(output, 0, sizeof(*output));
        output->st_mode = S_IFDIR | 0500;
        return true;
    }
    errno = ENOENT;
    return false;
}

bool DirectListLocked(std::string_view relative, std::vector<std::string>& names,
                      std::vector<bool>& directories) {
    std::string parent(relative);
    while (!parent.empty() && parent.back() == '/') parent.pop_back();
    if (g_direct_directories.find(parent) == g_direct_directories.end()) {
        errno = ENOTDIR;
        return false;
    }
    std::unordered_map<std::string, bool> children;
    const std::string prefix = parent.empty() ? std::string() : parent + "/";
    for (const std::string& directory : g_direct_directories) {
        if (!HasPrefix(directory, prefix) || directory.size() == prefix.size()) continue;
        const std::string_view suffix(directory.data() + prefix.size(), directory.size() - prefix.size());
        const size_t slash = suffix.find('/');
        const std::string child(suffix.substr(0, slash));
        if (!child.empty()) children[child] = true;
    }
    for (const auto& [name, indexed] : g_direct_entries) {
        if (!HasPrefix(name, prefix) || name.size() == prefix.size()) continue;
        const std::string_view suffix(name.data() + prefix.size(), name.size() - prefix.size());
        const size_t slash = suffix.find('/');
        const std::string child(suffix.substr(0, slash));
        if (!child.empty()) children.emplace(child, slash != std::string_view::npos);
    }
    names.clear();
    directories.clear();
    std::vector<std::pair<std::string, bool>> sorted(children.begin(), children.end());
    std::sort(sorted.begin(), sorted.end(), [](const auto& left, const auto& right) {
        return left.first < right.first;
    });
    for (const auto& [name, directory] : sorted) {
        names.push_back(name);
        directories.push_back(directory);
    }
    return true;
}

bool EmbeddedArchiveAlias(std::string_view relative, std::string& alias) {
    if (relative == "data/aswfTextures.zip" ||
        relative == "data/loadingTextures.zip" ||
        relative == "data/swfTextures.zip" ||
        relative == "data/trackTextures.zip" ||
        relative == "data/carTextures.zip" ||
        relative == "data/trafficTextures.zip" ||
        relative == "data/objectsTextures.zip" ||
        relative == "data/sceneTextures.zip" ||
        relative == "data/particleTextures.zip") {
        alias = "data/data/Textures/";
        alias.append(relative.substr(5));
        return true;
    }
    if (relative == "data/gameswf_effects.bdae") {
        alias = "data/data/SWF/gameswf_effects.bdae";
        return true;
    }
    if (relative == "DefaultEffects.bdae" ||
        relative == "data/DefaultEffects.bdae") {
        alias = "data/data/Glitch/DefaultEffects.bdae";
        return true;
    }
    if (relative == "data/loadingSplash.swf") {
        alias = "data/data/SWF/loadingSplash.swf";
        return true;
    }
    return false;
}

void ApplyEmbeddedArchiveAlias(std::string_view relative, std::string& host_path) {
    std::string alias;
    if (!EmbeddedArchiveAlias(relative, alias)) return;
    const std::string candidate = Join(g_extracted_root, alias);
    struct stat value_stat{};
    if (::lstat(candidate.c_str(), &value_stat) == 0 &&
        (S_ISREG(value_stat.st_mode) || S_ISDIR(value_stat.st_mode))) {
        host_path = candidate;
        LOGI("embedded archive alias guest-relative='%.*s' host='%s'",
             static_cast<int>(relative.size()), relative.data(), host_path.c_str());
    }
}

void ApplyEmbeddedFileAlias(std::string_view relative, std::string& host_path) {
    const auto exact = g_legacy_file_aliases.find(std::string(relative));
    if (exact == g_legacy_file_aliases.end()) return;
    const std::string candidate = Join(g_extracted_root, exact->second);
    struct stat value_stat{};
    if (::lstat(candidate.c_str(), &value_stat) == 0 && S_ISREG(value_stat.st_mode)) {
        host_path = candidate;
        LOGI("embedded legacy file alias guest-relative='%.*s' host='%s'",
             static_cast<int>(relative.size()), relative.data(), host_path.c_str());
    }
}

void ApplyEmbeddedDataRootAlias(std::string_view relative, std::string& host_path) {
    if (!HasPrefix(relative, "data/") || HasPrefix(relative, "data/data/")) return;
    std::string asset_relative = "data/";
    asset_relative.append(relative.data(), relative.size());
    const std::string candidate = Join(g_extracted_root, asset_relative);
    struct stat value_stat{};
    if (::lstat(candidate.c_str(), &value_stat) == 0 &&
        (S_ISREG(value_stat.st_mode) || S_ISDIR(value_stat.st_mode))) {
        host_path = candidate;
        LOGI("embedded data-root alias guest-relative='%.*s' host='%s'",
             static_cast<int>(relative.size()), relative.data(), host_path.c_str());
    }
}

bool TranslateLocked(const char* guest_path, std::string& host_path) {
    if (!g_enabled || !guest_path) return false;
    const size_t length = strnlen(guest_path, kMaxPath + 1);
    if (length > kMaxPath) return false;
    const std::string_view raw_value(guest_path, length);
    // The legacy filesystem sometimes emits the absolute shared-storage
    // root with a leading "./" after changing its working directory. Treat
    // only that exact prefix as equivalent; traversal components remain
    // rejected by the existing path validators.
    std::string normalized;
    std::string_view value = raw_value;
    if (HasPrefix(raw_value, "./") &&
        (HasPrefix(raw_value, "./sdcard/") || HasPrefix(raw_value, "./mnt/") ||
         HasPrefix(raw_value, "./storage/"))) {
        normalized.assign(raw_value.substr(1));
        value = normalized;
    }
    for (const std::string_view root : kGuestAppDataRoots) {
        if (!HasPrefix(value, root)) continue;
        if (value.size() != root.size() && value[root.size()] != '/') return false;
        std::string relative;
        if (!RelativeForGuestSuffix(value.substr(root.size()), relative) || !ValidRelative(relative)) return false;
        host_path = g_extracted_root;
        if (!relative.empty()) host_path = Join(host_path, relative);
        ApplyEmbeddedArchiveAlias(relative, host_path);
        ApplyEmbeddedFileAlias(relative, host_path);
        ApplyEmbeddedDataRootAlias(relative, host_path);
        return host_path.size() <= kMaxPath;
    }
    for (const std::string_view root : kGuestRoots) {
        if (!HasPrefix(value, root)) continue;
        if (value.size() != root.size() && value[root.size()] != '/') return false;
        std::string relative;
        if (!RelativeForGuestSuffix(value.substr(root.size()), relative) || !ValidRelative(relative)) return false;
        host_path = g_extracted_root;
        if (!relative.empty()) host_path = Join(host_path, relative);
        ApplyEmbeddedArchiveAlias(relative, host_path);
        ApplyEmbeddedFileAlias(relative, host_path);
        ApplyEmbeddedDataRootAlias(relative, host_path);
        return host_path.size() <= kMaxPath;
    }

    std::string relative_input;
    if (HasPrefix(raw_value, "./")) {
        relative_input.assign(raw_value.substr(2));
    } else {
        relative_input.assign(raw_value.data(), raw_value.size());
    }
    if (!relative_input.empty() && relative_input.front() != '/') {
        std::string relative;
        if (RelativeForEmbeddedPath(relative_input, relative)) {
            const std::string candidate = Join(g_extracted_root, relative);
            struct stat value_stat{};
            if (::lstat(candidate.c_str(), &value_stat) == 0 &&
                (S_ISREG(value_stat.st_mode) || S_ISDIR(value_stat.st_mode))) {
                host_path = candidate;
                return host_path.size() <= kMaxPath;
            }
            ApplyEmbeddedArchiveAlias(relative, host_path);
            ApplyEmbeddedFileAlias(relative, host_path);
            ApplyEmbeddedDataRootAlias(relative, host_path);
            if (host_path != g_extracted_root && host_path.size() <= kMaxPath) return true;
        }
    }
    return false;
}

bool IsMutableMetadataPath(std::string_view value) {
    const size_t slash = value.rfind('/');
    const std::string_view leaf = value.substr(slash == std::string_view::npos ? 0 : slash + 1);
    return leaf == "DeviceProfile.xml" || leaf == "B.A" || leaf == "InsTime";
}

bool MutablePathLocked(const char* guest_path, std::string& host_path) {
    if (!guest_path || g_sidecar_root.empty()) return false;
    const size_t length = strnlen(guest_path, kMaxPath + 1);
    if (length > kMaxPath) return false;
    const std::string_view value(guest_path, length);
    if (!IsMutableMetadataPath(value)) return false;

    // Validate that this is one of the guest OBB roots before accepting the
    // leaf-only sidecar mapping. The original relative path is intentionally
    // ignored after validation because these three files are root metadata.
    std::string embedded_path;
    if (g_direct_enabled) {
        std::string relative;
        if (!DirectRelativeLocked(guest_path, relative)) return false;
    } else if (!TranslateLocked(guest_path, embedded_path)) {
        return false;
    }
    const size_t slash = value.rfind('/');
    const std::string_view leaf = value.substr(slash == std::string_view::npos ? 0 : slash + 1);
    host_path = Join(g_sidecar_root, leaf);
    return host_path.size() <= kMaxPath;
}

bool PrepareSidecars(const std::string& base, const std::string& extracted_root,
                     std::string& sidecar_root) {
    sidecar_root = Join(base, "sidecars");
    if (!EnsureDirectory(sidecar_root)) return false;

    constexpr std::string_view metadata[] = {"DeviceProfile.xml", "B.A", "InsTime"};
    for (const std::string_view name : metadata) {
        const std::string sidecar = Join(sidecar_root, name);
        struct stat existing{};
        if (::lstat(sidecar.c_str(), &existing) == 0) {
            if (!S_ISREG(existing.st_mode)) {
                errno = EINVAL;
                return false;
            }
            // A previous diagnostic run may have created an empty sidecar
            // before the native generator crashed. Restore only that
            // recoverable empty state from the immutable template.
            if (existing.st_size != 0) continue;
        } else if (errno != ENOENT) {
            return false;
        }

        const std::string template_path = Join(extracted_root, Join("data", name));
        if (!CopyHostFile(template_path, sidecar)) {
            LOGE("cannot seed metadata sidecar '%s' from '%s' errno=%d",
                 sidecar.c_str(), template_path.c_str(), errno);
            return false;
        }
    }
    SyncDirectoryBestEffort(sidecar_root);
    return true;
}

bool PrepareDirectSidecars(AAssetManager* manager, const std::string& base,
                           std::string& sidecar_root) {
    sidecar_root = Join(base, "sidecars");
    if (!EnsureDirectory(sidecar_root)) return false;

    constexpr std::string_view metadata[] = {"DeviceProfile.xml", "B.A", "InsTime"};
    for (const std::string_view name : metadata) {
        const std::string sidecar = Join(sidecar_root, name);
        struct stat existing{};
        if (::lstat(sidecar.c_str(), &existing) == 0) {
            if (!S_ISREG(existing.st_mode)) {
                errno = EINVAL;
                return false;
            }
            if (existing.st_size != 0) continue;
            if (::unlink(sidecar.c_str()) != 0) return false;
        } else if (errno != ENOENT) {
            return false;
        }

        const std::string template_asset = Join("data", name);
        AAsset* template_file = AAssetManager_open(manager, template_asset.c_str(), AASSET_MODE_RANDOM);
        if (!template_file) {
            LOGE("direct OBB reader missing sidecar template '%s'", template_asset.c_str());
            errno = ENOENT;
            return false;
        }
        const off64_t length = AAsset_getLength64(template_file);
        AAsset_close(template_file);
        if (length < 0 || static_cast<uint64_t>(length) > std::numeric_limits<int64_t>::max()) {
            errno = EOVERFLOW;
            return false;
        }
        if (!CopyAsset(manager, AssetFile{template_asset, static_cast<int64_t>(length)}, sidecar)) {
            LOGE("cannot seed direct-reader sidecar '%s' errno=%d", sidecar.c_str(), errno);
            return false;
        }
    }
    SyncDirectoryBestEffort(sidecar_root);
    return true;
}

}  // namespace

namespace AssetVfs {

ReadHandle::~ReadHandle() {
    delete static_cast<DirectReadState*>(state);
    state = nullptr;
}

bool Prepare(AAssetManager* manager, const std::string& external_files_dir,
             const std::string& external_obb_dir) {
    std::lock_guard lock(g_mutex);
    if (g_initialized) return g_prepare_ok;

    g_initialized = true;
    bool has_release_containers = false;
    if (manager) {
        AAsset* main_asset = AAssetManager_open(manager, std::string(kEmbeddedMainObb).c_str(),
                                                AASSET_MODE_RANDOM);
        if (main_asset) AAsset_close(main_asset);
        AAsset* patch_asset = AAssetManager_open(manager, std::string(kEmbeddedPatchObb).c_str(),
                                                  AASSET_MODE_RANDOM);
        has_release_containers = main_asset != nullptr || patch_asset != nullptr;
        if (patch_asset) AAsset_close(patch_asset);
    }
    if (!has_release_containers && ValidAbsolutePath(external_obb_dir)) {
        const std::string external_main = Join(external_obb_dir, kExternalMainObb);
        const std::string external_patch = Join(external_obb_dir, kExternalPatchObb);
        has_release_containers = ::access(external_main.c_str(), R_OK) == 0 ||
                                 ::access(external_patch.c_str(), R_OK) == 0;
    }
    if (has_release_containers) {
        // A release container layout is authoritative. Never fall back to
        // extracting assets/data if its reader fails; that would silently
        // violate the no-materialization release contract.
        g_prepare_ok = manager && PrepareDirectImpl(manager, external_files_dir,
                                                     external_obb_dir, g_sidecar_root);
        g_direct_enabled = g_prepare_ok;
    } else {
        g_prepare_ok = manager && PrepareImpl(manager, external_files_dir, g_extracted_root,
                                              g_sidecar_root, g_legacy_file_aliases);
        g_direct_enabled = false;
    }
    g_enabled = g_prepare_ok && (g_direct_enabled || !g_extracted_root.empty());
    if (!g_prepare_ok) {
        LOGE("embedded data VFS preparation failed; guest bootstrap will stop");
    }
    return g_prepare_ok;
}

std::shared_ptr<ReadHandle> OpenReadHandle(const char* guest_path) {
    std::lock_guard lock(g_mutex);
    if (!g_direct_enabled || !guest_path) {
        errno = ENOENT;
        return {};
    }
    std::string relative;
    IndexedEntry indexed;
    if (!DirectRelativeLocked(guest_path, relative) ||
        !FindDirectEntryLocked(relative, indexed)) {
        errno = ENOENT;
        return {};
    }
    auto handle = std::make_shared<ReadHandle>();
    auto* state = new DirectReadState{indexed.archive, indexed.entry};
    state->position = 0;
    handle->state = state;
    return handle;
}

ssize_t PRead(ReadHandle* handle, void* output, size_t count, off64_t offset) {
    if (!handle || !handle->state || (!output && count) || offset < 0) {
        errno = EINVAL;
        return -1;
    }
    auto* state = static_cast<DirectReadState*>(handle->state);
    if (static_cast<uint64_t>(offset) >= state->entry.size) return 0;
    const size_t available = static_cast<size_t>(std::min<uint64_t>(
        state->entry.size - static_cast<uint64_t>(offset), count));
    std::lock_guard lock(state->archive->mutex);
    if (!ReadArchiveBytes(*state->archive,
                          state->entry.data_offset + static_cast<uint64_t>(offset),
                          output, available)) {
        return -1;
    }
    return static_cast<ssize_t>(available);
}

ssize_t Read(ReadHandle* handle, void* output, size_t count) {
    if (!handle || !handle->state) {
        errno = EBADF;
        return -1;
    }
    auto* state = static_cast<DirectReadState*>(handle->state);
    std::lock_guard cursor_lock(state->cursor_mutex);
    const ssize_t result = PRead(handle, output, count, static_cast<off64_t>(state->position));
    if (result > 0) state->position += static_cast<uint64_t>(result);
    return result;
}

off64_t Seek(ReadHandle* handle, off64_t offset, int whence) {
    if (!handle || !handle->state) {
        errno = EBADF;
        return -1;
    }
    auto* state = static_cast<DirectReadState*>(handle->state);
    std::lock_guard cursor_lock(state->cursor_mutex);
    const int64_t size = static_cast<int64_t>(state->entry.size);
    const int64_t current = static_cast<int64_t>(state->position);
    int64_t base = 0;
    if (whence == SEEK_SET) base = 0;
    else if (whence == SEEK_CUR) base = current;
    else if (whence == SEEK_END) base = size;
    else {
        errno = EINVAL;
        return -1;
    }
    if ((offset > 0 && base > std::numeric_limits<int64_t>::max() - offset) ||
        (offset < 0 && base < std::numeric_limits<int64_t>::min() - offset)) {
        errno = EOVERFLOW;
        return -1;
    }
    const int64_t next = base + offset;
    if (next < 0) {
        errno = EINVAL;
        return -1;
    }
    state->position = static_cast<uint64_t>(next);
    return static_cast<off64_t>(next);
}

off64_t Tell(ReadHandle* handle) {
    if (!handle || !handle->state) {
        errno = EBADF;
        return -1;
    }
    auto* state = static_cast<DirectReadState*>(handle->state);
    std::lock_guard cursor_lock(state->cursor_mutex);
    return static_cast<off64_t>(state->position);
}

off64_t Size(ReadHandle* handle) {
    if (!handle || !handle->state) {
        errno = EBADF;
        return -1;
    }
    auto* state = static_cast<DirectReadState*>(handle->state);
    return static_cast<off64_t>(state->entry.size);
}

int StatReadPath(const char* guest_path, struct stat* output) {
    std::lock_guard lock(g_mutex);
    if (!g_direct_enabled || !guest_path) {
        errno = ENOENT;
        return -1;
    }
    std::string relative;
    if (!DirectRelativeLocked(guest_path, relative) ||
        !DirectPathStatLocked(relative, output)) return -1;
    return 0;
}

bool ListReadDirectory(const char* guest_path, std::vector<std::string>& names,
                       std::vector<bool>& directories) {
    std::lock_guard lock(g_mutex);
    if (!g_direct_enabled || !guest_path) {
        errno = ENOENT;
        return false;
    }
    std::string relative;
    if (!DirectRelativeLocked(guest_path, relative)) return false;
    return DirectListLocked(relative, names, directories);
}

bool DirectEnabled() {
    std::lock_guard lock(g_mutex);
    return g_direct_enabled;
}

bool TranslateReadPath(const char* guest_path, std::string& host_path) {
    std::lock_guard lock(g_mutex);
    std::string sidecar;
    if (MutablePathLocked(guest_path, sidecar) && ::access(sidecar.c_str(), R_OK) == 0) {
        host_path = std::move(sidecar);
        return true;
    }
    if (g_direct_enabled) return false;
    return TranslateLocked(guest_path, host_path);
}

bool TranslateMutablePath(const char* guest_path, std::string& host_path) {
    std::lock_guard lock(g_mutex);
    return MutablePathLocked(guest_path, host_path);
}

bool Enabled() {
    std::lock_guard lock(g_mutex);
    return g_enabled;
}

}  // namespace AssetVfs
