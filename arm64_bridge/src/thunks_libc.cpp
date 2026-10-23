// SPDX-License-Identifier: GPL-3.0-or-later
#include "thunk_manager.h"
#include "asset_vfs.h"
#include "dynarmic_host.h"
#include "thunk_types.h"
#include "jni_fake_env.h"
#include <android/log.h>
#include <android/set_abort_message.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <climits>
#include <cmath>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cctype>
#include <chrono>
#include <ctime>
#include <cwchar>
#include <dirent.h>
#include <fcntl.h>
#include <functional>
#include <libgen.h>
#include <limits>
#include <memory>
#include <mutex>
#include <netdb.h>
#include <poll.h>
#include <pthread.h>
#include <pwd.h>
#include <sched.h>
#include <semaphore.h>
#include <signal.h>
#include <string>
#include <string_view>
#include <thread>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/system_properties.h>
#include <sys/time.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <unistd.h>
#include <locale.h>
#include <unordered_map>
#include <vector>
#include <zlib.h>

#define LOG_TAG "Arm32Bridge_Libc"
#if defined(ASPHALT7_FINAL_SILENT)
#define LOGI(...) ((void)0)
#define LOGW(...) ((void)0)
#define LOGE(...) ((void)0)
#else
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#endif
#if defined(ASPHALT7_VFS_TELEMETRY)
#define VFS_LOGI(...) LOGI(__VA_ARGS__)
#else
#define VFS_LOGI(...) ((void)0)
#endif

extern "C" int BionicStrerrorR(int,char*,size_t) __asm__("strerror_r");

namespace {
using Jit = Dynarmic::A32::Jit;
using Host = DynarmicHost;

[[noreturn]] void Invalid(const char* what) {
    LOGE("libc boundary FAILED: %s", what);
    android_set_abort_message(what);
    std::abort();
}

void* Span(Host& host, uint32_t p, size_t n) {
    if ((!p && n) || uint64_t(p) + n > host.GetGuestMemorySize()) {
        uint32_t pc = 0, lr = 0;
        if (host.IsJitRunning()) {
            auto& jit = host.CurrentJit();
            pc = jit.Regs()[15];
            lr = jit.Regs()[14];
        }
        LOGE("invalid guest memory range p=0x%08x n=%zu pc=0x%08x lr=0x%08x", p, n, pc, lr);
        char reason[160];
        std::snprintf(reason, sizeof(reason),
                      "guest memory range p=0x%08x n=%zu pc=0x%08x lr=0x%08x", p, n, pc, lr);
        Invalid(reason);
    }
    return p ? host.GetGuestMemoryBase() + p : nullptr;
}

const char* String(Host& host, uint32_t p) {
    if (!p) return nullptr;
    auto* s = static_cast<const char*>(Span(host, p, 1));
    // XML tuning data in this title is larger than 1 MiB. Legacy fixed-size
    // buffers may place their terminator in zero-filled allocator padding, so
    // retain a finite arena bound while honoring larger checked allocations.
    const uint32_t allocation_size = host.GuestAllocSize(p);
    const size_t bound = std::max<size_t>(allocation_size, 4 * 1024 * 1024);
    size_t available = std::min<size_t>(host.GetGuestMemorySize() - p, bound);
    if (!memchr(s, 0, available)) {
        auto& jit = host.CurrentJit();
        const uint32_t sp = jit.Regs()[13];
        const uint32_t caller = GuestRangeValid(host.GetGuestMemorySize(), sp + 12, 4)
                                    ? host.MemoryRead32(sp + 12) : 0;
        const uint32_t frame8 = GuestRangeValid(host.GetGuestMemorySize(), sp + 24, 4)
                                    ? host.MemoryRead32(sp + 24) : 0;
        const uint32_t frame12 = GuestRangeValid(host.GetGuestMemorySize(), sp + 28, 4)
                                     ? host.MemoryRead32(sp + 28) : 0;
        const uint32_t frame16 = GuestRangeValid(host.GetGuestMemorySize(), sp + 32, 4)
                                     ? host.MemoryRead32(sp + 32) : 0;
        LOGE("invalid guest string p=0x%08x pc=0x%08x lr=0x%08x sp=0x%08x caller=0x%08x frame=%08x,%08x,%08x alloc=%u available=%zu words=%08x,%08x,%08x,%08x",
             p, jit.Regs()[15], jit.Regs()[14], sp, caller, frame8, frame12, frame16,
             allocation_size, available,
             host.MemoryRead32(p), host.MemoryRead32(p + 4),
             host.MemoryRead32(p + 8), host.MemoryRead32(p + 12));
        char reason[160];
        std::snprintf(reason, sizeof(reason),
                      "unterminated guest string p=0x%08x pc=0x%08x lr=0x%08x available=%zu",
                      p, jit.Regs()[15], jit.Regs()[14], available);
        Invalid(reason);
    }
    return s;
}

const char* BoundedString(Host& host,uint32_t p,size_t n){
    if(!n)return nullptr;
    auto* s=static_cast<const char*>(Span(host,p,1));
    size_t available=host.GetGuestMemorySize()-p;
    if(n>available && !memchr(s,0,available))Invalid("bounded string exceeds guest arena");
    return s;
}
constexpr uint8_t CtypeByte(unsigned c){
    if(c>=128)return 0;
    uint8_t flags=0;
    if(c<' '||c==127)flags|=0x20;
    if(c==' '||(c>=9&&c<=13))flags|=0x08;
    if(c==' ')flags|=0x80;
    if(c>='0'&&c<='9')flags|=0x04;
    if(c>='A'&&c<='Z')flags|=0x01;
    if(c>='a'&&c<='z')flags|=0x02;
    if((c>='A'&&c<='F')||(c>='a'&&c<='f'))flags|=0x40;
    if(c>' '&&c<127&&!(flags&0x07))flags|=0x10;
    return flags;
}
static_assert(CtypeByte(' ')==0x88 && CtypeByte('\t')==0x28 && CtypeByte('A')==0x41 && CtypeByte('0')==4);
uint32_t Address(Host& host,const void* p) {
    if(!p)return 0;
    uintptr_t value=reinterpret_cast<uintptr_t>(p),base=reinterpret_cast<uintptr_t>(host.GetGuestMemoryBase());
    if(value<base || value-base>=host.GetGuestMemorySize())Invalid("host pointer cannot be a guest pointer");
    return static_cast<uint32_t>(value-base);
}
void Errno(Host& host, int value) { host.MemoryWrite32(host.GuestErrnoAddress(), value); }
void Result(Jit& jit, Host& host, int64_t value) {
    const int saved = errno;
    jit.Regs()[0] = static_cast<uint32_t>(value);
    if (value < 0) Errno(host, saved);
}
void Failure(Jit& jit, Host& host, int error) { errno = error; Result(jit, host, -1); }

bool MissingPathError(int error) { return error == ENOENT || error == ENOTDIR; }

bool ReadOnlyMode(const char* mode) {
    return mode && !strpbrk(mode, "wa+");
}

bool ReadOnlyOpenFlags(int flags) {
    return (flags & O_ACCMODE) == O_RDONLY &&
           !(flags & (O_CREAT | O_TRUNC | O_EXCL | O_APPEND));
}

bool InterestingAssetPath(const char* guest_path) {
    if (!guest_path) return false;
    return std::strstr(guest_path, "file00") || std::strstr(guest_path, "file01") ||
           std::strstr(guest_path, "DeviceConfig.xml") ||
           std::strstr(guest_path, "DeviceProfile.xml") || std::strstr(guest_path, "/B.A") ||
           std::strstr(guest_path, "Textures") || std::strstr(guest_path, "Objects") ||
           std::strstr(guest_path, "Audio") || std::strstr(guest_path, ".bdae") ||
           std::strstr(guest_path, ".car") || std::strstr(guest_path, ".traffic") ||
           std::strstr(guest_path, ".zip");
}

bool IsOconfPath(const char* guest_path) {
    return guest_path && std::strstr(guest_path, "/oconf.bar");
}

std::atomic<uint64_t> g_oconf_open_count{0};
std::atomic<uint64_t> g_oconf_close_count{0};
std::atomic<int64_t> g_oconf_live_count{0};
#if defined(ASPHALT7_VFS_TELEMETRY)
std::atomic<uint32_t> g_audio_read_logs{0};
#endif

int AddVirtualFd(std::shared_ptr<AssetVfs::ReadHandle> handle, const char* label);

struct GuestOpenFile {
    FILE* stream = nullptr;
    std::shared_ptr<AssetVfs::ReadHandle> direct;
};

GuestOpenFile OpenGuestFile(const char* guest_path, const char* mode) {
    GuestOpenFile result;
    if (guest_path &&
        (std::strstr(guest_path, "DeviceConfig.xml") ||
         std::strstr(guest_path, "DeviceProfile.xml") ||
         std::strstr(guest_path, "/B.A") || std::strstr(guest_path, "file00b.bin"))) {
        VFS_LOGI("ASSETVFS fopen-entry mode='%s' guest='%s'", mode ? mode : "", guest_path);
    }
    if (ReadOnlyMode(mode)) {
        result.direct = AssetVfs::OpenReadHandle(guest_path);
        if (result.direct) {
            VFS_LOGI("ASSETVFS direct api=fopen mode='%s' guest='%s'", mode ? mode : "",
                 guest_path ? guest_path : "(null)");
            return result;
        }
    }
    std::string mapped;
    const bool translated = ReadOnlyMode(mode)
                                ? AssetVfs::TranslateReadPath(guest_path, mapped)
                                : AssetVfs::TranslateMutablePath(guest_path, mapped);
    if (translated) {
        // The legacy engine uses fopen("w") as a metadata existence/touch
        // probe. It performs no fwrite and then parses the existing profile
        // through its own filesystem layer. Preserve the seeded sidecar in
        // that narrow case; ordinary save-game paths never reach this branch.
        std::string host_mode;
        const char* effective_mode = mode;
        if (!ReadOnlyMode(mode) && mode[0] == 'w' && !std::strchr(mode, '+')) {
            host_mode = std::strchr(mode, 'b') ? "r+b" : "r+";
            effective_mode = host_mode.c_str();
        }
        FILE* stream = ::fopen(mapped.c_str(), effective_mode);
        const int saved = errno;
        if (stream) {
            VFS_LOGI("ASSETVFS path-map api=fopen mode='%s' host-mode='%s' guest='%s' host='%s'",
                 mode, effective_mode, guest_path, mapped.c_str());
            result.stream = stream;
            return result;
        }
        if (!MissingPathError(saved)) {
            errno = saved;
            return result;
        }
    }
    FILE* fallback = ::fopen(guest_path, mode);
    if (InterestingAssetPath(guest_path)) {
        VFS_LOGI("ASSETVFS fallback api=fopen mode='%s' guest='%s' result=%s errno=%d",
             mode ? mode : "", guest_path ? guest_path : "(null)",
             fallback ? "open" : "miss", fallback ? 0 : errno);
    }
    result.stream = fallback;
    return result;
}

int OpenGuestFileDescriptor(const char* guest_path, int flags, mode_t mode) {
    if (ReadOnlyOpenFlags(flags)) {
        std::shared_ptr<AssetVfs::ReadHandle> direct = AssetVfs::OpenReadHandle(guest_path);
        if (direct) {
            const int fd = AddVirtualFd(std::move(direct), guest_path);
            VFS_LOGI("ASSETVFS direct api=open flags=0x%x guest='%s' vfd=%d",
                 flags, guest_path ? guest_path : "(null)", fd);
            return fd;
        }
    }
    std::string mapped;
    const bool translated = ReadOnlyOpenFlags(flags)
                                ? AssetVfs::TranslateReadPath(guest_path, mapped)
                                : AssetVfs::TranslateMutablePath(guest_path, mapped);
    if (translated) {
        int effective_flags = flags;
        if (!ReadOnlyOpenFlags(flags) && (flags & O_TRUNC)) {
            // Match the fopen metadata-preservation rule for callers that
            // use open(2) instead of stdio.
            effective_flags &= ~O_TRUNC;
            if ((effective_flags & O_ACCMODE) == O_WRONLY) {
                effective_flags = (effective_flags & ~O_ACCMODE) | O_RDWR;
            }
        }
        const int fd = ::open(mapped.c_str(), effective_flags, mode);
        const int saved = errno;
        if (fd >= 0) {
            VFS_LOGI("ASSETVFS path-map api=open flags=0x%x host-flags=0x%x guest='%s' host='%s' fd=%d",
                 flags, effective_flags, guest_path, mapped.c_str(), fd);
            return fd;
        }
        if (!MissingPathError(saved)) {
            errno = saved;
            return -1;
        }
    }
    const int fallback = ::open(guest_path, flags, mode);
    if (InterestingAssetPath(guest_path)) {
        VFS_LOGI("ASSETVFS fallback api=open flags=0x%x guest='%s' result=%s errno=%d",
             flags, guest_path ? guest_path : "(null)",
             fallback >= 0 ? "open" : "miss", fallback >= 0 ? 0 : errno);
    }
    return fallback;
}

int StatGuestPath(const char* guest_path, struct stat* output) {
    if (AssetVfs::DirectEnabled() && AssetVfs::StatReadPath(guest_path, output) == 0) {
        VFS_LOGI("ASSETVFS direct api=stat guest='%s'", guest_path ? guest_path : "(null)");
        return 0;
    }
    std::string mapped;
    if (AssetVfs::TranslateReadPath(guest_path, mapped)) {
        const int rc = ::stat(mapped.c_str(), output);
        const int saved = errno;
        if (rc == 0) {
            VFS_LOGI("ASSETVFS path-map api=stat guest='%s' host='%s'", guest_path, mapped.c_str());
            return 0;
        }
        if (!MissingPathError(saved)) {
            errno = saved;
            return rc;
        }
    }
    return ::stat(guest_path, output);
}

struct OpenDirectoryResult {
    DIR* native = nullptr;
    std::vector<std::string> names;
    std::vector<bool> directories;
    bool direct = false;
};

OpenDirectoryResult OpenGuestDirectory(const char* guest_path) {
    OpenDirectoryResult result;
    // The direct reader exposes archive directories without materializing
    // them. The libc Directory wrapper consumes this list below.
    if (AssetVfs::DirectEnabled() &&
        AssetVfs::ListReadDirectory(guest_path, result.names, result.directories)) {
        result.direct = true;
        return result;
    }
    std::string mapped;
    if (AssetVfs::TranslateReadPath(guest_path, mapped)) {
        DIR* directory = ::opendir(mapped.c_str());
        const int saved = errno;
        if (directory) {
            VFS_LOGI("ASSETVFS path-map api=opendir guest='%s' host='%s'", guest_path, mapped.c_str());
            result.native = directory;
            return result;
        }
        if (!MissingPathError(saved)) {
            errno = saved;
            return result;
        }
    }
    result.native = ::opendir(guest_path);
    return result;
}

int AccessGuestPath(const char* guest_path, int mode) {
    if (!(mode & W_OK) && AssetVfs::DirectEnabled()) {
        struct stat value{};
        if (AssetVfs::StatReadPath(guest_path, &value) == 0) {
            VFS_LOGI("ASSETVFS direct api=access guest='%s'", guest_path ? guest_path : "(null)");
            return 0;
        }
    }
    std::string mapped;
    const bool translated = (mode & W_OK)
                                ? AssetVfs::TranslateMutablePath(guest_path, mapped)
                                : AssetVfs::TranslateReadPath(guest_path, mapped);
    if (translated) {
        const int rc = ::access(mapped.c_str(), mode);
        const int saved = errno;
        if (rc == 0) {
            VFS_LOGI("ASSETVFS path-map api=access guest='%s' host='%s'", guest_path, mapped.c_str());
            return 0;
        }
        if (!MissingPathError(saved)) {
            errno = saved;
            return rc;
        }
    }
    return ::access(guest_path, mode);
}

gzFile OpenGuestGzip(const char* guest_path, const char* mode) {
    std::string mapped;
    if (ReadOnlyMode(mode) && AssetVfs::TranslateReadPath(guest_path, mapped)) {
        gzFile file = ::gzopen(mapped.c_str(), mode);
        const int saved = errno;
        if (file) {
            VFS_LOGI("ASSETVFS path-map api=gzopen guest='%s' host='%s'", guest_path, mapped.c_str());
            return file;
        }
        if (!MissingPathError(saved)) {
            errno = saved;
            return nullptr;
        }
    }
    return ::gzopen(guest_path, mode);
}

bool AffinityWideEnabled() {
    static const bool enabled = [] {
        char override_value[PROP_VALUE_MAX]{};
        if (__system_property_get("debug.conduit.affinity_wide", override_value) > 0) {
            if (std::strcmp(override_value, "0") == 0) {
                LOGI("affinity-wide policy disabled by debug override");
                return false;
            }
            if (std::strcmp(override_value, "1") == 0) {
                LOGI("affinity-wide policy enabled by debug override");
                return true;
            }
            LOGW("invalid debug.conduit.affinity_wide='%s'; affinity-wide policy enabled by default",
                  override_value);
            return true;
        }

        LOGI("affinity-wide policy enabled by default");
        return true;
    }();
    return enabled;
}

uint32_t Low32CpuMask(const cpu_set_t& native, bool* has_high = nullptr) {
    uint32_t mask = 0;
    bool high = false;
    for (int cpu = 0; cpu < CPU_SETSIZE; ++cpu) {
        if (!CPU_ISSET(cpu, &native)) continue;
        if (cpu < 32) mask |= 1u << cpu;
        else high = true;
    }
    if (has_high) *has_high = high;
    return mask;
}

bool ReadCurrentThreadAllowedCpuMask(cpu_set_t& native, uint32_t& low, bool& has_high) {
    char path[64]{};
    const int path_size = std::snprintf(
        path, sizeof(path), "/proc/self/task/%d/status", static_cast<int>(gettid()));
    if (path_size <= 0 || static_cast<size_t>(path_size) >= sizeof(path)) return false;
    FILE* file = std::fopen(path, "r");
    if (!file) return false;

    char* line = nullptr;
    size_t capacity = 0;
    bool parsed = false;
    constexpr char prefix[] = "Cpus_allowed_list:";
    while (getline(&line, &capacity, file) >= 0) {
        if (std::strncmp(line, prefix, sizeof(prefix) - 1) != 0) continue;
        cpu_set_t candidate{};
        CPU_ZERO(&candidate);
        uint32_t candidate_low = 0;
        bool candidate_high = false;
        bool any = false;
        char* cursor = line + sizeof(prefix) - 1;
        parsed = true;
        for (;;) {
            while (*cursor && std::isspace(static_cast<unsigned char>(*cursor))) ++cursor;
            if (!*cursor) break;
            errno = 0;
            char* end = nullptr;
            const unsigned long first = std::strtoul(cursor, &end, 10);
            if (errno || end == cursor) { parsed = false; break; }
            unsigned long last = first;
            cursor = end;
            if (*cursor == '-') {
                errno = 0;
                last = std::strtoul(cursor + 1, &end, 10);
                if (errno || end == cursor + 1) { parsed = false; break; }
                cursor = end;
            }
            if (first > last || last >= CPU_SETSIZE) { parsed = false; break; }
            for (unsigned long cpu = first; cpu <= last; ++cpu) {
                CPU_SET(static_cast<int>(cpu), &candidate);
                if (cpu < 32) candidate_low |= 1u << cpu;
                else candidate_high = true;
            }
            any = true;
            while (*cursor && std::isspace(static_cast<unsigned char>(*cursor))) ++cursor;
            if (!*cursor) break;
            if (*cursor != ',') { parsed = false; break; }
            ++cursor;
        }
        parsed = parsed && any;
        if (parsed) {
            native = candidate;
            low = candidate_low;
            has_high = candidate_high;
        }
        break;
    }
    std::free(line);
    std::fclose(file);
    return parsed;
}

// A successful real getaffinity plus the same thread's kernel-reported allowed
// list may feed exactly one immediately following guest setaffinity.  The list
// retains temporarily-offline CPUs, stays inside the app's allowed cpuset, and
// never changes the syscall result reported to the guest.
thread_local cpu_set_t g_affinity_before_guest_pin{};
thread_local uint32_t g_affinity_before_guest_pin_low = 0;
thread_local uint32_t g_affinity_before_guest_pin_observed_low = 0;
thread_local bool g_affinity_before_guest_pin_valid = false;

uint32_t CopyString(Host& host, const char* s) {
    if (!s) return 0;
    size_t size = strlen(s) + 1;
    uint32_t p = host.GuestAlloc(size, 4);
    if (p) memcpy(Span(host, p, size), s, size);
    return p;
}

struct Time32 { int32_t sec, nsec; };
static_assert(sizeof(Time32) == 8);
bool ReadTime(Host& host, uint32_t p, timespec& result) {
    auto* t = static_cast<const Time32*>(Span(host, p, sizeof(Time32)));
    if (t->nsec < 0 || t->nsec >= 1000000000) return false;
    result = {t->sec, t->nsec};
    return true;
}
bool WriteTime(Host& host, uint32_t p, const timespec& value) {
    if (value.tv_sec < INT32_MIN || value.tv_sec > INT32_MAX) { errno = EOVERFLOW; return false; }
    Time32 t{static_cast<int32_t>(value.tv_sec), static_cast<int32_t>(value.tv_nsec)};
    memcpy(Span(host, p, sizeof(t)), &t, sizeof(t));
    return true;
}

// Bionic ARM32 stat/stat64 is 104 bytes, not the generic Linux 64-byte old stat.
struct alignas(8) Stat32 {
    uint64_t dev;
    uint32_t pad0, ino32, mode, nlink, uid, gid;
    uint64_t rdev;
    uint32_t pad3, pad4;
    int64_t size;
    uint32_t blksize, pad5;
    uint64_t blocks;
    Time32 atime, mtime, ctime;
    uint64_t ino;
};
static_assert(sizeof(Stat32) == 104 && offsetof(Stat32, size) == 48 && offsetof(Stat32, ino) == 96);
bool WriteStat(Host& host, uint32_t p, const struct stat& s) {
    if (s.st_atim.tv_sec > INT32_MAX || s.st_atim.tv_sec < INT32_MIN ||
        s.st_mtim.tv_sec > INT32_MAX || s.st_mtim.tv_sec < INT32_MIN ||
        s.st_ctim.tv_sec > INT32_MAX || s.st_ctim.tv_sec < INT32_MIN) { errno = EOVERFLOW; return false; }
    Stat32 g{};
    g.dev=s.st_dev; g.ino32=static_cast<uint32_t>(s.st_ino); g.mode=s.st_mode;
    g.nlink=s.st_nlink; g.uid=s.st_uid; g.gid=s.st_gid; g.rdev=s.st_rdev;
    g.size=s.st_size; g.blksize=s.st_blksize; g.blocks=s.st_blocks; g.ino=s.st_ino;
    g.atime={static_cast<int32_t>(s.st_atim.tv_sec),static_cast<int32_t>(s.st_atim.tv_nsec)};
    g.mtime={static_cast<int32_t>(s.st_mtim.tv_sec),static_cast<int32_t>(s.st_mtim.tv_nsec)};
    g.ctime={static_cast<int32_t>(s.st_ctim.tv_sec),static_cast<int32_t>(s.st_ctim.tv_nsec)};
    memcpy(Span(host,p,sizeof(g)),&g,sizeof(g));
    return true;
}
struct alignas(8) Dirent32 {
    uint64_t ino;
    int64_t off;
    uint16_t reclen;
    uint8_t type;
    char name[256];
};
static_assert(sizeof(Dirent32)==280 && offsetof(Dirent32,name)==19);
struct Tm32 { int32_t sec,min,hour,mday,mon,year,wday,yday,isdst,gmtoff; uint32_t zone; };
static_assert(sizeof(Tm32)==44);
struct Attr32 { uint32_t flags,base,size,guard; int32_t policy,priority; };
static_assert(sizeof(Attr32)==24);

struct ThreadCache {
    std::unordered_map<std::string, std::pair<uint32_t,size_t>> strings;
    uint32_t tm=0, passwd=0, hostent=0;
    size_t passwd_capacity=0, hostent_capacity=0;
    uint32_t strtok_next=0;
};
thread_local ThreadCache t_cache;
thread_local std::unordered_map<Host*, uint32_t> t_kuser_tls;
uint32_t Self();

uint32_t KuserTlsAddress(Host& host) {
    auto& address = t_kuser_tls[&host];
    if (address) return address;
    address = host.GuestAlloc(16 * sizeof(uint32_t), 8);
    if (!address) return 0;
    memset(Span(host, address, 16 * sizeof(uint32_t)), 0, 16 * sizeof(uint32_t));
    host.MemoryWrite32(address + 0, address);
    host.MemoryWrite32(address + 8, Self());
    host.MemoryWrite32(address + 12, host.GuestErrnoAddress());
    return address;
}

uint32_t CachedString(Host& host, const std::string& key, const char* value) {
    if (!value) return 0;
    size_t n=strlen(value)+1;
    auto& entry=t_cache.strings[key];
    if (entry.second<n) {
        uint32_t next=host.GuestAlloc(n,4);
        if (!next) return 0;
        host.GuestFree(entry.first); entry={next,n};
    }
    memcpy(Span(host,entry.first,n),value,n);
    return entry.first;
}
void WriteTm(Host& host,uint32_t p,const tm& t) {
    Tm32 g{t.tm_sec,t.tm_min,t.tm_hour,t.tm_mday,t.tm_mon,t.tm_year,t.tm_wday,t.tm_yday,t.tm_isdst,
           static_cast<int32_t>(t.tm_gmtoff),CachedString(host,"tm_zone",t.tm_zone)};
    memcpy(Span(host,p,sizeof(g)),&g,sizeof(g));
}

size_t GuestWideLength(Host& host, uint32_t address) {
    if (!address || !GuestRangeValid(host.GetGuestMemorySize(), address, sizeof(wchar_t)))
        Invalid("null or invalid guest wide string");
    const size_t max_chars = std::min<size_t>(
        (host.GetGuestMemorySize() - address) / sizeof(wchar_t), 1024 * 1024);
    for (size_t index = 0; index < max_chars; ++index) {
        const uint64_t word_address = static_cast<uint64_t>(address) +
                                      static_cast<uint64_t>(index) * sizeof(wchar_t);
        if (host.MemoryRead32(static_cast<uint32_t>(word_address)) == 0)
            return index;
    }
    Invalid("unterminated guest wide string");
}

uint32_t CacheHostent(Host& host, const hostent* source) {
    if (!source) return 0;
    std::vector<const char*> aliases;
    if (source->h_aliases) {
        for (size_t i=0; source->h_aliases[i] && i<64; ++i) aliases.push_back(source->h_aliases[i]);
    }
    std::vector<const unsigned char*> addresses;
    if (source->h_addr_list) {
        for (size_t i=0; source->h_addr_list[i] && i<64; ++i)
            addresses.push_back(reinterpret_cast<const unsigned char*>(source->h_addr_list[i]));
    }
    const size_t address_bytes = source->h_length > 0 && source->h_length <= 16
        ? static_cast<size_t>(source->h_length) : 0;
    size_t size = 20 + (aliases.size()+1)*4 + (addresses.size()+1)*4;
    if (source->h_name) size += strlen(source->h_name)+1;
    for (const char* alias : aliases) size += strlen(alias)+1;
    size += addresses.size()*address_bytes;
    if (size > 64*1024) { Errno(host, EOVERFLOW); return 0; }
    if (size > t_cache.hostent_capacity) {
        uint32_t next=host.GuestAlloc(size,4);
        if (!next) { Errno(host,ENOMEM); return 0; }
        host.GuestFree(t_cache.hostent);
        t_cache.hostent=next;t_cache.hostent_capacity=size;
    }
    const uint32_t base=t_cache.hostent;
    memset(Span(host,base,size),0,size);
    uint32_t cursor=base+20;
    const uint32_t aliases_ptr=cursor;cursor+=(aliases.size()+1)*4;
    const uint32_t addresses_ptr=cursor;cursor+=(addresses.size()+1)*4;
    auto copy_string=[&](const char* text)->uint32_t{
        if(!text)return 0;const size_t n=strlen(text)+1;const uint32_t result=cursor;
        memcpy(Span(host,result,n),text,n);cursor+=static_cast<uint32_t>(n);return result;
    };
    host.MemoryWrite32(base+0,copy_string(source->h_name));
    for(size_t i=0;i<aliases.size();++i) host.MemoryWrite32(aliases_ptr+static_cast<uint32_t>(i*4),copy_string(aliases[i]));
    host.MemoryWrite32(base+4,aliases_ptr);
    host.MemoryWrite32(base+8,static_cast<uint32_t>(source->h_addrtype));
    host.MemoryWrite32(base+12,static_cast<uint32_t>(source->h_length));
    for(size_t i=0;i<addresses.size();++i){
        const uint32_t address=cursor;
        memcpy(Span(host,address,address_bytes),addresses[i],address_bytes);cursor+=static_cast<uint32_t>(address_bytes);
        host.MemoryWrite32(addresses_ptr+static_cast<uint32_t>(i*4),address);
    }
    host.MemoryWrite32(base+16,addresses_ptr);
    return base;
}

std::atomic<int> g_standard_fds[3]={-1,-1,-1};
FILE* g_standard_streams[3]={};
int NativeFd(int fd){return fd>=0&&fd<3?g_standard_fds[fd].load():fd;}
struct File {
    std::mutex mutex;
    FILE* stream = nullptr;
    std::shared_ptr<AssetVfs::ReadHandle> direct;
    std::string label;
    explicit File(FILE* f, std::string l = {}):stream(f),label(std::move(l)) {}
    explicit File(std::shared_ptr<AssetVfs::ReadHandle> h, std::string l = {})
        : direct(std::move(h)), label(std::move(l)) {}
    ~File(){ if(stream) fclose(stream); }
};
struct Directory {
    std::mutex mutex;
    DIR* directory = nullptr;
    uint32_t entry;
    std::vector<std::string> names;
    std::vector<bool> directories;
    size_t index = 0;
    bool virtual_directory = false;
    Directory(DIR* d,uint32_t p):directory(d),entry(p) {}
    Directory(std::vector<std::string> n, std::vector<bool> d, uint32_t p)
        : entry(p), names(std::move(n)), directories(std::move(d)), virtual_directory(true) {}
    ~Directory(){ if(directory) closedir(directory); }
};
struct Gzip {
    std::mutex mutex;
    gzFile file;
    explicit Gzip(gzFile f):file(f) {}
    ~Gzip(){ if(file) gzclose(file); }
};
std::mutex g_handles_mutex;
std::unordered_map<uint32_t,std::shared_ptr<File>> g_files;
std::unordered_map<uint32_t,std::shared_ptr<Directory>> g_dirs;
std::unordered_map<uint32_t,std::shared_ptr<Gzip>> g_gzip;
std::unordered_map<uint32_t,std::vector<uint32_t>> g_addrinfo;
struct VirtualFd {
    std::mutex mutex;
    std::shared_ptr<AssetVfs::ReadHandle> handle;
    std::string label;
    int flags = O_RDONLY;
};
std::atomic<int> g_next_virtual_fd{0x40000000};
std::unordered_map<int,std::shared_ptr<VirtualFd>> g_virtual_fds;

template<class T> std::shared_ptr<T> Lookup(const std::unordered_map<uint32_t,std::shared_ptr<T>>& table,uint32_t p) {
    std::lock_guard lock(g_handles_mutex);
    auto it=table.find(p);
    if(it==table.end()){ errno=EBADF; return {}; }
    return it->second;
}
template<class R,class Fn> R WithFile(uint32_t p,R fail,Fn&& fn) {
    auto file=Lookup(g_files,p);
    if(!file) return fail;
    std::lock_guard lock(file->mutex);
    if(!file->stream){errno=EBADF;return fail;}
    return fn(file->stream);
}

std::shared_ptr<VirtualFd> LookupVirtualFd(int fd) {
    std::lock_guard lock(g_handles_mutex);
    auto it = g_virtual_fds.find(fd);
    if (it == g_virtual_fds.end()) return {};
    return it->second;
}

std::shared_ptr<VirtualFd> TakeVirtualFd(int fd) {
    std::lock_guard lock(g_handles_mutex);
    auto it = g_virtual_fds.find(fd);
    if (it == g_virtual_fds.end()) return {};
    auto result = std::move(it->second);
    g_virtual_fds.erase(it);
    return result;
}

int AddVirtualFd(std::shared_ptr<AssetVfs::ReadHandle> handle, const char* label) {
    if (!handle) {
        errno = EINVAL;
        return -1;
    }
    for (unsigned attempt = 0; attempt != 100000; ++attempt) {
        const int fd = g_next_virtual_fd.fetch_add(1, std::memory_order_relaxed);
        if (fd < 0) continue;
        auto value = std::make_shared<VirtualFd>();
        value->handle = std::move(handle);
        if (label) value->label = label;
        std::lock_guard lock(g_handles_mutex);
        if (g_virtual_fds.emplace(fd, std::move(value)).second) return fd;
    }
    errno = EMFILE;
    return -1;
}

bool IsVirtualFile(uint32_t p) {
    auto file = Lookup(g_files, p);
    return file && static_cast<bool>(file->direct);
}

std::string FileLabel(uint32_t p) {
    auto file = Lookup(g_files, p);
    return file ? file->label : std::string();
}

bool IsMetadataLabel(const std::string& label) {
    const size_t slash = label.rfind('/');
    const std::string_view leaf(label.data() + (slash == std::string::npos ? 0 : slash + 1),
                                slash == std::string::npos ? label.size() : label.size() - slash - 1);
    return leaf == "DeviceProfile.xml" || leaf == "B.A" || leaf == "InsTime";
}

void LogFileOperation(const char* operation, uint32_t handle, const std::string& label,
                      size_t requested, size_t result) {
    if (!label.empty() && IsMetadataLabel(label)) {
        VFS_LOGI("ASSETVFS file-op=%s handle=0x%08x guest='%s' requested=%zu result=%zu",
             operation, handle, label.c_str(), requested, result);
    }
}

uint32_t AddFile(Host& host,FILE* file, const char* label = nullptr) {
    if(!file)return 0;
    uint32_t p=host.GuestAlloc(84,4);
    if(!p){fclose(file);errno=ENOMEM;return 0;}
    memset(Span(host,p,84),0,84);
    host.MemoryWrite16(p+14,static_cast<uint16_t>(fileno(file)));
    std::lock_guard lock(g_handles_mutex);
    g_files.emplace(p,std::make_shared<File>(file, label ? label : std::string()));
    return p;
}
uint32_t AddFile(Host& host, std::shared_ptr<AssetVfs::ReadHandle> direct, const char* label = nullptr) {
    if (!direct) return 0;
    uint32_t p = host.GuestAlloc(84, 4);
    if (!p) { errno = ENOMEM; return 0; }
    memset(Span(host, p, 84), 0, 84);
    host.MemoryWrite16(p + 14, 0xffffu);
    std::lock_guard lock(g_handles_mutex);
    g_files.emplace(p, std::make_shared<File>(std::move(direct), label ? label : std::string()));
    return p;
}
int CloseFile(Host& host,uint32_t p){
    auto f=Lookup(g_files,p);if(!f){errno=EBADF;return -1;}
    const bool is_oconf = f->label.find("/oconf.bar") != std::string::npos;
    bool standard=p>=0x200&&p<0x200+3*84;
    int rc;
    {std::lock_guard lock(f->mutex);
        if(!f->stream && !f->direct){errno=EBADF;return -1;}
        if(standard)g_standard_fds[(p-0x200)/84]=-1;
        rc=f->direct ? 0 : fclose(f->stream);f->stream=nullptr;f->direct.reset();
    }
    int saved=errno;{std::lock_guard lock(g_handles_mutex);g_files.erase(p);}
    if (is_oconf) {
        const uint64_t closed = g_oconf_close_count.fetch_add(1, std::memory_order_relaxed) + 1;
        const int64_t live = g_oconf_live_count.fetch_sub(1, std::memory_order_relaxed) - 1;
        if ((closed & 0x7fu) == 0) {
            LOGI("oconf handle stats closed=%llu live=%lld guest=0x%08x",
                 static_cast<unsigned long long>(closed),
                 static_cast<long long>(live), p);
        }
    }
    if(!standard)host.GuestFree(p);errno=saved;return rc;
}
int LogWrite(FILE* file,const char* s,size_t count) {
    bool standard_out=file==g_standard_streams[1]&&g_standard_fds[1]>=0;
    bool standard_error=file==g_standard_streams[2]&&g_standard_fds[2]>=0;
    if(standard_out || standard_error){
#if defined(ASPHALT7_FINAL_SILENT)
        (void)s;
#else
        for(size_t i=0;i<count;i+=4000) __android_log_print(standard_error?ANDROID_LOG_ERROR:ANDROID_LOG_INFO,
            "Asphalt7Guest","%.*s",static_cast<int>(std::min<size_t>(4000,count-i)),s+i);
#endif
        return static_cast<int>(count);
    }
    size_t n=fwrite(s,1,count,file);
    return n==count?static_cast<int>(n):-1;
}

// Address-keyed host objects retain their lifetime while waits release the registry lock.
struct Mutex {
    pthread_mutex_t value;
    bool live=false;
    explicit Mutex(int type){
        pthread_mutexattr_t attr;
        int rc=pthread_mutexattr_init(&attr);
        if(rc)Invalid("host mutex attributes");
        rc=pthread_mutexattr_settype(&attr,type);
        if(!rc)rc=pthread_mutex_init(&value,&attr);
        pthread_mutexattr_destroy(&attr);
        if(rc)Invalid("host mutex initialization");
        live=true;
    }
    ~Mutex(){if(live && pthread_mutex_destroy(&value))Invalid("destroying live guest mutex");}
};
struct Condition {
    pthread_cond_t value;
    clockid_t clock;
    bool live=false;
    std::mutex legacy_mutex;
    std::condition_variable legacy_cv;
    size_t legacy_waiters=0;
    size_t legacy_wakeups=0;
    std::atomic<bool> legacy_logged=false;
    explicit Condition(clockid_t c):clock(c){
        pthread_condattr_t attr;
        int rc=pthread_condattr_init(&attr);
        if(rc)Invalid("host condition attributes");
        rc=pthread_condattr_setclock(&attr,c);
        if(!rc)rc=pthread_cond_init(&value,&attr);
        pthread_condattr_destroy(&attr);
        if(rc)Invalid("host condition initialization");
        live=true;
    }
    int WaitWithoutMutex(){
        std::unique_lock lock(legacy_mutex);
        ++legacy_waiters;
        legacy_cv.wait(lock,[&]{return legacy_wakeups!=0;});
        --legacy_wakeups;
        --legacy_waiters;
        return 0;
    }
    int Signal(){
        bool notify=false;
        {
            std::lock_guard lock(legacy_mutex);
            if(legacy_waiters>legacy_wakeups){++legacy_wakeups;notify=true;}
        }
        if(notify){legacy_cv.notify_one();return 0;}
        return pthread_cond_signal(&value);
    }
    int Broadcast(){
        int rc=pthread_cond_broadcast(&value);
        bool notify=false;
        {
            std::lock_guard lock(legacy_mutex);
            if(legacy_waiters){legacy_wakeups=legacy_waiters;notify=true;}
        }
        if(notify)legacy_cv.notify_all();
        return rc;
    }
    size_t LegacyWaiters(){
        std::lock_guard lock(legacy_mutex);
        return legacy_waiters;
    }
    ~Condition(){if(live && pthread_cond_destroy(&value))Invalid("destroying live guest condition");}
};
struct Semaphore {
    sem_t value;
    bool live=false;
    explicit Semaphore(unsigned count){if(sem_init(&value,0,count))Invalid("host semaphore initialization");live=true;}
    ~Semaphore(){if(live && sem_destroy(&value))Invalid("destroying live guest semaphore");}
};
struct Once {
    std::mutex mutex;
    std::condition_variable cv;
    unsigned state=0;
    bool Run(const std::function<bool()>& init){
        std::unique_lock lock(mutex);
        cv.wait(lock,[&]{return state!=1;});
        if(state==2)return true;
        state=1;lock.unlock();
        bool complete=init();
        lock.lock();state=complete?2:0;lock.unlock();cv.notify_all();
        return complete;
    }
};
std::mutex g_sync_mutex;
std::unordered_map<uint32_t,std::shared_ptr<Mutex>> g_mutexes;
std::unordered_map<uint32_t,std::shared_ptr<Condition>> g_conditions;
std::unordered_map<uint32_t,std::shared_ptr<Semaphore>> g_semaphores;
std::unordered_map<uint32_t,std::shared_ptr<Once>> g_once;

std::shared_ptr<Mutex> GetMutex(Host& host,uint32_t p){
    if(!p){errno=EINVAL;return {};}
    Span(host,p,4);
    std::lock_guard lock(g_sync_mutex);
    auto it=g_mutexes.find(p);
    if(it!=g_mutexes.end())return it->second;
    uint32_t word=host.MemoryRead32(p);
    if(word&~0xc000u || (word>>14)>2){errno=EINVAL;return {};}
    auto value=std::make_shared<Mutex>(static_cast<int>(word>>14));
    g_mutexes.emplace(p,value);return value;
}
std::shared_ptr<Condition> GetCondition(Host& host,uint32_t p){
    if(!p){errno=EINVAL;return {};}
    Span(host,p,4);
    std::lock_guard lock(g_sync_mutex);
    auto it=g_conditions.find(p);
    if(it!=g_conditions.end())return it->second;
    uint32_t word=host.MemoryRead32(p);
    if(word&~2u){errno=(word&1)?ENOTSUP:EINVAL;return {};}
    auto value=std::make_shared<Condition>((word&2)?CLOCK_MONOTONIC:CLOCK_REALTIME);
    g_conditions.emplace(p,value);return value;
}
std::shared_ptr<Semaphore> GetSemaphore(uint32_t p){
    std::lock_guard lock(g_sync_mutex);
    auto it=g_semaphores.find(p);
    if(it==g_semaphores.end()){errno=EINVAL;return {};}
    return it->second;
}
int WaitCondition(Host& host,uint32_t cond,uint32_t mutex,uint32_t deadline,bool relative){
    auto c=GetCondition(host,cond);if(!c)return errno;
    // Immersion's legacy Android library deliberately passes a null mutex and
    // treats pthread_cond_wait as an event wait. Bionic tolerated this pattern;
    // returning EINVAL makes its haptic worker spin at 100% instead of sleeping.
    if(!mutex){
        if(relative || deadline)return EINVAL;
        if(!c->legacy_logged.exchange(true,std::memory_order_relaxed))
            LOGI("legacy pthread_cond_wait(cond=0x%08x, mutex=null): event wait enabled",cond);
        return c->WaitWithoutMutex();
    }
    auto m=GetMutex(host,mutex);if(!m)return errno;
    if(!relative && !deadline)return pthread_cond_wait(&c->value,&m->value);
    timespec time{};
    if(relative){
        if(clock_gettime(c->clock,&time))return errno;
        time.tv_sec+=deadline/1000;time.tv_nsec+=(deadline%1000)*1000000LL;
        time.tv_sec+=time.tv_nsec/1000000000;time.tv_nsec%=1000000000;
    }else if(!ReadTime(host,deadline,time))return EINVAL;
    return pthread_cond_timedwait(&c->value,&m->value,&time);
}

struct Thread {
    std::mutex mutex;
    pthread_t native{};
    bool detached=false,finished=false,joining=false,external=false;
    uint32_t retval=0,id=0;
};
std::mutex g_threads_mutex;
std::unordered_map<uint32_t,std::shared_ptr<Thread>> g_threads;
uint32_t g_next_thread=1;
thread_local std::shared_ptr<Thread> t_thread;
struct Key {uint32_t destructor;};
std::mutex g_keys_mutex;
std::unordered_map<uint32_t,Key> g_keys;
// ponytail: opaque monotonic keys avoid stale deleted-key values; 2^32 creations per process.
uint32_t g_next_key=1;
thread_local std::unordered_map<uint32_t,uint32_t> t_keys;

struct GuestJumpContext {
    std::thread::id owner{};
    Jit* jit=nullptr;
    std::array<uint32_t,8> callee_saved{};
    std::array<uint32_t,16> ext_regs{}; // D8-D15, as S16-S31.
    uint32_t fpscr=0;
    uint32_t sp=0;
    uint32_t lr=0;
    uint32_t cpsr=0;
    uint32_t signal_mask=0;
    bool saves_signal_mask=false;
};
struct GuestSignalAction {
    uint32_t handler=0;
    uint32_t mask=0;
    uint32_t flags=0;
    uint32_t restorer=0;
};
struct GuestAlarm {
    bool armed=false;
    std::chrono::steady_clock::time_point deadline{};
    uint32_t jump_buffer=0;
};
std::mutex g_jump_mutex;
std::unordered_map<uint32_t,GuestJumpContext> g_jump_contexts;
std::mutex g_signal_mutex;
GuestSignalAction g_sigalrm_action;
thread_local GuestAlarm t_alarm;
thread_local uint32_t t_guest_signal_mask=0;
constexpr uint32_t kGuestJumpCookie = 0x4a4d5000;
constexpr uint32_t kGuestJumpMagic = 0x4a4d5032;
constexpr uint32_t kGuestSigjmpStoredBytes = 128;
constexpr uint32_t kGuestSigjmpMagicOffset = 124;
constexpr uint32_t kSigalrmMask = 1u << (SIGALRM - 1);

std::shared_ptr<Thread> GetThread(uint32_t id){
    std::lock_guard lock(g_threads_mutex);
    auto it=g_threads.find(id);return it==g_threads.end()?nullptr:it->second;
}
void ForgetThread(const std::shared_ptr<Thread>& thread){
    std::lock_guard lock(g_threads_mutex);
    auto it=g_threads.find(thread->id);
    if(it!=g_threads.end() && it->second==thread)g_threads.erase(it);
}
std::shared_ptr<Thread> NewThread(){
    std::lock_guard lock(g_threads_mutex);
    if(!g_next_thread)return {};
    auto thread=std::make_shared<Thread>();thread->id=g_next_thread++;
    g_threads.emplace(thread->id,thread);return thread;
}
uint32_t Self(){
    auto& current=t_thread; // Initialize before the cleanup destructor is registered.
    struct Cleanup {~Cleanup(){if(t_thread&&t_thread->external)ForgetThread(t_thread);}};
    static thread_local Cleanup cleanup;
    (void)current;(void)cleanup;
    if(!t_thread){
        t_thread=NewThread();if(!t_thread)Invalid("guest thread identifiers exhausted");
        t_thread->native=pthread_self();t_thread->external=true;t_thread->detached=true;
    }
    return t_thread->id;
}
void RunTlsDestructors(Host& host){
    for(unsigned pass=0;pass<4;++pass){
        std::vector<std::pair<uint32_t,uint32_t>> pending;
        {
            std::lock_guard lock(g_keys_mutex);
            for(auto& [key,value]:t_keys){
                auto it=g_keys.find(key);
                if(value && it!=g_keys.end() && it->second.destructor){
                    pending.emplace_back(it->second.destructor,value);value=0;
                }
            }
        }
        if(pending.empty())break;
        for(auto [fn,value]:pending)host.RunFunction(fn,{value});
    }
    t_keys.clear();
}

void WriteGuestSignalAction(Host& host,uint32_t address,const GuestSignalAction& action){
    if(!address)return;
    host.MemoryWrite32(address,action.handler);
    host.MemoryWrite32(address+4,action.mask);
    host.MemoryWrite32(address+8,action.flags);
    host.MemoryWrite32(address+12,action.restorer);
}
GuestSignalAction ReadGuestSignalAction(Host& host,uint32_t address){
    Span(host,address,16);
    return {host.MemoryRead32(address),host.MemoryRead32(address+4),
            host.MemoryRead32(address+8),host.MemoryRead32(address+12)};
}

bool SaveGuestJump(Jit& j, Host& h, uint32_t buffer, bool saves_signal_mask) {
    if((buffer&3)||!GuestRangeValid(h.GetGuestMemorySize(),buffer,kGuestSigjmpStoredBytes)){
        LOGE("invalid guest jmp_buf 0x%08x",buffer);
        h.Fail("invalid ARM32 jmp_buf");
        return false;
    }
    GuestJumpContext context;
    context.owner=std::this_thread::get_id();context.jit=&j;
    context.fpscr=j.Fpscr();context.sp=j.Regs()[13];context.lr=j.Regs()[14];
    context.cpsr=j.Cpsr();context.signal_mask=t_guest_signal_mask;
    context.saves_signal_mask=saves_signal_mask;
    h.MemoryWrite32(buffer,kGuestJumpCookie|(saves_signal_mask?1u:0u));
    h.MemoryWrite32(buffer+4,saves_signal_mask?t_guest_signal_mask:0);
    for(unsigned i=0;i<context.ext_regs.size();++i){
        context.ext_regs[i]=j.ExtRegs()[16+i];h.MemoryWrite32(buffer+16+i*4,context.ext_regs[i]);
    }
    h.MemoryWrite32(buffer+80,context.fpscr);
    for(unsigned i=0;i<context.callee_saved.size();++i){
        context.callee_saved[i]=j.Regs()[4+i];h.MemoryWrite32(buffer+84+i*4,context.callee_saved[i]);
    }
    h.MemoryWrite32(buffer+116,context.lr);h.MemoryWrite32(buffer+120,context.sp);
    h.MemoryWrite32(buffer+kGuestSigjmpMagicOffset,kGuestJumpMagic);
    {std::lock_guard lock(g_jump_mutex);g_jump_contexts[buffer]=context;}
    if(t_alarm.armed)t_alarm.jump_buffer=buffer;
    j.Regs()[0]=0;
    return true;
}

bool RestoreGuestJump(Jit& j, Host& h, uint32_t buffer, uint32_t value) {
    GuestJumpContext context{};
    {std::lock_guard lock(g_jump_mutex);
        auto found=g_jump_contexts.find(buffer);
        if(found==g_jump_contexts.end()){h.Fail("unknown ARM32 jmp_buf");return false;}
        context=found->second;
    }
    const uint32_t cookie=buffer&&GuestRangeValid(h.GetGuestMemorySize(),buffer,kGuestSigjmpStoredBytes)?h.MemoryRead32(buffer):0;
    if((buffer&3)||cookie==0||((cookie&~1u)!=kGuestJumpCookie)||
       h.MemoryRead32(buffer+kGuestSigjmpMagicOffset)!=kGuestJumpMagic||
       context.owner!=std::this_thread::get_id()||context.jit!=&j||
       bool(cookie&1)!=context.saves_signal_mask){
        LOGE("invalid or cross-context guest longjmp 0x%08x",buffer);
        h.Fail("unsupported ARM32 jmp_buf restore context");
        return false;
    }
    for(unsigned i=0;i<context.ext_regs.size();++i)j.ExtRegs()[16+i]=h.MemoryRead32(buffer+16+i*4);
    j.SetFpscr(h.MemoryRead32(buffer+80));
    for(unsigned i=0;i<context.callee_saved.size();++i)j.Regs()[4+i]=h.MemoryRead32(buffer+84+i*4);
    const uint32_t lr=h.MemoryRead32(buffer+116);
    j.Regs()[13]=h.MemoryRead32(buffer+120);j.Regs()[14]=lr;
    j.SetCpsr((context.cpsr&~0x20u)|(lr&1?0x20u:0));
    if(context.saves_signal_mask)t_guest_signal_mask=h.MemoryRead32(buffer+4);
    t_alarm.jump_buffer=0;t_alarm.armed=false;
    j.Regs()[0]=value?value:1;j.Regs()[15]=lr&~1u;
    LOGI("guest longjmp restored ARM32 state buffer=0x%08x",buffer);
    return true;
}

// Deliver only the guest's observed SIGALRM path.  The jump target and buffer
// must belong to this thread and this JIT; no host signal or cross-thread entry.
bool GuestSignalPollImpl(Host& host,Jit& jit){
    if(!t_alarm.armed || std::chrono::steady_clock::now()<t_alarm.deadline)return false;
    GuestSignalAction action;
    {
        std::lock_guard lock(g_signal_mutex);
        action=g_sigalrm_action;
    }
    GuestJumpContext context;
    {
        std::lock_guard lock(g_jump_mutex);
        auto found=g_jump_contexts.find(t_alarm.jump_buffer);
        if(found==g_jump_contexts.end()){
            LOGE("SIGALRM expired without a guest sigjmp_buf");
            host.Fail("guest SIGALRM has no same-thread jump context");
            return false;
        }
        context=found->second;
    }
    if(!action.handler || !host.IsExecutableAddress(action.handler) ||
       context.owner!=std::this_thread::get_id() || context.jit!=&jit){
        LOGE("invalid guest SIGALRM delivery handler=0x%08x buffer=0x%08x",action.handler,t_alarm.jump_buffer);
        host.Fail("unsupported guest SIGALRM delivery context");
        return false;
    }
    t_alarm.armed=false;
    t_guest_signal_mask|=kSigalrmMask|action.mask;
    jit.Regs()[0]=SIGALRM;
    jit.Regs()[15]=action.handler&~1u;
    jit.SetCpsr((jit.Cpsr()&~0x20u)|(action.handler&1?0x20u:0));
    LOGI("guest SIGALRM delivered: handler=0x%08x buffer=0x%08x",action.handler,t_alarm.jump_buffer);
    return true;
}

struct ThreadStart {Host* host;uint32_t function,arg;std::shared_ptr<Thread> thread;};
void* ThreadEntry(void* opaque){
    std::unique_ptr<ThreadStart> start(static_cast<ThreadStart*>(opaque));
    auto thread=start->thread;t_thread=thread;
    {std::lock_guard lock(thread->mutex);thread->native=pthread_self();}
    uint32_t result=start->host->RunFunction(start->function,{start->arg});
    start->host->BeginThreadCleanup();
    RunTlsDestructors(*start->host);
    FakeJniEnv::Instance().ReleaseCurrentThread();
    start->host->ReleaseCurrentThread();
    bool detached;
    {std::lock_guard lock(thread->mutex);thread->retval=result;thread->finished=true;detached=thread->detached;}
    if(detached)ForgetThread(thread);
    t_thread.reset();
    return reinterpret_cast<void*>(static_cast<uintptr_t>(result));
}
int CreateThread(Host& host,uint32_t output,uint32_t attr_ptr,uint32_t function,uint32_t arg){
    if(!output || !function)return EINVAL;
    Span(host,output,4);
    Attr32 guest{0,0,1024*1024,4096,SCHED_OTHER,0};
    if(attr_ptr)memcpy(&guest,Span(host,attr_ptr,sizeof(guest)),sizeof(guest));
    // ponytail: host stacks reserve 1 MiB per guest thread; support sized arenas before accepting another size.
    if(guest.base || guest.size!=1024*1024 || (guest.flags&~1u))return ENOTSUP;
    auto thread=NewThread();if(!thread)return EAGAIN;
    thread->detached=(guest.flags&1)!=0;
    auto start=std::make_unique<ThreadStart>(ThreadStart{&host,function,arg,thread});
    pthread_attr_t attr;
    int rc=pthread_attr_init(&attr);
    if(rc){ForgetThread(thread);return rc;}
    rc=pthread_attr_setstacksize(&attr,8*1024*1024);
    if(!rc)rc=pthread_attr_setdetachstate(&attr,thread->detached?PTHREAD_CREATE_DETACHED:PTHREAD_CREATE_JOINABLE);
    if(!rc)rc=pthread_attr_setschedpolicy(&attr,guest.policy);
    sched_param schedule{};schedule.sched_priority=guest.priority;
    if(!rc)rc=pthread_attr_setschedparam(&attr,&schedule);
    pthread_t native{};
    if(!rc)rc=pthread_create(&native,&attr,ThreadEntry,start.get());
    pthread_attr_destroy(&attr);
    if(rc){ForgetThread(thread);return rc;}
    start.release();
    {std::lock_guard lock(thread->mutex);thread->native=native;}
    host.MemoryWrite32(output,thread->id);
    return 0;
}
int JoinThread(Host& host,uint32_t id,uint32_t output){
    auto thread=GetThread(id);if(!thread)return ESRCH;
    if(id==Self())return EDEADLK;
    if(output)Span(host,output,4);
    pthread_t native;
    {std::lock_guard lock(thread->mutex);
        if(thread->detached || thread->external || thread->joining)return EINVAL;
        thread->joining=true;native=thread->native;
    }
    void* result=nullptr;int rc=pthread_join(native,&result);
    if(rc){std::lock_guard lock(thread->mutex);thread->joining=false;return rc;}
    if(output)host.MemoryWrite32(output,static_cast<uint32_t>(reinterpret_cast<uintptr_t>(result)));
    ForgetThread(thread);return 0;
}
int DetachThread(uint32_t id){
    auto thread=GetThread(id);if(!thread)return ESRCH;
    bool finished;
    {std::lock_guard lock(thread->mutex);
        if(thread->detached || thread->external || thread->joining)return EINVAL;
        int rc=pthread_detach(thread->native);if(rc)return rc;
        thread->detached=true;finished=thread->finished;
    }
    if(finished)ForgetThread(thread);return 0;
}

struct AtExit {uint32_t function,arg,dso;};
std::mutex g_atexit_mutex;
std::vector<AtExit> g_atexit;
void Finalize(Host& host,uint32_t dso){
    for(;;){
        AtExit entry{};
        {
            std::lock_guard lock(g_atexit_mutex);
            for(auto it=g_atexit.rbegin();it!=g_atexit.rend();++it){
                if(!dso || it->dso==dso){entry=*it;g_atexit.erase(std::next(it).base());break;}
            }
        }
        if(!entry.function)break;
        host.RunFunction(entry.function,{entry.arg});
        if(host.HasFailed()||host.IsCurrentGuestThreadExiting())return;
    }
}

class VarArgs {
    Jit& jit;
    Host& host;
    uint32_t word;
    uint64_t cursor;
    bool memory;
public:
    VarArgs(Jit& j,Host& h,uint32_t first,bool list=false):jit(j),host(h),word(first),cursor(first),memory(list){}
    uint32_t U32(){
        if(memory){if(cursor>UINT32_MAX)Invalid("va_list overflow");Span(host,static_cast<uint32_t>(cursor),4);
            uint32_t v=host.MemoryRead32(static_cast<uint32_t>(cursor));cursor+=4;return v;}
        if(word<4)return jit.Regs()[word++];
        return host.ReadStackWord(jit,word++-4);
    }
    uint64_t U64(){if(memory)cursor=(cursor+7)&~uint64_t(7);else word=(word+1)&~1u;
        uint64_t lo=U32();return lo|(uint64_t(U32())<<32);}
    double F64(){uint64_t raw=U64();double value;memcpy(&value,&raw,8);return value;}
};
template<class T> std::string PrintValue(const std::string& fmt,T value){
    int n=snprintf(nullptr,0,fmt.c_str(),value);
    if(n<0||n>1024*1024)Invalid("printf conversion exceeds bound");
    std::string text(static_cast<size_t>(n)+1,'\0');snprintf(text.data(),text.size(),fmt.c_str(),value);text.resize(n);return text;
}
void StoreCount(Host& host,uint32_t p,int64_t value,const std::string& length){
    if(length=="hh"){auto v=static_cast<int8_t>(value);memcpy(Span(host,p,1),&v,1);}
    else if(length=="h"){auto v=static_cast<int16_t>(value);memcpy(Span(host,p,2),&v,2);}
    else if(length=="ll"||length=="j"){memcpy(Span(host,p,8),&value,8);}
    else{auto v=static_cast<int32_t>(value);memcpy(Span(host,p,4),&v,4);}
}
std::string Format(Host& host,const char* fmt,VarArgs& args){
    if(!fmt)Invalid("null printf format");
    std::string result;
    for(const char* p=fmt;*p;){
        if(*p!='%'){if(result.size()>=1024*1024)Invalid("printf result exceeds bound");result+=*p++;continue;}++p;
        if(*p=='%'){result+='%';++p;continue;}
        std::string spec="%";
        while(*p&&strchr("-+ #0",*p))spec+=*p++;
        auto digits=[&]{unsigned value=0;while(isdigit(static_cast<unsigned char>(*p))){
            value=value*10+(*p-'0');if(value>1024*1024)Invalid("printf field width exceeds bound");spec+=*p++;}};
        if(*p=='*'){int32_t width=args.U32();++p;if(int64_t(width)>1024*1024||int64_t(width)<-1024*1024)Invalid("printf width exceeds bound");spec+=std::to_string(width);}
        else digits();
        if(*p=='.'){
            ++p;
            if(*p=='*'){int32_t precision=args.U32();++p;if(precision>1024*1024)Invalid("printf precision exceeds bound");if(precision>=0)spec+='.'+std::to_string(precision);}
            else {spec+='.';digits();}
        }
        std::string length;
        if(*p=='h'||*p=='l'){length+=*p++;if(*p==length[0])length+=*p++;}
        else if(*p&&strchr("jztL",*p))length+=*p++;
        char c=*p;if(!c)Invalid("incomplete printf format");++p;
        spec+=length;spec+=c;
        if(c=='n'){StoreCount(host,args.U32(),result.size(),length);continue;}
        if(c=='s'){
            if(!length.empty())Invalid("wide printf strings not supported");
            const char* s=String(host,args.U32());result+=PrintValue(spec,s?s:"(null)");
        }else if(c=='c'){
            if(!length.empty())Invalid("wide printf characters not supported");result+=PrintValue(spec,static_cast<int>(args.U32()));
        }else if(c=='p'){
            if(!length.empty())Invalid("printf pointer length");result+=PrintValue(spec,reinterpret_cast<void*>(static_cast<uintptr_t>(args.U32())));
        }else if(strchr("di",c)){
            int64_t v=(length=="ll"||length=="j")?static_cast<int64_t>(args.U64()):static_cast<int32_t>(args.U32());
            if(length=="ll")result+=PrintValue(spec,static_cast<long long>(v));
            else if(length=="j")result+=PrintValue(spec,static_cast<intmax_t>(v));
            else if(length=="l"||length=="z"||length=="t")result+=PrintValue(spec,static_cast<long>(v));
            else result+=PrintValue(spec,static_cast<int>(v));
        }else if(strchr("uoxX",c)){
            uint64_t v=(length=="ll"||length=="j")?args.U64():args.U32();
            if(length=="ll")result+=PrintValue(spec,static_cast<unsigned long long>(v));
            else if(length=="j")result+=PrintValue(spec,static_cast<uintmax_t>(v));
            else if(length=="l"||length=="z"||length=="t")result+=PrintValue(spec,static_cast<unsigned long>(v));
            else result+=PrintValue(spec,static_cast<unsigned>(v));
        }else if(strchr("aAeEfFgG",c)){
            double v=args.F64();result+=length=="L"?PrintValue(spec,static_cast<long double>(v)):PrintValue(spec,v);
        }else Invalid("unsupported printf conversion");
        if(result.size()>1024*1024)Invalid("printf result exceeds bound");
    }
    return result;
}
void PrintToBuffer(Jit& j,Host& h,bool bounded,bool list){
    uint32_t p=j.Regs()[0],size=bounded?j.Regs()[1]:UINT32_MAX;
    const char* fmt=String(h,j.Regs()[bounded?2:1]);
    VarArgs args(j,h,list?j.Regs()[bounded?3:2]:(bounded?3:2),list);
    std::string text=Format(h,fmt,args);
    size_t n=bounded?(size?std::min<size_t>(text.size(),size-1):0):text.size();
    if(!bounded||size){char* out=static_cast<char*>(Span(h,p,n+1));memcpy(out,text.data(),n);out[n]=0;}
    j.Regs()[0]=text.size();
}

// Each scanf conversion is parsed by the host, but values are stored using guest widths.
int Scan(Host& h,const char* input,const char* format,VarArgs& args){
    const char* start=input;int assigned=0;
    while(*format){
        if(isspace(static_cast<unsigned char>(*format))){
            while(isspace(static_cast<unsigned char>(*format)))++format;
            while(isspace(static_cast<unsigned char>(*input)))++input;continue;
        }
        if(*format!='%'){if(*input!=*format)return assigned?assigned:(*input?0:EOF);++input;++format;continue;}
        ++format;if(*format=='%'){if(*input!='%')return assigned?assigned:(*input?0:EOF);++input;++format;continue;}
        bool suppress=*format=='*';if(suppress)++format;
        std::string width;while(isdigit(static_cast<unsigned char>(*format)))width+=*format++;
        std::string length;
        if(*format=='h'||*format=='l'){length+=*format++;if(*format==length[0])length+=*format++;}
        else if(*format&&strchr("jztL",*format))length+=*format++;
        char conversion=*format;if(!conversion)Invalid("incomplete scanf format");++format;
        if(conversion=='n'){if(!suppress)StoreCount(h,args.U32(),input-start,length);continue;}
        std::string suffix(1,conversion);
        if(conversion=='['){if(*format=='^')suffix+=*format++;if(*format==']')suffix+=*format++;
            while(*format&&*format!=']')suffix+=*format++;if(!*format)Invalid("unterminated scanf scanset");suffix+=*format++;}
        uint32_t destination=suppress?0:args.U32();int consumed=-1;
        if(suppress){std::string spec="%*"+width+length+suffix+"%n";sscanf(input,spec.c_str(),&consumed);}
        else if(conversion=='s'||conversion=='c'||conversion=='['){
            if(!length.empty())Invalid("wide scanf strings not supported");
            size_t limit=conversion=='c'?1:strlen(input);
            if(!width.empty()){char* end=nullptr;unsigned long long n=strtoull(width.c_str(),&end,10);
                if(!n||n>1024*1024||*end)Invalid("scanf width exceeds bound");limit=static_cast<size_t>(n);}
            std::vector<char> temporary(limit+1);
            std::string spec="%"+std::to_string(limit)+suffix+"%n";
            sscanf(input,spec.c_str(),temporary.data(),&consumed);
            if(consumed>=0){size_t n=conversion=='c'?std::min<size_t>(limit,consumed):strlen(temporary.data())+1;
                memcpy(Span(h,destination,n),temporary.data(),n);}
        }else if(strchr("di",conversion)){
            long long value=0;std::string spec="%"+width+"ll"+suffix+"%n";
            sscanf(input,spec.c_str(),&value,&consumed);if(consumed>=0)StoreCount(h,destination,value,length);
        }else if(strchr("uoxX",conversion)){
            unsigned long long value=0;std::string spec="%"+width+"ll"+suffix+"%n";
            sscanf(input,spec.c_str(),&value,&consumed);if(consumed>=0)StoreCount(h,destination,static_cast<int64_t>(value),length);
        }else if(strchr("aAeEfFgG",conversion)){
            double value=0;std::string spec="%"+width+"l"+suffix+"%n";
            sscanf(input,spec.c_str(),&value,&consumed);
            if(consumed>=0){if(length=="l"||length=="L")memcpy(Span(h,destination,8),&value,8);
                else{float f=static_cast<float>(value);memcpy(Span(h,destination,4),&f,4);}}
        }else if(conversion=='p'){
            void* value=nullptr;std::string spec="%"+width+"p%n";sscanf(input,spec.c_str(),&value,&consumed);
            if(consumed>=0)StoreCount(h,destination,reinterpret_cast<uintptr_t>(value),"");
        }else Invalid("unsupported scanf conversion");
        if(consumed<0){const char* remaining=input;if(conversion!='c'&&conversion!='[')while(isspace(static_cast<unsigned char>(*remaining)))++remaining;return assigned?assigned:(*remaining?0:EOF);}
        input+=consumed;if(!suppress)++assigned;
    }
    return assigned;
}

void SelfCheck(){
    Mutex recursive(PTHREAD_MUTEX_RECURSIVE),checked(PTHREAD_MUTEX_ERRORCHECK);
    if(pthread_mutex_lock(&recursive.value)||pthread_mutex_lock(&recursive.value)||
       pthread_mutex_unlock(&recursive.value)||pthread_mutex_unlock(&recursive.value))Invalid("recursive mutex self-check");
    if(pthread_mutex_lock(&checked.value)||pthread_mutex_lock(&checked.value)!=EDEADLK||
       pthread_mutex_destroy(&checked.value)!=EBUSY||pthread_mutex_unlock(&checked.value))Invalid("error-check/locked-destroy mutex self-check");
    Semaphore sem(0);
    if(sem_trywait(&sem.value)!=-1 || errno!=EAGAIN || sem_post(&sem.value)||sem_wait(&sem.value))Invalid("semaphore self-check");
    Once once;unsigned calls=0;once.Run([&]{++calls;return true;});once.Run([&]{++calls;return true;});
    if(calls!=1)Invalid("once self-check");
    Condition legacy(CLOCK_MONOTONIC);
    std::atomic<bool> legacy_woke=false;
    std::thread legacy_waiter([&]{legacy.WaitWithoutMutex();legacy_woke=true;});
    auto limit=std::chrono::steady_clock::now()+std::chrono::seconds(1);
    while(!legacy.LegacyWaiters()){
        if(std::chrono::steady_clock::now()>=limit)Invalid("legacy condition registration self-check");
        std::this_thread::yield();
    }
    if(legacy.Signal())Invalid("legacy condition signal self-check");
    legacy_waiter.join();
    if(!legacy_woke.load() || legacy.LegacyWaiters())Invalid("legacy condition wake self-check");
    LOGI("LibcSelfCheck OK: Bionic layouts, mutex types, condition modes, semaphore, once");
}
} // namespace

bool GuestSignalPoll(DynarmicHost& host,Dynarmic::A32::Jit& jit){
    return GuestSignalPollImpl(host,jit);
}

void GuestSyncForget(uint32_t addr,uint32_t size){
    const uint64_t end=uint64_t(addr)+size;
    std::lock_guard lock(g_sync_mutex);
    auto forget=[&](auto& table){
        for(auto it=table.begin();it!=table.end();){
            if(it->first>=addr && it->first<end){
                if(it->second.use_count()!=1)Invalid("free of synchronization object in use");
                it=table.erase(it);
            }else ++it;
        }
    };
    forget(g_mutexes);forget(g_conditions);forget(g_semaphores);forget(g_once);
}

void GuestLibcThreadExit(DynarmicHost& host){
    RunTlsDestructors(host);
    for(auto& [_,entry]:t_cache.strings)host.GuestFree(entry.first);
    host.GuestFree(t_cache.tm);host.GuestFree(t_cache.passwd);host.GuestFree(t_cache.hostent);t_cache={};
    auto tls=t_kuser_tls.find(&host);if(tls!=t_kuser_tls.end()){host.GuestFree(tls->second);t_kuser_tls.erase(tls);}
    if(t_thread && t_thread->external){ForgetThread(t_thread);t_thread.reset();}
}

void ThunkManager::RegisterLibcThunks(){
    m_host.MemoryWrite32(0x100,0x7bd48a31);
    RegisterSymbol("__stack_chk_guard",0x100);
    RegisterSymbol("__sF",0x200);
    memset(Span(m_host,0x200,3*84),0,3*84);
    for(unsigned i=0;i<3;++i){
        uint32_t p=0x200+i*84;
        m_host.MemoryWrite16(p+12,i==0?4:(i==1?8:10));
        m_host.MemoryWrite16(p+14,i);
        // Guest standard streams own duplicates; closing one cannot invalidate host FILEs.
        int fd=dup(static_cast<int>(i));if(fd<0)Invalid("host standard descriptor unavailable");
        FILE* stream=fdopen(fd,i==0?"r":"w");if(!stream){close(fd);Invalid("standard stream duplication");}
        if(setvbuf(stream,nullptr,_IONBF,0))Invalid("standard stream buffering");
        g_standard_fds[i]=fd;g_standard_streams[i]=stream;
        std::lock_guard lock(g_handles_mutex);
        g_files.emplace(p,std::make_shared<File>(stream));
    }
    // The Imm consumers load a pointer global, then table[unsigned_byte + 1].
    uint32_t ctype=m_host.GuestAlloc(257,4),lower=m_host.GuestAlloc(257*2,4),upper=m_host.GuestAlloc(257*2,4);
    uint32_t ctype_pointer=m_host.GuestAlloc(4,4),lower_pointer=m_host.GuestAlloc(4,4),upper_pointer=m_host.GuestAlloc(4,4);
    if(!ctype||!lower||!upper||!ctype_pointer||!lower_pointer||!upper_pointer)Invalid("ctype data allocation");
    m_host.MemoryWrite8(ctype,0);m_host.MemoryWrite16(lower,0xffff);m_host.MemoryWrite16(upper,0xffff);
    for(unsigned c=0;c<256;++c){
        m_host.MemoryWrite8(ctype+c+1,CtypeByte(c));
        m_host.MemoryWrite16(lower+2*(c+1),(c>='A'&&c<='Z')?c+('a'-'A'):c);
        m_host.MemoryWrite16(upper+2*(c+1),(c>='a'&&c<='z')?c-('a'-'A'):c);
    }
    m_host.MemoryWrite32(ctype_pointer,ctype);m_host.MemoryWrite32(lower_pointer,lower);m_host.MemoryWrite32(upper_pointer,upper);
    RegisterSymbol("_ctype_",ctype_pointer);
    RegisterSymbol("_tolower_tab_",lower_pointer);
    RegisterSymbol("_toupper_tab_",upper_pointer);
    RegisterThunk("__errno",[](Jit& j,Host& h){j.Regs()[0]=h.GuestErrnoAddress();});
    RegisterThunk("__kuser_memory_barrier",[](Jit&,Host&){
        std::atomic_thread_fence(std::memory_order_seq_cst);
    });
    RegisterThunk("__kuser_cmpxchg",[](Jit& j,Host& h){
        const uint32_t address=j.Regs()[2];
        if((address&3)||!GuestRangeValid(h.GetGuestMemorySize(),address,sizeof(uint32_t))){
            const uint32_t pc=h.IsJitRunning()?h.CurrentJit().Regs()[15]:0;
            const uint32_t lr=h.IsJitRunning()?h.CurrentJit().Regs()[14]:0;
            LOGE("invalid __kuser_cmpxchg address=0x%08x expected=0x%08x desired=0x%08x pc=0x%08x lr=0x%08x",
                 address,j.Regs()[0],j.Regs()[1],pc,lr);
            // The original helper reports a failed comparison to callers
            // that race with teardown.  Do not poison the whole bridge for a
            // stale/null guest lock: letting the caller retry is recoverable,
            // while h.Fail() makes the next Activity resume crash outright.
            j.Regs()[0]=1;
            return;
        }
        uint32_t expected=j.Regs()[0];
        const uint32_t desired=j.Regs()[1];
        const bool exchanged=__atomic_compare_exchange_n(
            reinterpret_cast<uint32_t*>(h.GetGuestMemoryBase()+address),&expected,desired,false,
            __ATOMIC_SEQ_CST,__ATOMIC_SEQ_CST);
        j.Regs()[0]=exchanged?0:1;
    });
    RegisterThunk("__kuser_cmpxchg64",[](Jit& j,Host& h){
        const uint32_t old_address=j.Regs()[0],new_address=j.Regs()[1],target=j.Regs()[2];
        if((old_address&7)||(new_address&7)||(target&7)||
           !GuestRangeValid(h.GetGuestMemorySize(),old_address,sizeof(uint64_t))||
           !GuestRangeValid(h.GetGuestMemorySize(),new_address,sizeof(uint64_t))||
           !GuestRangeValid(h.GetGuestMemorySize(),target,sizeof(uint64_t))){
            h.Fail("invalid __kuser_cmpxchg64 address");return;
        }
        uint64_t expected=0,desired=0;
        memcpy(&expected,h.GetGuestMemoryBase()+old_address,sizeof(expected));
        memcpy(&desired,h.GetGuestMemoryBase()+new_address,sizeof(desired));
        const bool exchanged=__atomic_compare_exchange_n(
            reinterpret_cast<uint64_t*>(h.GetGuestMemoryBase()+target),&expected,desired,false,
            __ATOMIC_SEQ_CST,__ATOMIC_SEQ_CST);
        j.Regs()[0]=exchanged?0:1;
    });
    RegisterThunk("__kuser_get_tls",[](Jit& j,Host& h){j.Regs()[0]=KuserTlsAddress(h);});

    RegisterThunk("pthread_create",[](Jit& j,Host& h){j.Regs()[0]=CreateThread(h,j.Regs()[0],j.Regs()[1],j.Regs()[2],j.Regs()[3]);});
    RegisterThunk("pthread_self",[](Jit& j,Host&){j.Regs()[0]=Self();});
    RegisterThunk("pthread_join",[](Jit& j,Host& h){j.Regs()[0]=JoinThread(h,j.Regs()[0],j.Regs()[1]);});
    RegisterThunk("pthread_detach",[](Jit& j,Host&){j.Regs()[0]=DetachThread(j.Regs()[0]);});
    RegisterThunk("pthread_exit",[](Jit& j,Host& h){h.ExitCurrentGuestThread(j.Regs()[0]);});
    RegisterThunk("pthread_attr_init",[](Jit& j,Host& h){
        Attr32 a{0,0,1024*1024,4096,SCHED_OTHER,0};memcpy(Span(h,j.Regs()[0],sizeof(a)),&a,sizeof(a));j.Regs()[0]=0;
    });
    RegisterThunk("pthread_attr_destroy",[](Jit& j,Host& h){Span(h,j.Regs()[0],sizeof(Attr32));j.Regs()[0]=0;});
    RegisterThunk("pthread_attr_getstacksize",[](Jit& j,Host& h){
        auto* a=static_cast<const Attr32*>(Span(h,j.Regs()[0],sizeof(Attr32)));
        Span(h,j.Regs()[1],4);h.MemoryWrite32(j.Regs()[1],a->size);j.Regs()[0]=0;
    });
    RegisterThunk("pthread_attr_getschedparam",[](Jit& j,Host& h){
        auto* a=static_cast<const Attr32*>(Span(h,j.Regs()[0],sizeof(Attr32)));
        Span(h,j.Regs()[1],4);h.MemoryWrite32(j.Regs()[1],a->priority);j.Regs()[0]=0;
    });
    RegisterThunk("pthread_attr_setschedparam",[](Jit& j,Host& h){
        auto* a=static_cast<Attr32*>(Span(h,j.Regs()[0],sizeof(Attr32)));
        Span(h,j.Regs()[1],4);int priority=static_cast<int32_t>(h.MemoryRead32(j.Regs()[1]));
        if(priority<sched_get_priority_min(a->policy)||priority>sched_get_priority_max(a->policy)){j.Regs()[0]=EINVAL;return;}
        a->priority=priority;j.Regs()[0]=0;
    });
    RegisterThunk("pthread_setschedparam",[](Jit& j,Host& h){
        auto t=GetThread(j.Regs()[0]);if(!t){j.Regs()[0]=ESRCH;return;}
        Span(h,j.Regs()[2],4);sched_param p{};p.sched_priority=static_cast<int32_t>(h.MemoryRead32(j.Regs()[2]));
        pthread_t native;{std::lock_guard lock(t->mutex);native=t->native;}
        j.Regs()[0]=pthread_setschedparam(native,static_cast<int>(j.Regs()[1]),&p);
    });
    RegisterThunk("pthread_setname_np",[](Jit& j,Host& h){
        auto t=GetThread(j.Regs()[0]);if(!t){j.Regs()[0]=ESRCH;return;}
        const char* name=String(h,j.Regs()[1]);if(!name){j.Regs()[0]=EINVAL;return;}
        pthread_t native;{std::lock_guard lock(t->mutex);native=t->native;}
        j.Regs()[0]=pthread_setname_np(native,name);
    });
    RegisterThunk("pthread_mutexattr_init",[](Jit& j,Host& h){Span(h,j.Regs()[0],4);h.MemoryWrite32(j.Regs()[0],0);j.Regs()[0]=0;});
    RegisterThunk("pthread_mutexattr_destroy",[](Jit& j,Host& h){Span(h,j.Regs()[0],4);j.Regs()[0]=0;});
    RegisterThunk("pthread_mutexattr_settype",[](Jit& j,Host& h){
        Span(h,j.Regs()[0],4);if(j.Regs()[1]>2){j.Regs()[0]=EINVAL;return;}
        h.MemoryWrite32(j.Regs()[0],j.Regs()[1]);j.Regs()[0]=0;
    });
    RegisterThunk("pthread_mutex_init",[](Jit& j,Host& h){
        uint32_t p=j.Regs()[0];Span(h,p,4);int type=0;
        if(j.Regs()[1]){Span(h,j.Regs()[1],4);type=h.MemoryRead32(j.Regs()[1]);}
        if(type<0||type>2){j.Regs()[0]=ENOTSUP;return;}
        std::lock_guard lock(g_sync_mutex);
        if(g_mutexes.count(p)){j.Regs()[0]=EBUSY;return;}
        g_mutexes.emplace(p,std::make_shared<Mutex>(type));h.MemoryWrite32(p,type<<14);j.Regs()[0]=0;
    });
    RegisterThunk("pthread_mutex_destroy",[](Jit& j,Host& h){
        uint32_t p=j.Regs()[0];auto value=GetMutex(h,p);if(!value){j.Regs()[0]=errno;return;}
        std::lock_guard lock(g_sync_mutex);
        if(value.use_count()!=2){j.Regs()[0]=EBUSY;return;}
        int rc=pthread_mutex_destroy(&value->value);
        if(!rc){value->live=false;g_mutexes.erase(p);h.MemoryWrite32(p,0xdeadc0de);}
        j.Regs()[0]=rc;
    });
    RegisterThunk("pthread_mutex_lock",[](Jit& j,Host& h){
        auto m=GetMutex(h,j.Regs()[0]);
        j.Regs()[0]=m?pthread_mutex_lock(&m->value):errno;
    });
    RegisterThunk("pthread_mutex_trylock",[](Jit& j,Host& h){auto m=GetMutex(h,j.Regs()[0]);j.Regs()[0]=m?pthread_mutex_trylock(&m->value):errno;});
    RegisterThunk("pthread_mutex_unlock",[](Jit& j,Host& h){auto m=GetMutex(h,j.Regs()[0]);j.Regs()[0]=m?pthread_mutex_unlock(&m->value):errno;});
    RegisterThunk("pthread_cond_init",[](Jit& j,Host& h){
        uint32_t p=j.Regs()[0],word=0;Span(h,p,4);
        if(j.Regs()[1]){Span(h,j.Regs()[1],4);word=h.MemoryRead32(j.Regs()[1]);}
        if(word&~2u){j.Regs()[0]=ENOTSUP;return;}
        std::lock_guard lock(g_sync_mutex);
        if(g_conditions.count(p)){j.Regs()[0]=EBUSY;return;}
        g_conditions.emplace(p,std::make_shared<Condition>((word&2)?CLOCK_MONOTONIC:CLOCK_REALTIME));
        h.MemoryWrite32(p,word);j.Regs()[0]=0;
    });
    RegisterThunk("pthread_cond_destroy",[](Jit& j,Host& h){
        uint32_t p=j.Regs()[0];auto value=GetCondition(h,p);if(!value){j.Regs()[0]=errno;return;}
        std::lock_guard lock(g_sync_mutex);
        if(value.use_count()!=2){j.Regs()[0]=EBUSY;return;}
        int rc=pthread_cond_destroy(&value->value);
        if(!rc){value->live=false;g_conditions.erase(p);h.MemoryWrite32(p,0xdeadc0de);}
        j.Regs()[0]=rc;
    });
    RegisterThunk("pthread_cond_wait",[](Jit& j,Host& h){j.Regs()[0]=WaitCondition(h,j.Regs()[0],j.Regs()[1],0,false);});
    RegisterThunk("pthread_cond_timedwait",[](Jit& j,Host& h){
        if(!j.Regs()[2]){j.Regs()[0]=EINVAL;return;}
        j.Regs()[0]=WaitCondition(h,j.Regs()[0],j.Regs()[1],j.Regs()[2],false);
    });
    RegisterThunk("pthread_cond_timeout_np",[](Jit& j,Host& h){j.Regs()[0]=WaitCondition(h,j.Regs()[0],j.Regs()[1],j.Regs()[2],true);});
    RegisterThunk("pthread_cond_signal",[](Jit& j,Host& h){auto c=GetCondition(h,j.Regs()[0]);j.Regs()[0]=c?c->Signal():errno;});
    RegisterThunk("pthread_cond_broadcast",[](Jit& j,Host& h){auto c=GetCondition(h,j.Regs()[0]);j.Regs()[0]=c?c->Broadcast():errno;});
    RegisterThunk("pthread_once",[](Jit& j,Host& h){
        uint32_t p=j.Regs()[0],fn=j.Regs()[1];Span(h,p,4);
        if(!fn){j.Regs()[0]=EINVAL;return;}
        std::shared_ptr<Once> once;
        {std::lock_guard lock(g_sync_mutex);auto& slot=g_once[p];
            if(!slot){slot=std::make_shared<Once>();uint32_t state=h.MemoryRead32(p);
                if(state!=0&&state!=2)Invalid("unknown pthread_once state");slot->state=state;}
            once=slot;
        }
        once->Run([&]{h.MemoryWrite32(p,1);h.CallGuestNested(fn,{});
            bool complete=!h.IsCurrentGuestThreadExiting();h.MemoryWrite32(p,complete?2:0);return complete;});
        j.Regs()[0]=0;
    });
    RegisterThunk("pthread_key_create",[](Jit& j,Host& h){
        Span(h,j.Regs()[0],4);std::lock_guard lock(g_keys_mutex);
        if(g_keys.size()>=128||!g_next_key){j.Regs()[0]=EAGAIN;return;}
        uint32_t key=g_next_key++;g_keys.emplace(key,Key{j.Regs()[1]});h.MemoryWrite32(j.Regs()[0],key);j.Regs()[0]=0;
    });
    RegisterThunk("pthread_key_delete",[](Jit& j,Host&){
        uint32_t key=j.Regs()[0];std::lock_guard lock(g_keys_mutex);
        if(!g_keys.erase(key)){j.Regs()[0]=EINVAL;return;}t_keys.erase(key);j.Regs()[0]=0;
    });
    RegisterThunk("pthread_setspecific",[](Jit& j,Host&){
        std::lock_guard lock(g_keys_mutex);
        if(!g_keys.count(j.Regs()[0])){j.Regs()[0]=EINVAL;return;}
        for(auto it=t_keys.begin();it!=t_keys.end();)if(!g_keys.count(it->first))it=t_keys.erase(it);else ++it;
        t_keys[j.Regs()[0]]=j.Regs()[1];j.Regs()[0]=0;
    });
    RegisterThunk("pthread_getspecific",[](Jit& j,Host&){
        std::lock_guard lock(g_keys_mutex);auto it=t_keys.find(j.Regs()[0]);
        j.Regs()[0]=g_keys.count(j.Regs()[0])&&it!=t_keys.end()?it->second:0;
    });
    RegisterThunk("sem_init",[](Jit& j,Host& h){
        uint32_t p=j.Regs()[0];Span(h,p,4);
        if(j.Regs()[1]){Failure(j,h,ENOTSUP);return;}
        if(j.Regs()[2]>INT_MAX){Failure(j,h,EINVAL);return;}
        std::lock_guard lock(g_sync_mutex);
        if(g_semaphores.count(p)){Failure(j,h,EBUSY);return;}
        g_semaphores.emplace(p,std::make_shared<Semaphore>(j.Regs()[2]));h.MemoryWrite32(p,0);j.Regs()[0]=0;
    });
    RegisterThunk("sem_destroy",[](Jit& j,Host& h){
        uint32_t p=j.Regs()[0];auto sem=GetSemaphore(p);if(!sem){Failure(j,h,EINVAL);return;}
        std::lock_guard lock(g_sync_mutex);
        if(sem.use_count()!=2){Failure(j,h,EBUSY);return;}
        int rc=sem_destroy(&sem->value);if(!rc){sem->live=false;g_semaphores.erase(p);h.MemoryWrite32(p,0xdeadc0de);}Result(j,h,rc);
    });
    RegisterThunk("sem_wait",[](Jit& j,Host& h){auto s=GetSemaphore(j.Regs()[0]);Result(j,h,s?sem_wait(&s->value):-1);});
    RegisterThunk("sem_trywait",[](Jit& j,Host& h){auto s=GetSemaphore(j.Regs()[0]);Result(j,h,s?sem_trywait(&s->value):-1);});
    RegisterThunk("sem_post",[](Jit& j,Host& h){auto s=GetSemaphore(j.Regs()[0]);Result(j,h,s?sem_post(&s->value):-1);});
    RegisterThunk("sem_getvalue",[](Jit& j,Host& h){
        auto s=GetSemaphore(j.Regs()[0]);if(!s){Failure(j,h,EINVAL);return;}
        Span(h,j.Regs()[1],4);int value=0;int rc=sem_getvalue(&s->value,&value);
        if(!rc)h.MemoryWrite32(j.Regs()[1],value);Result(j,h,rc);
    });
    RegisterThunk("malloc",[](Jit& j,Host& h){uint32_t p=h.GuestAlloc(j.Regs()[0],8);if(!p)Errno(h,ENOMEM);j.Regs()[0]=p;});
    RegisterThunk("calloc",[](Jit& j,Host& h){
        uint64_t bytes=uint64_t(j.Regs()[0])*j.Regs()[1];
        if(bytes>UINT32_MAX){Errno(h,ENOMEM);j.Regs()[0]=0;return;}
        uint32_t p=h.GuestAlloc(bytes,8);if(p)memset(Span(h,p,bytes),0,bytes);else Errno(h,ENOMEM);j.Regs()[0]=p;
    });
    RegisterThunk("free",[](Jit& j,Host& h){h.GuestFree(j.Regs()[0]);});
    RegisterThunk("realloc",[](Jit& j,Host& h){
        uint32_t old=j.Regs()[0],size=j.Regs()[1];
        if(!size){h.GuestFree(old);j.Regs()[0]=0;return;}
        uint32_t next=h.GuestAlloc(size,8);
        if(!next){Errno(h,ENOMEM);j.Regs()[0]=0;return;}
        if(old){size_t n=std::min(size,h.GuestAllocSize(old));if(n)memcpy(Span(h,next,n),Span(h,old,n),n);h.GuestFree(old);}
        j.Regs()[0]=next;
    });
    RegisterThunk("memcpy",[](Jit& j,Host& h){
        const uint32_t destination=j.Regs()[0],source=j.Regs()[1];
        const size_t n=j.Regs()[2];
        if(!n){j.Regs()[0]=destination;return;}
        const bool destination_ok=GuestRangeValid(h.GetGuestMemorySize(),destination,n);
        const bool source_ok=GuestRangeValid(h.GetGuestMemorySize(),source,n);
        if(destination_ok&&source_ok){
            ::memcpy(h.GetGuestMemoryBase()+destination,h.GetGuestMemoryBase()+source,n);
            j.Regs()[0]=destination;
            return;
        }
        // A few optional car variants call memcpy with a missing texture
        // payload after the archive lookup fails. Treat only this boundary as
        // recoverable: keep all other libc spans strict, but make the caller
        // receive a valid zero-filled texture instead of aborting the bridge.
        static std::atomic<uint32_t> fallback_count{0};
        const uint32_t ordinal=fallback_count.fetch_add(1,std::memory_order_relaxed);
        if(ordinal<8||(ordinal&&(ordinal&(ordinal-1))==0)){
            const uint32_t pc=h.IsJitRunning()?h.CurrentJit().Regs()[15]:0;
            const uint32_t lr=h.IsJitRunning()?h.CurrentJit().Regs()[14]:0;
            LOGW("memcpy fallback dst=0x%08x src=0x%08x n=%zu dst_ok=%d src_ok=%d pc=0x%08x lr=0x%08x count=%u",
                 destination,source,n,destination_ok,source_ok,pc,lr,ordinal+1);
        }
        if(destination_ok){
            ::memset(h.GetGuestMemoryBase()+destination,0,n);
            j.Regs()[0]=destination;
        }else{
            j.Regs()[0]=0;
        }
    });
    RegisterThunk("memmove",[](Jit& j,Host& h){
        const uint32_t destination=j.Regs()[0],source=j.Regs()[1];
        const size_t n=j.Regs()[2];
        if(!n){j.Regs()[0]=destination;return;}
        const bool destination_ok=GuestRangeValid(h.GetGuestMemorySize(),destination,n);
        const bool source_ok=GuestRangeValid(h.GetGuestMemorySize(),source,n);
        if(destination_ok&&source_ok){
            ::memmove(h.GetGuestMemoryBase()+destination,h.GetGuestMemoryBase()+source,n);
            j.Regs()[0]=destination;
            return;
        }
        // The original game can pass a missing optional payload through
        // memmove after a failed asset lookup. Keep this boundary recoverable
        // just like memcpy: preserve the destination and provide zero data
        // when the destination is usable, instead of aborting the whole race.
        static std::atomic<uint32_t> fallback_count{0};
        const uint32_t ordinal=fallback_count.fetch_add(1,std::memory_order_relaxed);
        if(ordinal<8||(ordinal&&(ordinal&(ordinal-1))==0)){
            const uint32_t pc=h.IsJitRunning()?h.CurrentJit().Regs()[15]:0;
            const uint32_t lr=h.IsJitRunning()?h.CurrentJit().Regs()[14]:0;
            LOGW("memmove fallback dst=0x%08x src=0x%08x n=%zu dst_ok=%d src_ok=%d pc=0x%08x lr=0x%08x count=%u",
                 destination,source,n,destination_ok,source_ok,pc,lr,ordinal+1);
        }
        if(destination_ok){
            ::memset(h.GetGuestMemoryBase()+destination,0,n);
            j.Regs()[0]=destination;
        }else{
            j.Regs()[0]=0;
        }
    });
    RegisterThunk("memset",[](Jit& j,Host& h){size_t n=j.Regs()[2];if(n)memset(Span(h,j.Regs()[0],n),j.Regs()[1],n);});
    RegisterThunk("memcmp",[](Jit& j,Host& h){size_t n=j.Regs()[2];j.Regs()[0]=n?memcmp(Span(h,j.Regs()[0],n),Span(h,j.Regs()[1],n),n):0;});
    RegisterThunk("memchr",[](Jit& j,Host& h){size_t n=j.Regs()[2];void* p=n?memchr(Span(h,j.Regs()[0],n),j.Regs()[1],n):nullptr;j.Regs()[0]=p?Address(h,p):0;});
    RegisterThunk("memrchr",[](Jit& j,Host& h){size_t n=j.Regs()[2];void* p=n?memrchr(Span(h,j.Regs()[0],n),j.Regs()[1],n):nullptr;j.Regs()[0]=p?Address(h,p):0;});
    RegisterThunk("strlen",[](Jit& j,Host& h){const char* s=String(h,j.Regs()[0]);if(!s)Invalid("strlen null");j.Regs()[0]=strlen(s);});
    RegisterThunk("strcmp",[](Jit& j,Host& h){j.Regs()[0]=strcmp(String(h,j.Regs()[0]),String(h,j.Regs()[1]));});
    RegisterThunk("strncmp",[](Jit& j,Host& h){size_t n=j.Regs()[2];j.Regs()[0]=n?strncmp(BoundedString(h,j.Regs()[0],n),BoundedString(h,j.Regs()[1],n),n):0;});
    RegisterThunk("strcasecmp",[](Jit& j,Host& h){j.Regs()[0]=strcasecmp(String(h,j.Regs()[0]),String(h,j.Regs()[1]));});
    RegisterThunk("strncasecmp",[](Jit& j,Host& h){size_t n=j.Regs()[2];j.Regs()[0]=n?strncasecmp(BoundedString(h,j.Regs()[0],n),BoundedString(h,j.Regs()[1],n),n):0;});
    RegisterThunk("strcpy",[](Jit& j,Host& h){const char* s=String(h,j.Regs()[1]);size_t n=strlen(s)+1;memcpy(Span(h,j.Regs()[0],n),s,n);});
    RegisterThunk("strncpy",[](Jit& j,Host& h){size_t n=j.Regs()[2];if(n)strncpy(static_cast<char*>(Span(h,j.Regs()[0],n)),BoundedString(h,j.Regs()[1],n),n);});
    RegisterThunk("strcat",[](Jit& j,Host& h){const char* s=String(h,j.Regs()[1]);size_t n=strlen(String(h,j.Regs()[0]))+strlen(s)+1;strcat(static_cast<char*>(Span(h,j.Regs()[0],n)),s);});
    RegisterThunk("strncat",[](Jit& j,Host& h){size_t limit=j.Regs()[2];if(!limit)return;const char* s=BoundedString(h,j.Regs()[1],limit);size_t n=strlen(String(h,j.Regs()[0]))+strnlen(s,limit)+1;strncat(static_cast<char*>(Span(h,j.Regs()[0],n)),s,limit);});
    RegisterThunk("strlcat",[](Jit& j,Host& h){j.Regs()[0]=strlcat(static_cast<char*>(Span(h,j.Regs()[0],j.Regs()[2])),String(h,j.Regs()[1]),j.Regs()[2]);});
    RegisterThunk("strdup",[](Jit& j,Host& h){uint32_t p=CopyString(h,String(h,j.Regs()[0]));if(!p)Errno(h,ENOMEM);j.Regs()[0]=p;});
    RegisterThunk("strchr",[](Jit& j,Host& h){const char* p=strchr(String(h,j.Regs()[0]),j.Regs()[1]);j.Regs()[0]=p?Address(h,p):0;});
    RegisterThunk("strrchr",[](Jit& j,Host& h){const char* p=strrchr(String(h,j.Regs()[0]),j.Regs()[1]);j.Regs()[0]=p?Address(h,p):0;});
    RegisterThunk("strstr",[](Jit& j,Host& h){const char* p=strstr(String(h,j.Regs()[0]),String(h,j.Regs()[1]));j.Regs()[0]=p?Address(h,p):0;});
    RegisterThunk("strtok_r",[](Jit& j,Host& h){
        uint32_t save=j.Regs()[2];Span(h,save,4);char* next=const_cast<char*>(String(h,h.MemoryRead32(save)));
        char* token=strtok_r(const_cast<char*>(String(h,j.Regs()[0])),String(h,j.Regs()[1]),&next);
        h.MemoryWrite32(save,next?Address(h,next):0);j.Regs()[0]=token?Address(h,token):0;
    });
    RegisterThunk("strtok",[](Jit& j,Host& h){
        char* next=const_cast<char*>(String(h,t_cache.strtok_next));
        char* token=strtok_r(const_cast<char*>(String(h,j.Regs()[0])),String(h,j.Regs()[1]),&next);
        t_cache.strtok_next=next?Address(h,next):0;j.Regs()[0]=token?Address(h,token):0;
    });
    RegisterThunk("atoi",[](Jit& j,Host& h){j.Regs()[0]=atoi(String(h,j.Regs()[0]));});
    RegisterThunk("strtol",[](Jit& j,Host& h){
        uint32_t p=j.Regs()[0],out=j.Regs()[1];char* end=nullptr;errno=0;
        long long value=strtoll(String(h,p),&end,static_cast<int>(j.Regs()[2]));
        if(value>INT32_MAX){value=INT32_MAX;errno=ERANGE;}else if(value<INT32_MIN){value=INT32_MIN;errno=ERANGE;}
        if(out){Span(h,out,4);h.MemoryWrite32(out,Address(h,end));}
        if(errno)Errno(h,errno);j.Regs()[0]=static_cast<uint32_t>(value);
    });
    RegisterThunk("strtoul",[](Jit& j,Host& h){
        uint32_t p=j.Regs()[0],out=j.Regs()[1];const char* s=String(h,p);char* end=nullptr;errno=0;
        uint64_t value=strtoull(s,&end,static_cast<int>(j.Regs()[2]));while(isspace(static_cast<unsigned char>(*s)))++s;
        bool negative=*s=='-';uint64_t magnitude=negative?uint64_t(0)-value:value;
        if(errno==ERANGE||magnitude>UINT32_MAX){value=UINT32_MAX;errno=ERANGE;}
        if(out){Span(h,out,4);h.MemoryWrite32(out,Address(h,end));}
        if(errno)Errno(h,errno);j.Regs()[0]=static_cast<uint32_t>(value);
    });
    RegisterThunk("strtod",[](Jit& j,Host& h){
        uint32_t out=j.Regs()[1];char* end=nullptr;errno=0;double value=strtod(String(h,j.Regs()[0]),&end);
        if(out){Span(h,out,4);h.MemoryWrite32(out,Address(h,end));}
        if(errno)Errno(h,errno);WriteDF(j,0,value);
    });
    RegisterThunk("isspace",[](Jit& j,Host&){int c=static_cast<int32_t>(j.Regs()[0]);j.Regs()[0]=(c>=0&&c<=255)?isspace(c):0;});
    RegisterThunk("toupper",[](Jit& j,Host&){int c=static_cast<int32_t>(j.Regs()[0]);j.Regs()[0]=(c>=0&&c<=255)?toupper(c):c;});
    RegisterThunk("qsort",[](Jit& j,Host& h){
        uint32_t base=j.Regs()[0],count=j.Regs()[1],size=j.Regs()[2],compare=j.Regs()[3];
        if(count<2||!size)return;if(!compare)Invalid("qsort comparator");
        size_t bytes=uint64_t(count)*size;auto* data=static_cast<uint8_t*>(Span(h,base,bytes));
        std::vector<uint8_t> original(data,data+bytes);std::vector<uint32_t> order(count);
        for(uint32_t i=0;i<count;++i)order[i]=i;
        std::sort(order.begin(),order.end(),[&](uint32_t a,uint32_t b){return static_cast<int32_t>(h.CallGuestNested(compare,{base+a*size,base+b*size}))<0;});
        for(uint32_t i=0;i<count;++i)memcpy(data+size_t(i)*size,original.data()+size_t(order[i])*size,size);
    });
    RegisterThunk("bsearch",[](Jit& j,Host& h){
        uint32_t key=j.Regs()[0],base=j.Regs()[1],count=j.Regs()[2],size=j.Regs()[3];
        uint32_t compare=h.ReadStackWord(j,0);j.Regs()[0]=0;
        if(!count||!size)return;if(!compare)Invalid("bsearch comparator");Span(h,base,uint64_t(count)*size);
        uint32_t low=0,high=count;while(low<high){uint32_t mid=low+(high-low)/2,p=base+mid*size;
            int32_t value=h.CallGuestNested(compare,{key,p});if(!value){j.Regs()[0]=p;return;}if(value<0)high=mid;else low=mid+1;}
    });
    RegisterThunk("sin",[](Jit& j,Host&){WriteDF(j,0,sin(ReadDF(j,0)));});
    RegisterThunk("cos",[](Jit& j,Host&){WriteDF(j,0,cos(ReadDF(j,0)));});
    RegisterThunk("tan",[](Jit& j,Host&){WriteDF(j,0,tan(ReadDF(j,0)));});
    RegisterThunk("acos",[](Jit& j,Host&){WriteDF(j,0,acos(ReadDF(j,0)));});
    RegisterThunk("asin",[](Jit& j,Host&){WriteDF(j,0,asin(ReadDF(j,0)));});
    RegisterThunk("ceil",[](Jit& j,Host&){WriteDF(j,0,ceil(ReadDF(j,0)));});
    RegisterThunk("floor",[](Jit& j,Host&){WriteDF(j,0,floor(ReadDF(j,0)));});
    RegisterThunk("exp",[](Jit& j,Host&){WriteDF(j,0,exp(ReadDF(j,0)));});
    RegisterThunk("log",[](Jit& j,Host&){WriteDF(j,0,log(ReadDF(j,0)));});
    RegisterThunk("log10",[](Jit& j,Host&){WriteDF(j,0,log10(ReadDF(j,0)));});
    RegisterThunk("fmod",[](Jit& j,Host&){WriteDF(j,0,fmod(ReadDF(j,0),ReadDF(j,1)));});
    RegisterThunk("pow",[](Jit& j,Host&){WriteDF(j,0,pow(ReadDF(j,0),ReadDF(j,1)));});
    RegisterThunk("sinf",[](Jit& j,Host&){WriteSF(j,0,sinf(ReadSF(j,0)));});
    RegisterThunk("cosf",[](Jit& j,Host&){WriteSF(j,0,cosf(ReadSF(j,0)));});
    RegisterThunk("tanf",[](Jit& j,Host&){WriteSF(j,0,tanf(ReadSF(j,0)));});
    RegisterThunk("acosf",[](Jit& j,Host&){WriteSF(j,0,acosf(ReadSF(j,0)));});
    RegisterThunk("asinf",[](Jit& j,Host&){WriteSF(j,0,asinf(ReadSF(j,0)));});
    RegisterThunk("atanf",[](Jit& j,Host&){WriteSF(j,0,atanf(ReadSF(j,0)));});
    RegisterThunk("ceilf",[](Jit& j,Host&){WriteSF(j,0,ceilf(ReadSF(j,0)));});
    RegisterThunk("floorf",[](Jit& j,Host&){WriteSF(j,0,floorf(ReadSF(j,0)));});
    RegisterThunk("expf",[](Jit& j,Host&){WriteSF(j,0,expf(ReadSF(j,0)));});
    RegisterThunk("logf",[](Jit& j,Host&){WriteSF(j,0,logf(ReadSF(j,0)));});
    RegisterThunk("log10f",[](Jit& j,Host&){WriteSF(j,0,log10f(ReadSF(j,0)));});
    RegisterThunk("fmodf",[](Jit& j,Host&){WriteSF(j,0,fmodf(ReadSF(j,0),ReadSF(j,1)));});
    RegisterThunk("powf",[](Jit& j,Host&){WriteSF(j,0,powf(ReadSF(j,0),ReadSF(j,1)));});
    RegisterThunk("atan2f",[](Jit& j,Host&){WriteSF(j,0,atan2f(ReadSF(j,0),ReadSF(j,1)));});
    RegisterThunk("lrand48",[](Jit& j,Host&){j.Regs()[0]=static_cast<uint32_t>(lrand48());});
    RegisterThunk("__android_log_print",[](Jit& j,Host& h){
#if defined(ASPHALT7_FINAL_SILENT)
        // Android's log APIs return 1 when a message is accepted. Keep that
        // contract even when the release build suppresses the actual output;
        // the guest uses the return value during startup.
        j.Regs()[0] = 1;
#else
        int priority=j.Regs()[0];const char* tag=String(h,j.Regs()[1]);VarArgs args(j,h,3);
        std::string text=Format(h,String(h,j.Regs()[2]),args);j.Regs()[0]=__android_log_write(priority,tag?tag:"Asphalt7Guest",text.c_str());
#endif
    });
    RegisterThunk("__android_log_vprint",[](Jit& j,Host& h){
#if defined(ASPHALT7_FINAL_SILENT)
        // Match __android_log_print for the guest while keeping release output silent.
        j.Regs()[0] = 1;
#else
        int priority=j.Regs()[0];const char* tag=String(h,j.Regs()[1]);VarArgs args(j,h,j.Regs()[3],true);
        std::string text=Format(h,String(h,j.Regs()[2]),args);j.Regs()[0]=__android_log_write(priority,tag?tag:"Asphalt7Guest",text.c_str());
#endif
    });
    RegisterThunk("printf",[](Jit& j,Host& h){VarArgs args(j,h,1);std::string text=Format(h,String(h,j.Regs()[0]),args);Result(j,h,WithFile(0x254,-1,[&](FILE* f){return LogWrite(f,text.data(),text.size());}));});
    RegisterThunk("fprintf",[](Jit& j,Host& h){
        uint32_t file=j.Regs()[0];VarArgs args(j,h,2);std::string text=Format(h,String(h,j.Regs()[1]),args);
        Result(j,h,WithFile(file,-1,[&](FILE* f){return LogWrite(f,text.data(),text.size());}));
    });
    RegisterThunk("sprintf",[](Jit& j,Host& h){PrintToBuffer(j,h,false,false);});
    RegisterThunk("snprintf",[](Jit& j,Host& h){PrintToBuffer(j,h,true,false);});
    RegisterThunk("vsprintf",[](Jit& j,Host& h){PrintToBuffer(j,h,false,true);});
    RegisterThunk("vsnprintf",[](Jit& j,Host& h){PrintToBuffer(j,h,true,true);});
    RegisterThunk("sscanf",[](Jit& j,Host& h){VarArgs args(j,h,2);j.Regs()[0]=Scan(h,String(h,j.Regs()[0]),String(h,j.Regs()[1]),args);});
    RegisterThunk("puts",[](Jit& j,Host& h){std::string text=String(h,j.Regs()[0]);text+='\n';Result(j,h,WithFile(0x254,-1,[&](FILE* f){return LogWrite(f,text.data(),text.size());}));});
    RegisterThunk("fputs",[](Jit& j,Host& h){const char* text=String(h,j.Regs()[0]);Result(j,h,WithFile(j.Regs()[1],-1,[&](FILE* f){return LogWrite(f,text,strlen(text));}));});
    RegisterThunk("putchar",[](Jit& j,Host& h){char c=j.Regs()[0];int rc=WithFile(0x254,-1,[&](FILE* f){return LogWrite(f,&c,1);});Result(j,h,rc<0?-1:static_cast<unsigned char>(c));});
    RegisterThunk("fputc",[](Jit& j,Host& h){char c=j.Regs()[0];int rc=WithFile(j.Regs()[1],-1,[&](FILE* f){return LogWrite(f,&c,1);});Result(j,h,rc<0?-1:static_cast<unsigned char>(c));});
    RegisterThunk("fgetc",[](Jit& j,Host& h){
        const uint32_t handle=j.Regs()[0];auto file=Lookup(g_files,handle);
        if(file&&file->direct){std::lock_guard lock(file->mutex);unsigned char value=0;const ssize_t n=AssetVfs::Read(file->direct.get(),&value,1);if(n==1){j.Regs()[0]=value;return;}if(n==0){j.Regs()[0]=EOF;return;}Errno(h,errno);j.Regs()[0]=EOF;return;}
        Result(j,h,WithFile(handle,EOF,[](FILE* f){return fgetc(f);}));
    });
    RegisterThunk("fgets",[](Jit& j,Host& h){
        uint32_t output=j.Regs()[0];int size=static_cast<int32_t>(j.Regs()[1]);if(size<=0){j.Regs()[0]=0;Errno(h,EINVAL);return;}
        char* p=static_cast<char*>(Span(h,output,size));const uint32_t handle=j.Regs()[2];auto file=Lookup(g_files,handle);
        if(file&&file->direct){std::lock_guard lock(file->mutex);errno=0;int index=0;while(index<size-1){char value=0;const ssize_t n=AssetVfs::Read(file->direct.get(),&value,1);if(n<0){if(!errno)errno=EIO;break;}if(n==0)break;p[index++]=value;if(value=='\n')break;}char* result=index?p:nullptr;if(!result&&errno)Errno(h,errno);j.Regs()[0]=result?output:0;return;}
        char* result=WithFile(handle,static_cast<char*>(nullptr),[&](FILE* f){return fgets(p,size,f);});
        if(!result)Errno(h,errno);j.Regs()[0]=result?output:0;
    });
    RegisterThunk("perror",[](Jit& j,Host& h){
        int error=h.MemoryRead32(h.GuestErrnoAddress());const char* prefix=String(h,j.Regs()[0]);
        LOGE("%s%s%s",prefix?prefix:"",prefix&&*prefix?": ":"",strerror(error));
    });
    RegisterThunk("fopen",[](Jit& j,Host& h){
        const char* path=String(h,j.Regs()[0]);const char* mode=String(h,j.Regs()[1]);
        if(!path||!mode){Errno(h,EINVAL);j.Regs()[0]=0;return;}
        const char* leaf=strrchr(path,'/');leaf=leaf?leaf+1:path;
        if(!strcmp(leaf,"CUHLwd") && strpbrk(mode,"wa+")){LOGE("unsupported ARM32 watchdog extraction: %s",path);Errno(h,ENOTSUP);j.Regs()[0]=0;return;}
        GuestOpenFile opened=OpenGuestFile(path,mode);
        uint32_t result=opened.direct ? AddFile(h,std::move(opened.direct),path) : AddFile(h,opened.stream,path);
        if (result && IsOconfPath(path)) {
            const uint64_t opened_count = g_oconf_open_count.fetch_add(1, std::memory_order_relaxed) + 1;
            const int64_t live = g_oconf_live_count.fetch_add(1, std::memory_order_relaxed) + 1;
            if ((opened_count & 0x7fu) == 0) {
                LOGI("oconf handle stats opened=%llu live=%lld guest=0x%08x",
                     static_cast<unsigned long long>(opened_count),
                     static_cast<long long>(live), result);
            }
        }
        if(!result)Errno(h,errno);j.Regs()[0]=result;
    });
    RegisterThunk("fclose",[](Jit& j,Host& h){
        const uint32_t handle=j.Regs()[0];
        const std::string label=FileLabel(handle);
        LogFileOperation("fclose",handle,label,0,0);
        Result(j,h,CloseFile(h,handle));
    });
    RegisterThunk("fflush",[](Jit& j,Host& h){
        if(j.Regs()[0]){auto file=Lookup(g_files,j.Regs()[0]);if(file&&file->direct){j.Regs()[0]=0;return;}Result(j,h,WithFile(j.Regs()[0],EOF,[](FILE* f){return fflush(f);}));return;}
        std::vector<std::shared_ptr<File>> files;{std::lock_guard lock(g_handles_mutex);for(auto& [_,f]:g_files)files.push_back(f);}
        int error=0;for(auto& f:files){std::lock_guard lock(f->mutex);if(f->stream&&fflush(f->stream))error=errno;}
        if(error)Failure(j,h,error);else j.Regs()[0]=0;
    });
    RegisterThunk("fread",[](Jit& j,Host& h){
        size_t size=j.Regs()[1],count=j.Regs()[2];void* p=Span(h,j.Regs()[0],uint64_t(size)*count);
        const uint32_t handle=j.Regs()[3];
        const std::string label=FileLabel(handle);
        auto file=Lookup(g_files,handle);
        if(file&&file->direct){std::lock_guard lock(file->mutex);if(!size||!count){j.Regs()[0]=0;return;}const size_t bytes=size*count;const ssize_t n=AssetVfs::Read(file->direct.get(),p,bytes);if(n<0){Errno(h,errno);j.Regs()[0]=0;return;}LogFileOperation("fread",handle,label,bytes,static_cast<size_t>(n));
#if defined(ASPHALT7_VFS_TELEMETRY)
            if (label.find(".mpc") != std::string::npos &&
                g_audio_read_logs.fetch_add(1, std::memory_order_relaxed) < 32) {
                const auto* bytes_ptr = static_cast<const uint8_t*>(p);
                const uint8_t b0 = n > 0 ? bytes_ptr[0] : 0;
                const uint8_t b1 = n > 1 ? bytes_ptr[1] : 0;
                const uint8_t b2 = n > 2 ? bytes_ptr[2] : 0;
                const uint8_t b3 = n > 3 ? bytes_ptr[3] : 0;
                VFS_LOGI("ASSETVFS audio-read guest='%s' requested=%zu result=%zd "
                         "pos=%lld first=%02x%02x%02x%02x",
                         label.c_str(), bytes, n,
                         static_cast<long long>(AssetVfs::Tell(file->direct.get()) - n),
                         b0, b1, b2, b3);
            }
#endif
            j.Regs()[0]=static_cast<size_t>(n)/size;return;}
        size_t n=WithFile(handle,size_t(0),[&](FILE* f){return fread(p,size,count,f);});
        LogFileOperation("fread",handle,label,size*count,n*size);
        if(n<count)Errno(h,errno);j.Regs()[0]=n;
    });
    RegisterThunk("fwrite",[](Jit& j,Host& h){
        size_t size=j.Regs()[1],count=j.Regs()[2];const char* p=static_cast<const char*>(Span(h,j.Regs()[0],uint64_t(size)*count));
        if(!size||!count){j.Regs()[0]=0;return;}
        const uint32_t handle=j.Regs()[3];
        auto file=Lookup(g_files,handle);if(file&&file->direct){Errno(h,EBADF);j.Regs()[0]=0;return;}
        const std::string label=FileLabel(handle);
        size_t n=WithFile(handle,size_t(0),[&](FILE* f){
            if((f==g_standard_streams[1]&&g_standard_fds[1]>=0)||(f==g_standard_streams[2]&&g_standard_fds[2]>=0))return LogWrite(f,p,size*count)<0?size_t(0):count;return fwrite(p,size,count,f);});
        LogFileOperation("fwrite",handle,label,size*count,n*size);
        if(n<count)Errno(h,errno);j.Regs()[0]=n;
    });
    RegisterThunk("fseek",[](Jit& j,Host& h){
        int32_t offset=j.Regs()[1];int whence=j.Regs()[2];const uint32_t handle=j.Regs()[0];const std::string label=FileLabel(handle);auto file=Lookup(g_files,handle);if(file&&file->direct){std::lock_guard lock(file->mutex);const off64_t result=AssetVfs::Seek(file->direct.get(),offset,whence);LogFileOperation("fseek",handle,label,static_cast<size_t>(offset),result<0?0:static_cast<size_t>(result));Result(j,h,result);return;}const int result=WithFile(handle,-1,[&](FILE* f){return fseeko(f,offset,whence);});LogFileOperation("fseek",handle,label,static_cast<size_t>(offset),result);Result(j,h,result);
    });
    RegisterThunk("ftell",[](Jit& j,Host& h){
        auto file=Lookup(g_files,j.Regs()[0]);if(file&&file->direct){std::lock_guard lock(file->mutex);const off64_t value=AssetVfs::Tell(file->direct.get());if(value>INT32_MAX){Failure(j,h,EOVERFLOW);return;}Result(j,h,value);return;}
        off_t value=WithFile(j.Regs()[0],off_t(-1),[](FILE* f){return ftello(f);});
        if(value>INT32_MAX){Failure(j,h,EOVERFLOW);return;}Result(j,h,value);
    });
    RegisterThunk("open",[](Jit& j,Host& h){
        const char* path=String(h,j.Regs()[0]);int flags=j.Regs()[1];if(!path){Failure(j,h,EFAULT);return;}
        const char* leaf=strrchr(path,'/');leaf=leaf?leaf+1:path;
        if(!strcmp(leaf,"CUHLwd") && (flags&(O_WRONLY|O_RDWR|O_CREAT|O_TRUNC))){LOGE("unsupported ARM32 watchdog extraction: %s",path);Failure(j,h,ENOTSUP);return;}
        Result(j,h,OpenGuestFileDescriptor(path,flags,static_cast<mode_t>(j.Regs()[2])));
    });
    // Embedded files use real host descriptors; fstat/read/pread/lseek below
    // retain the bridge's existing identity-FD behavior. Whole-container
    // entries use synthetic descriptors with explicit range-read handling.
    RegisterThunk("close",[](Jit& j,Host& h){
        int fd=static_cast<int>(j.Regs()[0]);
        auto virtual_fd=LookupVirtualFd(fd);
        if (virtual_fd) { std::lock_guard lock(g_handles_mutex); g_virtual_fds.erase(fd); j.Regs()[0]=0; return; }
        Result(j,h,fd>=0&&fd<3?CloseFile(h,0x200+84*fd):close(fd));
    });
    RegisterThunk("read",[](Jit& j,Host& h){
        int fd=static_cast<int>(j.Regs()[0]);
        auto virtual_fd=LookupVirtualFd(fd);
        if (virtual_fd) { std::lock_guard lock(virtual_fd->mutex); Result(j,h,AssetVfs::Read(virtual_fd->handle.get(),Span(h,j.Regs()[1],j.Regs()[2]),j.Regs()[2])); return; }
        Result(j,h,read(NativeFd(fd),Span(h,j.Regs()[1],j.Regs()[2]),j.Regs()[2]));
    });
    RegisterThunk("write",[](Jit& j,Host& h){
        int fd=j.Regs()[0];size_t size=j.Regs()[2];const char* p=static_cast<const char*>(Span(h,j.Regs()[1],size));
        if(fd==1||fd==2)Result(j,h,WithFile(0x200+84*fd,-1,[&](FILE* f){return LogWrite(f,p,size);}));
        else Result(j,h,write(NativeFd(fd),p,size));
    });
    RegisterThunk("lseek",[](Jit& j,Host& h){
        int fd=static_cast<int>(j.Regs()[0]);
        auto virtual_fd=LookupVirtualFd(fd);
        if (virtual_fd) { std::lock_guard lock(virtual_fd->mutex); Result(j,h,AssetVfs::Seek(virtual_fd->handle.get(),static_cast<int32_t>(j.Regs()[1]),static_cast<int>(j.Regs()[2]))); return; }
        off_t value=lseek(NativeFd(fd),static_cast<int32_t>(j.Regs()[1]),static_cast<int>(j.Regs()[2]));
        if(value>INT32_MAX){Failure(j,h,EOVERFLOW);return;}Result(j,h,value);
    });
    RegisterThunk("access",[](Jit& j,Host& h){Result(j,h,AccessGuestPath(String(h,j.Regs()[0]),j.Regs()[1]));});
    RegisterThunk("mkdir",[](Jit& j,Host& h){Result(j,h,mkdir(String(h,j.Regs()[0]),j.Regs()[1]));});
    RegisterThunk("umask",[](Jit& j,Host&){j.Regs()[0]=umask(j.Regs()[0]);});
    RegisterThunk("flock",[](Jit& j,Host& h){Result(j,h,flock(NativeFd(static_cast<int>(j.Regs()[0])),static_cast<int>(j.Regs()[1])));});
    RegisterThunk("stat",[](Jit& j,Host& h){
        uint32_t p=j.Regs()[1];Span(h,p,sizeof(Stat32));struct stat value{};
        int rc=StatGuestPath(String(h,j.Regs()[0]),&value);if(!rc&&!WriteStat(h,p,value))rc=-1;Result(j,h,rc);
    });
    RegisterThunk("fstat",[](Jit& j,Host& h){
        uint32_t p=j.Regs()[1];Span(h,p,sizeof(Stat32));struct stat value{};int fd=static_cast<int>(j.Regs()[0]);
        auto virtual_fd=LookupVirtualFd(fd);
        int rc=virtual_fd ? 0 : fstat(NativeFd(fd),&value);
        if (virtual_fd) { std::lock_guard lock(virtual_fd->mutex); value.st_mode=S_IFREG|0400; value.st_size=AssetVfs::Size(virtual_fd->handle.get()); }
        if(!rc&&!WriteStat(h,p,value))rc=-1;Result(j,h,rc);
    });
    RegisterThunk("opendir",[](Jit& j,Host& h){
        OpenDirectoryResult opened=OpenGuestDirectory(String(h,j.Regs()[0]));
        if(!opened.direct && !opened.native){Errno(h,errno);j.Regs()[0]=0;return;}
        uint32_t p=h.GuestAlloc(sizeof(Dirent32),8);
        if(!p){if(opened.native)closedir(opened.native);Errno(h,ENOMEM);j.Regs()[0]=0;return;}
        if (opened.direct) {
            std::lock_guard lock(g_handles_mutex);
            g_dirs.emplace(p,std::make_shared<Directory>(std::move(opened.names),
                                                         std::move(opened.directories),p));
        } else {
            std::lock_guard lock(g_handles_mutex);
            g_dirs.emplace(p,std::make_shared<Directory>(opened.native,p));
        }
        j.Regs()[0]=p;
    });
    RegisterThunk("readdir",[](Jit& j,Host& h){
        auto d=Lookup(g_dirs,j.Regs()[0]);if(!d){Errno(h,EBADF);j.Regs()[0]=0;return;}
        std::lock_guard lock(d->mutex);
        Dirent32 g{};
        if (d->virtual_directory) {
            if (d->index >= d->names.size()) { j.Regs()[0]=0; return; }
            g.ino = static_cast<uint32_t>(d->index + 1);
            g.off = static_cast<uint32_t>(d->index + 1);
            g.reclen = sizeof(g);
            g.type = d->directories[d->index] ? DT_DIR : DT_REG;
            const std::string& name = d->names[d->index++];
            memcpy(g.name,name.data(),std::min<size_t>(name.size(),sizeof(g.name)-1));
        } else {
            if(!d->directory){Errno(h,EBADF);j.Regs()[0]=0;return;}
            errno=0;dirent* entry=readdir(d->directory);if(!entry){if(errno)Errno(h,errno);j.Regs()[0]=0;return;}
            g.ino=entry->d_ino;g.off=entry->d_off;g.reclen=sizeof(g);g.type=entry->d_type;
            memcpy(g.name,entry->d_name,strnlen(entry->d_name,255));
        }
        memcpy(Span(h,d->entry,sizeof(g)),&g,sizeof(g));j.Regs()[0]=d->entry;
    });
    RegisterThunk("closedir",[](Jit& j,Host& h){
        uint32_t p=j.Regs()[0];auto d=Lookup(g_dirs,p);if(!d){Failure(j,h,EBADF);return;}
        int rc;{std::lock_guard lock(d->mutex);
            if (d->virtual_directory) { d->virtual_directory=false; rc=0; }
            else { if(!d->directory){Failure(j,h,EBADF);return;}rc=closedir(d->directory);d->directory=nullptr; }
        }
        int saved=errno;{std::lock_guard lock(g_handles_mutex);g_dirs.erase(p);}h.GuestFree(d->entry);errno=saved;Result(j,h,rc);
    });
    RegisterThunk("gzopen",[](Jit& j,Host& h){
        gzFile file=OpenGuestGzip(String(h,j.Regs()[0]),String(h,j.Regs()[1]));if(!file){Errno(h,errno);j.Regs()[0]=0;return;}
        uint32_t p=h.GuestAlloc(4,4);if(!p){gzclose(file);Errno(h,ENOMEM);j.Regs()[0]=0;return;}
        {std::lock_guard lock(g_handles_mutex);g_gzip.emplace(p,std::make_shared<Gzip>(file));}j.Regs()[0]=p;
    });
    RegisterThunk("gzgets",[](Jit& j,Host& h){
        auto g=Lookup(g_gzip,j.Regs()[0]);uint32_t p=j.Regs()[1];int length=static_cast<int32_t>(j.Regs()[2]);
        if(!g||length<=0){Errno(h,EINVAL);j.Regs()[0]=0;return;}
        std::lock_guard lock(g->mutex);if(!g->file){Errno(h,EBADF);j.Regs()[0]=0;return;}
        char* result=gzgets(g->file,static_cast<char*>(Span(h,p,length)),length);if(!result)Errno(h,errno);j.Regs()[0]=result?p:0;
    });
    RegisterThunk("gzclose",[](Jit& j,Host& h){
        uint32_t p=j.Regs()[0];auto g=Lookup(g_gzip,p);if(!g){j.Regs()[0]=Z_STREAM_ERROR;return;}
        int rc;{std::lock_guard lock(g->mutex);if(!g->file){j.Regs()[0]=Z_STREAM_ERROR;return;}rc=gzclose(g->file);g->file=nullptr;}
        {std::lock_guard lock(g_handles_mutex);g_gzip.erase(p);}h.GuestFree(p);j.Regs()[0]=rc;
    });
    RegisterThunk("clock_gettime",[](Jit& j,Host& h){
        uint32_t p=j.Regs()[1];Span(h,p,8);timespec value{};int rc=clock_gettime(static_cast<clockid_t>(j.Regs()[0]),&value);
        if(!rc&&!WriteTime(h,p,value))rc=-1;Result(j,h,rc);
    });
    RegisterThunk("gettimeofday",[](Jit& j,Host& h){
        uint32_t p=j.Regs()[0],tzp=j.Regs()[1];if(p)Span(h,p,8);if(tzp)Span(h,tzp,8);
        timeval tv{};struct timezone tz{};int rc=gettimeofday(&tv,tzp?&tz:nullptr);
        if(!rc&&p){if(tv.tv_sec>INT32_MAX||tv.tv_sec<INT32_MIN){Failure(j,h,EOVERFLOW);return;}
            h.MemoryWrite32(p,static_cast<uint32_t>(tv.tv_sec));h.MemoryWrite32(p+4,static_cast<uint32_t>(tv.tv_usec));}
        if(!rc&&tzp){h.MemoryWrite32(tzp,tz.tz_minuteswest);h.MemoryWrite32(tzp+4,tz.tz_dsttime);}Result(j,h,rc);
    });
    RegisterThunk("nanosleep",[](Jit& j,Host& h){
        timespec request{},remaining{};uint32_t output=j.Regs()[1];if(output)Span(h,output,8);
        if(!ReadTime(h,j.Regs()[0],request)||request.tv_sec<0){Failure(j,h,EINVAL);return;}
        int rc=nanosleep(&request,output?&remaining:nullptr);int saved=errno;
        if(rc<0&&saved==EINTR&&output)WriteTime(h,output,remaining);errno=saved;Result(j,h,rc);
    });
    RegisterThunk("usleep",[](Jit& j,Host& h){
#if !defined(ASPHALT7_FINAL_SILENT)
        static thread_local unsigned logged=0;
        if(logged<4){LOGI("guest usleep tid=%d usec=%u caller=0x%08x",gettid(),j.Regs()[0],j.Regs()[14]);++logged;}
#endif
        Result(j,h,usleep(j.Regs()[0]));
    });
    RegisterThunk("sleep",[](Jit& j,Host& h){unsigned remaining=sleep(j.Regs()[0]);if(remaining)Errno(h,errno);j.Regs()[0]=remaining;});
    RegisterThunk("time",[](Jit& j,Host& h){
        uint32_t p=j.Regs()[0];if(p)Span(h,p,4);time_t value=time(nullptr);
        if(value>INT32_MAX||value<INT32_MIN){Failure(j,h,EOVERFLOW);return;}
        if(p)h.MemoryWrite32(p,static_cast<uint32_t>(value));Result(j,h,value);
    });
    RegisterThunk("localtime",[](Jit& j,Host& h){
        Span(h,j.Regs()[0],4);time_t value=static_cast<int32_t>(h.MemoryRead32(j.Regs()[0]));tm result{};
        if(!localtime_r(&value,&result)){Errno(h,errno);j.Regs()[0]=0;return;}
        if(!t_cache.tm)t_cache.tm=h.GuestAlloc(sizeof(Tm32),4);
        if(!t_cache.tm){Errno(h,ENOMEM);j.Regs()[0]=0;return;}WriteTm(h,t_cache.tm,result);j.Regs()[0]=t_cache.tm;
    });
    RegisterThunk("gmtime_r",[](Jit& j,Host& h){
        Span(h,j.Regs()[0],4);uint32_t p=j.Regs()[1];Span(h,p,sizeof(Tm32));time_t value=static_cast<int32_t>(h.MemoryRead32(j.Regs()[0]));tm result{};
        if(!gmtime_r(&value,&result)){Errno(h,errno);j.Regs()[0]=0;return;}WriteTm(h,p,result);j.Regs()[0]=p;
    });
    RegisterThunk("getenv",[](Jit& j,Host& h){const char* name=String(h,j.Regs()[0]);const char* value=getenv(name);j.Regs()[0]=CachedString(h,std::string("env:")+name,value);});
    RegisterThunk("strerror",[](Jit& j,Host& h){int error=j.Regs()[0];j.Regs()[0]=CachedString(h,"strerror",strerror(error));});
    RegisterThunk("strerror_r",[](Jit& j,Host& h){
        char* p=static_cast<char*>(Span(h,j.Regs()[1],j.Regs()[2]));j.Regs()[0]=BionicStrerrorR(j.Regs()[0],p,j.Regs()[2]);
    });
    RegisterThunk("basename",[](Jit& j,Host& h){
        const char* path=String(h,j.Regs()[0]);char* value=basename(const_cast<char*>(path));
        uintptr_t address=reinterpret_cast<uintptr_t>(value),base=reinterpret_cast<uintptr_t>(h.GetGuestMemoryBase());
        j.Regs()[0]=(address>=base&&address-base<h.GetGuestMemorySize())?Address(h,value):CachedString(h,"basename",value);
    });
    RegisterThunk("getpwuid",[](Jit& j,Host& h){
        passwd* pw=getpwuid(static_cast<uid_t>(j.Regs()[0]));if(!pw){Errno(h,errno);j.Regs()[0]=0;return;}
        const char* strings[]={pw->pw_name,pw->pw_passwd,pw->pw_dir,pw->pw_shell};size_t size=24;
        for(auto s:strings)if(s)size+=strlen(s)+1;
        if(size>t_cache.passwd_capacity){uint32_t next=h.GuestAlloc(size,4);if(!next){Errno(h,ENOMEM);j.Regs()[0]=0;return;}
            h.GuestFree(t_cache.passwd);t_cache.passwd=next;t_cache.passwd_capacity=size;}
        uint32_t p=t_cache.passwd,cursor=p+24;uint32_t fields[]={0,0,pw->pw_uid,pw->pw_gid,0,0};
        const unsigned indexes[]={0,1,4,5};for(unsigned i=0;i<4;++i)if(strings[i]){
            size_t n=strlen(strings[i])+1;fields[indexes[i]]=cursor;memcpy(Span(h,cursor,n),strings[i],n);cursor+=n;}
        memcpy(Span(h,p,sizeof(fields)),fields,sizeof(fields));j.Regs()[0]=p;
    });
    RegisterThunk("getpid",[](Jit& j,Host&){j.Regs()[0]=getpid();});
    RegisterThunk("getppid",[](Jit& j,Host&){j.Regs()[0]=getppid();});
    RegisterThunk("geteuid",[](Jit& j,Host&){j.Regs()[0]=geteuid();});
    RegisterThunk("gettid",[](Jit& j,Host&){j.Regs()[0]=gettid();});
    RegisterThunk("sched_yield",[](Jit& j,Host& h){Result(j,h,sched_yield());});
    RegisterThunk("sched_get_priority_min",[](Jit& j,Host& h){Result(j,h,sched_get_priority_min(j.Regs()[0]));});
    RegisterThunk("sched_get_priority_max",[](Jit& j,Host& h){Result(j,h,sched_get_priority_max(j.Regs()[0]));});
    RegisterThunk("fcntl",[](Jit& j,Host& h){
        int fd=NativeFd(j.Regs()[0]),command=j.Regs()[1];uint32_t arg=j.Regs()[2];
        if(command==F_DUPFD||command==F_DUPFD_CLOEXEC||command==F_GETFD||command==F_SETFD||command==F_GETFL||command==F_SETFL){Result(j,h,fcntl(fd,command,arg));return;}
        bool wide=command>=12&&command<=14;
        if((command>=5&&command<=7)||wide){
            Span(h,arg,wide?32:16);struct flock value{};
            value.l_type=static_cast<int16_t>(h.MemoryRead16(arg));value.l_whence=static_cast<int16_t>(h.MemoryRead16(arg+2));
            value.l_start=wide?static_cast<int64_t>(h.MemoryRead64(arg+8)):static_cast<int32_t>(h.MemoryRead32(arg+4));
            value.l_len=wide?static_cast<int64_t>(h.MemoryRead64(arg+16)):static_cast<int32_t>(h.MemoryRead32(arg+8));
            value.l_pid=static_cast<int32_t>(h.MemoryRead32(arg+(wide?24:12)));
            int translated=wide?command-7:command;int rc=fcntl(fd,translated,&value);
            if(!rc&&translated==F_GETLK){
                if(!wide&&(value.l_start>INT32_MAX||value.l_start<INT32_MIN||value.l_len>INT32_MAX||value.l_len<INT32_MIN)){Failure(j,h,EOVERFLOW);return;}
                h.MemoryWrite16(arg,value.l_type);h.MemoryWrite16(arg+2,value.l_whence);
                if(wide){h.MemoryWrite64(arg+8,value.l_start);h.MemoryWrite64(arg+16,value.l_len);}else{h.MemoryWrite32(arg+4,value.l_start);h.MemoryWrite32(arg+8,value.l_len);}
                h.MemoryWrite32(arg+(wide?24:12),value.l_pid);
            }Result(j,h,rc);return;
        }
        LOGE("unsupported fcntl command %d",command);Failure(j,h,ENOTSUP);
    });
    RegisterThunk("ioctl",[](Jit& j,Host& h){
        int fd=NativeFd(j.Regs()[0]);unsigned request=j.Regs()[1];
        if(request==FIONREAD||request==FIONBIO){Result(j,h,ioctl(fd,request,Span(h,j.Regs()[2],4)));return;}
        if(request==SIOCGIFCONF){
            const uint32_t guest_arg=j.Regs()[2];
            Span(h,guest_arg,8);
            const int32_t guest_capacity=static_cast<int32_t>(h.MemoryRead32(guest_arg));
            const uint32_t guest_buffer=h.MemoryRead32(guest_arg+4);
            if(guest_capacity<0){Failure(j,h,EINVAL);return;}
            if(guest_capacity&&guest_buffer)Span(h,guest_buffer,static_cast<size_t>(guest_capacity));
            const size_t native_capacity=std::min<size_t>(std::max<size_t>(guest_capacity,16u*sizeof(ifreq)),64u*1024u);
            std::vector<uint8_t> native_storage(native_capacity);
            ifconf native{};
            native.ifc_len=static_cast<int>(native_storage.size());
            native.ifc_buf=reinterpret_cast<char*>(native_storage.data());
            const int rc=ioctl(fd,request,&native);
            if(rc==0&&guest_buffer&&guest_capacity){
                const size_t native_count=std::min<size_t>(
                    native.ifc_len>0?static_cast<size_t>(native.ifc_len)/sizeof(ifreq):0,
                    native_storage.size()/sizeof(ifreq));
                const size_t guest_stride=16+sizeof(sockaddr);
                const size_t guest_count=std::min(native_count,static_cast<size_t>(guest_capacity)/guest_stride);
                for(size_t i=0;i<guest_count;++i){
                    const auto* source=reinterpret_cast<const ifreq*>(native_storage.data()+i*sizeof(ifreq));
                    const uint32_t destination=guest_buffer+static_cast<uint32_t>(i*guest_stride);
                    memcpy(Span(h,destination,guest_stride),source,guest_stride);
                }
                h.MemoryWrite32(guest_arg,static_cast<uint32_t>(guest_count*guest_stride));
            }else if(rc==0){
                h.MemoryWrite32(guest_arg,static_cast<uint32_t>(std::max(native.ifc_len,0)));
            }
            Result(j,h,rc);
            if(rc==0)LOGI("guest SIOCGIFCONF translated guest_capacity=%d native_bytes=%d guest_bytes=%u",guest_capacity,native.ifc_len,h.MemoryRead32(guest_arg));
            return;
        }
        if(request==SIOCGIFFLAGS){
            const uint32_t guest_arg=j.Regs()[2];
            constexpr size_t guest_ifreq_size=16+sizeof(sockaddr);
            auto* guest_ifreq=static_cast<uint8_t*>(Span(h,guest_arg,guest_ifreq_size));
            ifreq native{};
            memcpy(native.ifr_name,guest_ifreq,IFNAMSIZ);
            const int rc=ioctl(fd,request,&native);
            if(rc==0)memcpy(guest_ifreq,&native,guest_ifreq_size);
            Result(j,h,rc);
            if(rc==0)LOGI("guest SIOCGIFFLAGS translated ifname='%s' flags=0x%x",native.ifr_name,static_cast<unsigned short>(native.ifr_flags));
            return;
        }
        if(request==SIOCGIFHWADDR){
            const uint32_t guest_arg=j.Regs()[2];
            constexpr size_t guest_ifreq_size=16+sizeof(sockaddr);
            auto* guest_ifreq=static_cast<uint8_t*>(Span(h,guest_arg,guest_ifreq_size));
            ifreq native{};
            memcpy(native.ifr_name,guest_ifreq,IFNAMSIZ);
            const int rc=ioctl(fd,request,&native);
            if(rc==0)memcpy(guest_ifreq,&native,guest_ifreq_size);
            Result(j,h,rc);
            if(rc==0)LOGI("guest SIOCGIFHWADDR translated ifname='%s' family=%d",native.ifr_name,native.ifr_hwaddr.sa_family);
            return;
        }
        if(fd<0){Failure(j,h,EBADF);return;}
        LOGE("unsupported device ioctl fd=%d request=0x%x",fd,request);Failure(j,h,ENOTTY);
    });
    RegisterThunk("syscall",[](Jit& j,Host& h){
        uint32_t number=j.Regs()[0];
        if(number==224){j.Regs()[0]=gettid();return;}
        if(number==20){j.Regs()[0]=getpid();return;}
        if(number==240){
            uint32_t p=j.Regs()[1],operation=j.Regs()[2],value=j.Regs()[3];
            if(p&3){Failure(j,h,EINVAL);return;}void* address=Span(h,p,4);
            unsigned command=operation&0x7f;
            if(command!=0&&command!=1&&command!=9&&command!=10){LOGE("unsupported ARM futex operation %u",operation);Failure(j,h,ENOSYS);return;}
            timespec time{},*timeout=nullptr;uint32_t bitset=0xffffffffu;
            if(command==0||command==9){uint32_t time_ptr=h.ReadStackWord(j,0);if(time_ptr){if(!ReadTime(h,time_ptr,time)){Failure(j,h,EINVAL);return;}timeout=&time;}}
            if(command==9||command==10)bitset=h.ReadStackWord(j,2);
            Result(j,h,::syscall(SYS_futex,address,operation,value,timeout,nullptr,bitset));return;
        }
        if(number==241||number==242){
            // ARM32 syscall 241/242 are sched_set/getaffinity.  The guest
            // proves the four-byte ARM cpu_set_t ABI in AND_CurrentThreadAffinityMask.
            pid_t pid=static_cast<pid_t>(j.Regs()[1]);
            uint32_t set_size=j.Regs()[2],p=j.Regs()[3];
            if(set_size!=sizeof(uint32_t)||!p||(p&3)){
                g_affinity_before_guest_pin_valid=false;
                Failure(j,h,EINVAL);return;
            }
            if(number==242){
                // A failed refresh must not leave a snapshot from an older
                // getaffinity available to a later setaffinity on this thread.
                g_affinity_before_guest_pin_valid=false;
                cpu_set_t native{};
                if(sched_getaffinity(pid,sizeof(native),&native)!=0){Result(j,h,-1);return;}
                bool has_high=false;
                const uint32_t mask=Low32CpuMask(native,&has_high);
                if(AffinityWideEnabled()&&(pid==0||pid==gettid())&&mask&&!has_high){
                    cpu_set_t allowed=native;
                    uint32_t allowed_low=mask;
                    bool allowed_high=has_high;
                    if(ReadCurrentThreadAllowedCpuMask(allowed,allowed_low,allowed_high)&&
                       allowed_low&&!allowed_high&&(mask&~allowed_low)==0){
                        g_affinity_before_guest_pin=allowed;
                        g_affinity_before_guest_pin_low=allowed_low;
                        g_affinity_before_guest_pin_observed_low=mask;
                        g_affinity_before_guest_pin_valid=true;
                        LOGI("affinity-wide snapshot online=0x%08x allowed=0x%08x",
                             mask,allowed_low);
                    }
                }
                h.MemoryWrite32(p,mask);
                j.Regs()[0]=0;
                LOGI("guest syscall 242 sched_getaffinity pid=%d mask=0x%08x",static_cast<int>(pid),mask);
                return;
            }
            const uint32_t requested_mask=h.MemoryRead32(p);
            cpu_set_t requested{};CPU_ZERO(&requested);
            for(unsigned cpu=0;cpu<32;++cpu)if(requested_mask&(1u<<cpu))CPU_SET(cpu,&requested);
            const bool self=pid==0||pid==gettid();
            const bool singleton=requested_mask&&(requested_mask&(requested_mask-1u))==0;
            const bool widen=AffinityWideEnabled()&&self&&singleton&&
                              g_affinity_before_guest_pin_valid&&
                              !(requested_mask&~g_affinity_before_guest_pin_observed_low);
            const cpu_set_t effective=widen?g_affinity_before_guest_pin:requested;
            const uint32_t effective_request=widen?g_affinity_before_guest_pin_low:requested_mask;
            g_affinity_before_guest_pin_valid=false;
            const int rc=sched_setaffinity(pid,sizeof(effective),&effective);
            const int call_errno=errno;
            Result(j,h,rc);
            uint32_t actual_mask=0;int verify_ok=0;
            if(rc==0&&widen){
                cpu_set_t actual{};
                if(sched_getaffinity(pid,sizeof(actual),&actual)==0){
                    actual_mask=Low32CpuMask(actual);verify_ok=1;
                }
            }
            errno=call_errno;
            LOGI("guest syscall 241 sched_setaffinity pid=%d requested=0x%08x effective_request=0x%08x mode=%s result=%d errno=%d verify=%d actual_low32=0x%08x",
                 static_cast<int>(pid),requested_mask,effective_request,widen?"wide":"passthrough",
                 rc,rc<0?call_errno:0,verify_ok,actual_mask);
            return;
        }
        LOGE("unsupported ARM syscall %u",number);Failure(j,h,ENOSYS);
    });
    // LAN uses the original IPv4 socket protocol; retired HTTP/DNS requests
    // remain disabled at their own entry points.
    RegisterThunk("socket",[](Jit& j,Host& h){Result(j,h,::socket(j.Regs()[0],j.Regs()[1],j.Regs()[2]));});
    RegisterThunk("bind",[](Jit& j,Host& h){Result(j,h,bind(NativeFd(j.Regs()[0]),static_cast<const sockaddr*>(Span(h,j.Regs()[1],j.Regs()[2])),j.Regs()[2]));});
    RegisterThunk("connect",[](Jit& j,Host& h){Result(j,h,::connect(NativeFd(j.Regs()[0]),static_cast<const sockaddr*>(Span(h,j.Regs()[1],j.Regs()[2])),j.Regs()[2]));});
    RegisterThunk("send",[](Jit& j,Host& h){Result(j,h,send(NativeFd(j.Regs()[0]),Span(h,j.Regs()[1],j.Regs()[2]),j.Regs()[2],j.Regs()[3]));});
    RegisterThunk("recv",[](Jit& j,Host& h){Result(j,h,recv(NativeFd(j.Regs()[0]),Span(h,j.Regs()[1],j.Regs()[2]),j.Regs()[2],j.Regs()[3]));});
    RegisterThunk("poll",[](Jit& j,Host& h){
        static_assert(sizeof(pollfd)==8);uint32_t count=j.Regs()[1];
        auto* guest=static_cast<pollfd*>(Span(h,j.Regs()[0],uint64_t(count)*8));
        std::vector<pollfd> native(count);std::vector<bool> invalid(count);unsigned invalid_count=0;
        for(uint32_t i=0;i<count;++i){native[i]=guest[i];native[i].fd=NativeFd(guest[i].fd);
            invalid[i]=guest[i].fd>=0&&native[i].fd<0;if(invalid[i])++invalid_count;}
        int rc=poll(native.data(),count,invalid_count?0:static_cast<int32_t>(j.Regs()[2]));
        if(rc>=0){for(uint32_t i=0;i<count;++i)guest[i].revents=invalid[i]?POLLNVAL:native[i].revents;rc+=invalid_count;}Result(j,h,rc);
    });
    RegisterThunk("getsockname",[](Jit& j,Host& h){
        uint32_t size_ptr=j.Regs()[2];Span(h,size_ptr,4);socklen_t size=h.MemoryRead32(size_ptr);
        auto* p=static_cast<sockaddr*>(Span(h,j.Regs()[1],size));int rc=getsockname(NativeFd(j.Regs()[0]),p,&size);
        if(!rc)h.MemoryWrite32(size_ptr,size);Result(j,h,rc);
    });
    RegisterThunk("getpeername",[](Jit& j,Host& h){
        uint32_t size_ptr=j.Regs()[2];Span(h,size_ptr,4);socklen_t size=h.MemoryRead32(size_ptr);
        auto* p=static_cast<sockaddr*>(Span(h,j.Regs()[1],size));int rc=getpeername(NativeFd(j.Regs()[0]),p,&size);
        if(!rc)h.MemoryWrite32(size_ptr,size);Result(j,h,rc);
    });
    RegisterThunk("setsockopt",[](Jit& j,Host& h){
        uint32_t size=h.ReadStackWord(j,0);int level=j.Regs()[1],option=j.Regs()[2];
        const void* p=Span(h,j.Regs()[3],size);timeval tv{};
        if(level==SOL_SOCKET&&(option==SO_RCVTIMEO||option==SO_SNDTIMEO)){
            if(size<8){Failure(j,h,EINVAL);return;}tv.tv_sec=static_cast<int32_t>(h.MemoryRead32(j.Regs()[3]));tv.tv_usec=static_cast<int32_t>(h.MemoryRead32(j.Regs()[3]+4));p=&tv;size=sizeof(tv);
        }Result(j,h,setsockopt(NativeFd(j.Regs()[0]),level,option,p,size));
    });
    RegisterThunk("getsockopt",[](Jit& j,Host& h){
        uint32_t size_ptr=h.ReadStackWord(j,0);Span(h,size_ptr,4);socklen_t size=h.MemoryRead32(size_ptr);
        int level=j.Regs()[1],option=j.Regs()[2];uint32_t output=j.Regs()[3];void* p=Span(h,output,size);timeval tv{};bool timeout=level==SOL_SOCKET&&(option==SO_RCVTIMEO||option==SO_SNDTIMEO);
        if(timeout){if(size<8){Failure(j,h,EINVAL);return;}p=&tv;size=sizeof(tv);}
        int rc=getsockopt(NativeFd(j.Regs()[0]),level,option,p,&size);
        if(!rc){if(timeout){if(tv.tv_sec>INT32_MAX){Failure(j,h,EOVERFLOW);return;}h.MemoryWrite32(output,tv.tv_sec);h.MemoryWrite32(output+4,tv.tv_usec);size=8;}h.MemoryWrite32(size_ptr,size);}Result(j,h,rc);
    });
    RegisterThunk("inet_ntop",[](Jit& j,Host& h){
        int family=j.Regs()[0];uint32_t output=j.Regs()[2];size_t input_size=family==AF_INET?4:(family==AF_INET6?16:0);
        if(!input_size){Errno(h,EAFNOSUPPORT);j.Regs()[0]=0;return;}
        const char* result=inet_ntop(family,Span(h,j.Regs()[1],input_size),static_cast<char*>(Span(h,output,j.Regs()[3])),j.Regs()[3]);
        if(!result)Errno(h,errno);j.Regs()[0]=result?output:0;
    });
    RegisterThunk("inet_pton",[](Jit& j,Host& h){
        int family=j.Regs()[0];size_t size=family==AF_INET?4:(family==AF_INET6?16:0);if(!size){Failure(j,h,EAFNOSUPPORT);return;}
        Result(j,h,inet_pton(family,String(h,j.Regs()[1]),Span(h,j.Regs()[2],size)));
    });
    RegisterThunk("getaddrinfo",[](Jit& j,Host& h){
        uint32_t hints_ptr=j.Regs()[2],output=j.Regs()[3];Span(h,output,4);h.MemoryWrite32(output,0);addrinfo hints{},*result=nullptr;
        j.Regs()[0]=EAI_NONAME;
        return;
        if(hints_ptr){Span(h,hints_ptr,32);hints.ai_flags=h.MemoryRead32(hints_ptr);hints.ai_family=h.MemoryRead32(hints_ptr+4);hints.ai_socktype=h.MemoryRead32(hints_ptr+8);hints.ai_protocol=h.MemoryRead32(hints_ptr+12);
            if(h.MemoryRead32(hints_ptr+16)||h.MemoryRead32(hints_ptr+20)||h.MemoryRead32(hints_ptr+24)||h.MemoryRead32(hints_ptr+28)){j.Regs()[0]=EAI_BADHINTS;return;}}
        int rc=getaddrinfo(String(h,j.Regs()[0]),String(h,j.Regs()[1]),hints_ptr?&hints:nullptr,&result);
        if(rc){if(rc==EAI_SYSTEM)Errno(h,errno);j.Regs()[0]=rc;return;}
        std::vector<uint32_t> allocations;uint32_t first=0,previous=0;
        auto allocate=[&](size_t n){uint32_t p=h.GuestAlloc(n,4);if(p)allocations.push_back(p);return p;};
        for(auto* item=result;item;item=item->ai_next){
            uint32_t p=allocate(32);if(!p){rc=EAI_MEMORY;break;}
            uint32_t address=0,name=0;
            if(item->ai_addrlen){address=allocate(item->ai_addrlen);if(!address){rc=EAI_MEMORY;break;}memcpy(Span(h,address,item->ai_addrlen),item->ai_addr,item->ai_addrlen);}
            if(item->ai_canonname){size_t n=strlen(item->ai_canonname)+1;name=allocate(n);if(!name){rc=EAI_MEMORY;break;}memcpy(Span(h,name,n),item->ai_canonname,n);}
            uint32_t fields[]={static_cast<uint32_t>(item->ai_flags),static_cast<uint32_t>(item->ai_family),static_cast<uint32_t>(item->ai_socktype),static_cast<uint32_t>(item->ai_protocol),static_cast<uint32_t>(item->ai_addrlen),name,address,0};
            memcpy(Span(h,p,32),fields,32);if(previous)h.MemoryWrite32(previous+28,p);else first=p;previous=p;
        }
        freeaddrinfo(result);
        if(rc){for(uint32_t p:allocations)h.GuestFree(p);j.Regs()[0]=rc;return;}
        {std::lock_guard lock(g_handles_mutex);g_addrinfo.emplace(first,std::move(allocations));}
        h.MemoryWrite32(output,first);j.Regs()[0]=0;
    });
    RegisterThunk("freeaddrinfo",[](Jit& j,Host& h){
        uint32_t p=j.Regs()[0];if(!p)return;std::vector<uint32_t> allocations;
        {std::lock_guard lock(g_handles_mutex);auto it=g_addrinfo.find(p);if(it==g_addrinfo.end())Invalid("freeaddrinfo unknown allocation");allocations=std::move(it->second);g_addrinfo.erase(it);}
        for(uint32_t address:allocations)h.GuestFree(address);
    });
    RegisterThunk("__cxa_atexit",[](Jit& j,Host&){
        std::lock_guard lock(g_atexit_mutex);g_atexit.push_back({j.Regs()[0],j.Regs()[1],j.Regs()[2]});j.Regs()[0]=0;
    });
    RegisterThunk("__aeabi_atexit",[](Jit& j,Host&){
        std::lock_guard lock(g_atexit_mutex);g_atexit.push_back({j.Regs()[1],j.Regs()[0],j.Regs()[2]});j.Regs()[0]=0;
    });
    RegisterThunk("__cxa_finalize",[](Jit& j,Host& h){Finalize(h,j.Regs()[0]);});
    RegisterThunk("__stack_chk_fail",[](Jit&,Host&){Invalid("guest stack canary failed");});
    RegisterThunk("abort",[](Jit& j,Host&){
        LOGE("guest abort pc=0x%08x lr=0x%08x sp=0x%08x r0-r3=%08x,%08x,%08x,%08x",
             j.Regs()[15], j.Regs()[14], j.Regs()[13],
             j.Regs()[0], j.Regs()[1], j.Regs()[2], j.Regs()[3]);
        Invalid("guest abort");
    });
    RegisterThunk("__assert2",[](Jit& j,Host& h){
        const char* file=String(h,j.Regs()[0]);
        const int line=static_cast<int>(j.Regs()[1]);
        const char* function=String(h,j.Regs()[2]);
        const char* expression=String(h,j.Regs()[3]);
        auto& jit=h.CurrentJit();
        LOGE("guest assertion: %s:%d %s: %s pc=0x%08x lr=0x%08x sp=0x%08x",
             file, line, function, expression, jit.Regs()[15], jit.Regs()[14],
             jit.Regs()[13]);
        Invalid("guest assertion");
    });
    RegisterThunk("exit",[](Jit& j,Host& h){
        int status=j.Regs()[0];Finalize(h,0);if(h.HasFailed())Invalid("guest exit finalization failed");
        fflush(nullptr);::_exit(status);
    });
    RegisterThunk("_exit",[](Jit& j,Host&){::_exit(static_cast<int>(j.Regs()[0]));});
    RegisterThunk("raise",[](Jit& j,Host& h){
        LOGE("unsupported guest raise signal=%u; host signal delivery is disabled",j.Regs()[0]);
        Failure(j,h,ENOTSUP);
    });

    // The bundled CUHLwd executable is ARM32, not an arm64-compatible child process.
    RegisterThunk("vfork",[](Jit& j,Host& h){LOGE("unsupported ARM32 watchdog vfork; no child launched");Failure(j,h,ENOTSUP);});
    RegisterThunk("execl",[](Jit& j,Host& h){LOGE("unsupported guest execl; no binary executed");Failure(j,h,ENOTSUP);});
    RegisterThunk("mknod",[](Jit& j,Host& h){LOGE("unsupported guest device/daemon node creation");Failure(j,h,ENOTSUP);});

    // The guest uses the ARM32 Bionic signal path only for SIGALRM around DNS.
    // Other signal numbers remain explicit capability failures.
    RegisterThunk("sigaction",[](Jit& j,Host& h){
        const int signal=static_cast<int>(j.Regs()[0]);
        const uint32_t new_action=j.Regs()[1],old_action=j.Regs()[2];
        if(signal!=SIGALRM){
            LOGE("unsupported ARM32 signal handler ABI (signal=%d)",signal);
            Failure(j,h,ENOTSUP);return;
        }
        if((new_action&&((new_action&3)||!GuestRangeValid(h.GetGuestMemorySize(),new_action,16)))||
           (old_action&&((old_action&3)||!GuestRangeValid(h.GetGuestMemorySize(),old_action,16)))){
            Failure(j,h,EFAULT);return;
        }
        GuestSignalAction current{},next{};
        {std::lock_guard lock(g_signal_mutex);current=g_sigalrm_action;}
        if(old_action)WriteGuestSignalAction(h,old_action,current);
        if(new_action){
            next=ReadGuestSignalAction(h,new_action);
            if(next.handler!=0&&next.handler!=1&&!h.IsExecutableAddress(next.handler)){
                LOGE("invalid SIGALRM handler 0x%08x",next.handler);Failure(j,h,EINVAL);return;
            }
            std::lock_guard lock(g_signal_mutex);g_sigalrm_action=next;
        }
        LOGI("guest sigaction SIGALRM handler=0x%08x new=%u old=%u",next.handler,new_action?1:0,old_action?1:0);
        j.Regs()[0]=0;
    });
    RegisterThunk("alarm",[](Jit& j,Host&){
        const uint32_t seconds=j.Regs()[0];
        uint32_t remaining=0;
        if(t_alarm.armed){
            const auto now=std::chrono::steady_clock::now();
            const auto left=std::chrono::duration_cast<std::chrono::milliseconds>(t_alarm.deadline-now).count();
            if(left>0)remaining=static_cast<uint32_t>((left+999)/1000);
        }
        t_alarm.armed=seconds!=0;
        if(t_alarm.armed)t_alarm.deadline=std::chrono::steady_clock::now()+std::chrono::seconds(seconds);
        else t_alarm.jump_buffer=0;
        LOGI("guest alarm seconds=%u remaining=%u",seconds,remaining);
        j.Regs()[0]=remaining;
    });
    RegisterThunk("setjmp",[](Jit& j,Host& h){SaveGuestJump(j,h,j.Regs()[0],false);});
    RegisterThunk("longjmp",[](Jit& j,Host& h){RestoreGuestJump(j,h,j.Regs()[0],j.Regs()[1]);});
    RegisterThunk("sigsetjmp",[](Jit& j,Host& h){
        SaveGuestJump(j,h,j.Regs()[0],j.Regs()[1]!=0);
    });
    RegisterThunk("siglongjmp",[](Jit& j,Host& h){
        RestoreGuestJump(j,h,j.Regs()[0],j.Regs()[1]);
    });

    // The legacy ARM32 image was linked against a wider Bionic/libstdc++
    // surface than the small core set above. Keep these providers typed and
    // guest-memory aware; a zero-return catch-all would make startup appear
    // successful and corrupt the first real network/file/locale call.
    RegisterThunk("select",[](Jit& j,Host& h){
        const int nfds=static_cast<int>(j.Regs()[0]);
        if(nfds<0||nfds>FD_SETSIZE){Failure(j,h,EINVAL);return;}
        const uint32_t read_ptr=j.Regs()[1],write_ptr=j.Regs()[2],except_ptr=j.Regs()[3];
        const uint32_t time_ptr=h.ReadStackWord(j,0);
        const size_t guest_fd_bytes=sizeof(uint32_t)*FD_SETSIZE/32;
        fd_set read_set{},write_set{},except_set{};
        auto read_set_from_guest=[&](uint32_t address,fd_set& output){
            if(!address)return true;
            Span(h,address,guest_fd_bytes);FD_ZERO(&output);
            for(int fd=0;fd<nfds;++fd){
                const uint32_t bit=h.MemoryRead32(address+static_cast<uint32_t>((fd>>5)*4));
                if(!(bit&(1u<<static_cast<unsigned>(fd&31))))continue;
                const int native=NativeFd(fd);if(native>=0&&native<FD_SETSIZE)FD_SET(native,&output);
            }
            return true;
        };
        read_set_from_guest(read_ptr,read_set);read_set_from_guest(write_ptr,write_set);read_set_from_guest(except_ptr,except_set);
        timeval timeout{},*timeout_ptr=nullptr;
        if(time_ptr){Span(h,time_ptr,8);timeout.tv_sec=static_cast<int32_t>(h.MemoryRead32(time_ptr));timeout.tv_usec=static_cast<int32_t>(h.MemoryRead32(time_ptr+4));timeout_ptr=&timeout;}
        int rc=::select(nfds,read_ptr?&read_set:nullptr,write_ptr?&write_set:nullptr,except_ptr?&except_set:nullptr,timeout_ptr);
        if(rc>=0){
            auto write_set_to_guest=[&](uint32_t address,const fd_set& input){
                if(!address)return;for(int fd=0;fd<nfds;++fd){const int native=NativeFd(fd);const bool set=native>=0&&native<FD_SETSIZE&&FD_ISSET(native,&input);const uint32_t word=address+static_cast<uint32_t>((fd>>5)*4);uint32_t value=h.MemoryRead32(word);value=set?(value|(1u<<static_cast<unsigned>(fd&31))):(value&~(1u<<static_cast<unsigned>(fd&31)));h.MemoryWrite32(word,value);}
            };
            write_set_to_guest(read_ptr,read_set);write_set_to_guest(write_ptr,write_set);write_set_to_guest(except_ptr,except_set);
            if(time_ptr){if(timeout.tv_sec>INT32_MAX||timeout.tv_sec<INT32_MIN||timeout.tv_usec>INT32_MAX||timeout.tv_usec<INT32_MIN){Failure(j,h,EOVERFLOW);return;}h.MemoryWrite32(time_ptr,static_cast<uint32_t>(timeout.tv_sec));h.MemoryWrite32(time_ptr+4,static_cast<uint32_t>(timeout.tv_usec));}
        }
        Result(j,h,rc);
    });
    RegisterThunk("gethostbyname",[](Jit& j,Host& h){
        const hostent* value=::gethostbyname(String(h,j.Regs()[0]));
        if(!value){Errno(h,h_errno);j.Regs()[0]=0;return;}j.Regs()[0]=CacheHostent(h,value);
    });
    RegisterThunk("gethostbyaddr",[](Jit& j,Host& h){
        const uint32_t address=j.Regs()[0];const int length=static_cast<int>(j.Regs()[1]);const int type=static_cast<int>(j.Regs()[2]);
        const hostent* value=::gethostbyaddr(Span(h,address,length),length,type);
        if(!value){Errno(h,h_errno);j.Regs()[0]=0;return;}j.Regs()[0]=CacheHostent(h,value);
    });
    RegisterThunk("gethostname",[](Jit& j,Host& h){
        const uint32_t output=j.Regs()[0],length=j.Regs()[1];if(length)Span(h,output,length);
        if(length>16*1024*1024){Failure(j,h,EOVERFLOW);return;}
        std::vector<char> buffer(std::max<uint32_t>(length,1u));int rc=::gethostname(buffer.data(),buffer.size());
        if(!rc&&length)memcpy(Span(h,output,length),buffer.data(),length);Result(j,h,rc);
    });
    RegisterThunk("inet_addr",[](Jit& j,Host& h){
        in_addr address{};const char* text=String(h,j.Regs()[0]);j.Regs()[0]=(text&&inet_aton(text,&address))?address.s_addr:INADDR_NONE;
    });
    RegisterThunk("inet_ntoa",[](Jit& j,Host& h){
        in_addr address{};address.s_addr=j.Regs()[0];j.Regs()[0]=CachedString(h,"inet_ntoa",inet_ntoa(address));
    });
    RegisterThunk("listen",[](Jit& j,Host& h){Result(j,h,::listen(NativeFd(j.Regs()[0]),static_cast<int>(j.Regs()[1])));});
    RegisterThunk("shutdown",[](Jit& j,Host& h){Result(j,h,::shutdown(NativeFd(j.Regs()[0]),static_cast<int>(j.Regs()[1])));});
    RegisterThunk("accept",[](Jit& j,Host& h){
        const int fd=NativeFd(j.Regs()[0]);const uint32_t address=j.Regs()[1],length_ptr=j.Regs()[2];socklen_t capacity=0;
        if(length_ptr){Span(h,length_ptr,4);capacity=h.MemoryRead32(length_ptr);}sockaddr_storage storage{};socklen_t native_length=std::min<socklen_t>(capacity,sizeof(storage));
        int result=::accept(fd,address?reinterpret_cast<sockaddr*>(&storage):nullptr,length_ptr?&native_length:nullptr);
        if(result>=0&&address&&capacity){const size_t copy=std::min<size_t>(native_length,capacity);memcpy(Span(h,address,copy),&storage,copy);}
        if(result>=0&&length_ptr)h.MemoryWrite32(length_ptr,native_length);Result(j,h,result);
    });
    RegisterThunk("sendto",[](Jit& j,Host& h){
        const uint32_t destination=h.ReadStackWord(j,0);const socklen_t length=h.ReadStackWord(j,1);
        const sockaddr* address=destination?static_cast<const sockaddr*>(Span(h,destination,length)):nullptr;
        Result(j,h,::sendto(NativeFd(j.Regs()[0]),Span(h,j.Regs()[1],j.Regs()[2]),j.Regs()[2],j.Regs()[3],address,length));
    });
    RegisterThunk("recvfrom",[](Jit& j,Host& h){
        const uint32_t address_ptr=h.ReadStackWord(j,0),length_ptr=h.ReadStackWord(j,1);socklen_t capacity=0;
        if(length_ptr){Span(h,length_ptr,4);capacity=h.MemoryRead32(length_ptr);}sockaddr_storage storage{};socklen_t native_length=std::min<socklen_t>(capacity,sizeof(storage));
        sockaddr* address=address_ptr?reinterpret_cast<sockaddr*>(&storage):nullptr;
        ssize_t result=::recvfrom(NativeFd(j.Regs()[0]),Span(h,j.Regs()[1],j.Regs()[2]),j.Regs()[2],j.Regs()[3],address,length_ptr?&native_length:nullptr);
        if(result>=0&&address_ptr&&capacity)memcpy(Span(h,address_ptr,std::min<size_t>(native_length,capacity)),&storage,std::min<size_t>(native_length,capacity));
        if(result>=0&&length_ptr)h.MemoryWrite32(length_ptr,native_length);Result(j,h,result);
    });
    RegisterThunk("pread",[](Jit& j,Host& h){
        Arm32CallArgs args(j,h);const int raw_fd=static_cast<int>(args.U32());const uint32_t output=args.Ptr();const size_t count=args.U32();const off_t offset=static_cast<off_t>(args.I64());
        auto virtual_fd=LookupVirtualFd(raw_fd);
        if (virtual_fd) { std::lock_guard lock(virtual_fd->mutex); Result(j,h,AssetVfs::PRead(virtual_fd->handle.get(),Span(h,output,count),count,offset)); return; }
        Result(j,h,::pread(NativeFd(raw_fd),Span(h,output,count),count,offset));
    });
    RegisterThunk("getuid",[](Jit& j,Host&){j.Regs()[0]=static_cast<uint32_t>(::getuid());});
    RegisterThunk("getgid",[](Jit& j,Host&){j.Regs()[0]=static_cast<uint32_t>(::getgid());});
    RegisterThunk("getegid",[](Jit& j,Host&){j.Regs()[0]=static_cast<uint32_t>(::getegid());});
    RegisterThunk("sysconf",[](Jit& j,Host& h){Result(j,h,::sysconf(static_cast<int>(j.Regs()[0])));});
    RegisterThunk("fsync",[](Jit& j,Host& h){Result(j,h,::fsync(NativeFd(static_cast<int>(j.Regs()[0]))));});
    RegisterThunk("unlink",[](Jit& j,Host& h){Result(j,h,::unlink(String(h,j.Regs()[0])));});
    RegisterThunk("remove",[](Jit& j,Host& h){Result(j,h,::remove(String(h,j.Regs()[0])));});
    RegisterThunk("rename",[](Jit& j,Host& h){Result(j,h,::rename(String(h,j.Regs()[0]),String(h,j.Regs()[1])));});
    RegisterThunk("chmod",[](Jit& j,Host& h){Result(j,h,::chmod(String(h,j.Regs()[0]),static_cast<mode_t>(j.Regs()[1])));});
    RegisterThunk("clock",[](Jit& j,Host&){j.Regs()[0]=static_cast<uint32_t>(::clock());});
    RegisterThunk("pthread_attr_setstacksize",[](Jit& j,Host& h){
        const uint32_t attr=j.Regs()[0],size=j.Regs()[1];if(!attr||size<PTHREAD_STACK_MIN){j.Regs()[0]=EINVAL;return;}Span(h,attr,sizeof(Attr32));h.MemoryWrite32(attr+8,size);j.Regs()[0]=0;
    });
    RegisterThunk("pthread_attr_setdetachstate",[](Jit& j,Host& h){
        const uint32_t attr=j.Regs()[0];const int state=static_cast<int>(j.Regs()[1]);if(!attr||(state!=PTHREAD_CREATE_JOINABLE&&state!=PTHREAD_CREATE_DETACHED)){j.Regs()[0]=EINVAL;return;}Span(h,attr,sizeof(Attr32));uint32_t flags=h.MemoryRead32(attr);if(state==PTHREAD_CREATE_DETACHED)flags|=1u;else flags&=~1u;h.MemoryWrite32(attr,flags);j.Regs()[0]=0;
    });
    RegisterThunk("pthread_equal",[](Jit& j,Host&){j.Regs()[0]=j.Regs()[0]==j.Regs()[1];});
    RegisterThunk("pthread_kill",[](Jit& j,Host& h){
        const uint32_t id=j.Regs()[0];const int signal=static_cast<int>(j.Regs()[1]);j.Regs()[0]=(GetThread(id)&&(signal==0||signal>0))?0:ESRCH;
        (void)h;
    });
    RegisterThunk("bsd_signal",[](Jit& j,Host&){
        const int signal=static_cast<int>(j.Regs()[0]);const uint32_t handler=j.Regs()[1];uint32_t previous=0;
        if(signal==SIGALRM){std::lock_guard lock(g_signal_mutex);previous=g_sigalrm_action.handler;g_sigalrm_action={handler,0,0,0};}j.Regs()[0]=previous;
    });
    RegisterThunk("srand48",[](Jit& j,Host& h){Arm32CallArgs args(j,h);::srand48(static_cast<long>(args.I64()));j.Regs()[0]=0;});
    RegisterThunk("strtoll",[](Jit& j,Host& h){
        const char* text=String(h,j.Regs()[0]);const uint32_t output=j.Regs()[1];char* end=nullptr;errno=0;long long value=text?::strtoll(text,&end,static_cast<int>(j.Regs()[2])):0;
        if(output){Span(h,output,4);h.MemoryWrite32(output,end?Address(h,end):0);}if(errno)Errno(h,errno);j.Regs()[0]=static_cast<uint32_t>(value);j.Regs()[1]=static_cast<uint32_t>(static_cast<uint64_t>(value)>>32);
    });
    RegisterThunk("atol",[](Jit& j,Host& h){const char* text=String(h,j.Regs()[0]);j.Regs()[0]=text?static_cast<uint32_t>(static_cast<int32_t>(::strtol(text,nullptr,10))):0;});
    RegisterThunk("strxfrm",[](Jit& j,Host& h){const char* source=String(h,j.Regs()[2]);char* output=static_cast<char*>(j.Regs()[1]?Span(h,j.Regs()[0],j.Regs()[1]):nullptr);j.Regs()[0]=source?static_cast<uint32_t>(::strxfrm(output,source,j.Regs()[1])):0;});
    RegisterThunk("strcoll",[](Jit& j,Host& h){j.Regs()[0]=static_cast<uint32_t>(::strcoll(String(h,j.Regs()[0]),String(h,j.Regs()[1])));});
    RegisterThunk("strpbrk",[](Jit& j,Host& h){const char* result=::strpbrk(String(h,j.Regs()[0]),String(h,j.Regs()[1]));j.Regs()[0]=result?Address(h,result):0;});
    RegisterThunk("strlcpy",[](Jit& j,Host& h){
        const char* source=String(h,j.Regs()[1]);const size_t size=j.Regs()[2];const size_t length=source?strlen(source):0;
        if(size){Span(h,j.Regs()[0],size);const size_t copy=std::min(length,size-1);memcpy(Span(h,j.Regs()[0],copy),source,copy);h.MemoryWrite8(j.Regs()[0]+static_cast<uint32_t>(copy),0);}j.Regs()[0]=static_cast<uint32_t>(length);
    });
    RegisterThunk("tolower",[](Jit& j,Host&){const int c=static_cast<int32_t>(j.Regs()[0]);j.Regs()[0]=(c>=0&&c<=255)?static_cast<uint32_t>(std::tolower(c)):static_cast<uint32_t>(c);});
    RegisterThunk("isalpha",[](Jit& j,Host&){const int c=static_cast<int32_t>(j.Regs()[0]);j.Regs()[0]=(c>=0&&c<=255)?static_cast<uint32_t>(std::isalpha(c)):0;});
    RegisterThunk("isalnum",[](Jit& j,Host&){const int c=static_cast<int32_t>(j.Regs()[0]);j.Regs()[0]=(c>=0&&c<=255)?static_cast<uint32_t>(std::isalnum(c)):0;});
    RegisterThunk("isupper",[](Jit& j,Host&){const int c=static_cast<int32_t>(j.Regs()[0]);j.Regs()[0]=(c>=0&&c<=255)?static_cast<uint32_t>(std::isupper(c)):0;});
    RegisterThunk("isxdigit",[](Jit& j,Host&){const int c=static_cast<int32_t>(j.Regs()[0]);j.Regs()[0]=(c>=0&&c<=255)?static_cast<uint32_t>(std::isxdigit(c)):0;});
    RegisterThunk("wcscmp",[](Jit& j,Host& h){const uint32_t left=j.Regs()[0],right=j.Regs()[1];const size_t left_len=GuestWideLength(h,left),right_len=GuestWideLength(h,right);const wchar_t* a=static_cast<const wchar_t*>(Span(h,left,(left_len+1)*sizeof(wchar_t)));const wchar_t* b=static_cast<const wchar_t*>(Span(h,right,(right_len+1)*sizeof(wchar_t)));j.Regs()[0]=static_cast<uint32_t>(std::wcscmp(a,b));});
    RegisterThunk("wcscpy",[](Jit& j,Host& h){const uint32_t output=j.Regs()[0],source=j.Regs()[1];const size_t length=GuestWideLength(h,source);Span(h,output,(length+1)*sizeof(wchar_t));memcpy(Span(h,output,(length+1)*sizeof(wchar_t)),Span(h,source,(length+1)*sizeof(wchar_t)),(length+1)*sizeof(wchar_t));j.Regs()[0]=output;});
    RegisterThunk("wcslen",[](Jit& j,Host& h){j.Regs()[0]=static_cast<uint32_t>(GuestWideLength(h,j.Regs()[0]));});
    RegisterThunk("setlocale",[](Jit& j,Host& h){j.Regs()[0]=CachedString(h,"setlocale",::setlocale(static_cast<int>(j.Regs()[0]),String(h,j.Regs()[1])));});
    RegisterThunk("gmtime",[](Jit& j,Host& h){
        Span(h,j.Regs()[0],4);time_t value=static_cast<int32_t>(h.MemoryRead32(j.Regs()[0]));tm result{};if(!gmtime_r(&value,&result)){Errno(h,errno);j.Regs()[0]=0;return;}if(!t_cache.tm)t_cache.tm=h.GuestAlloc(sizeof(Tm32),4);if(!t_cache.tm){Errno(h,ENOMEM);j.Regs()[0]=0;return;}WriteTm(h,t_cache.tm,result);j.Regs()[0]=t_cache.tm;
    });
    RegisterThunk("localtime_r",[](Jit& j,Host& h){
        Span(h,j.Regs()[0],4);const uint32_t output=j.Regs()[1];Span(h,output,sizeof(Tm32));time_t value=static_cast<int32_t>(h.MemoryRead32(j.Regs()[0]));tm result{};if(!localtime_r(&value,&result)){Errno(h,errno);j.Regs()[0]=0;return;}WriteTm(h,output,result);j.Regs()[0]=output;
    });
    RegisterThunk("mktime",[](Jit& j,Host& h){
        const uint32_t input=j.Regs()[0];Span(h,input,sizeof(Tm32));const Tm32 guest=*static_cast<const Tm32*>(Span(h,input,sizeof(Tm32)));tm value{};value.tm_sec=guest.sec;value.tm_min=guest.min;value.tm_hour=guest.hour;value.tm_mday=guest.mday;value.tm_mon=guest.mon;value.tm_year=guest.year;value.tm_wday=guest.wday;value.tm_yday=guest.yday;value.tm_isdst=guest.isdst;time_t result=::mktime(&value);if(result>INT32_MAX||result<INT32_MIN){Failure(j,h,EOVERFLOW);return;}WriteTm(h,input,value);Result(j,h,result);
    });
    RegisterThunk("strftime",[](Jit& j,Host& h){
        const uint32_t output=j.Regs()[0],capacity=j.Regs()[1],format_ptr=j.Regs()[2],input=j.Regs()[3];if(capacity)Span(h,output,capacity);Span(h,input,sizeof(Tm32));const Tm32 guest=*static_cast<const Tm32*>(Span(h,input,sizeof(Tm32)));tm value{};value.tm_sec=guest.sec;value.tm_min=guest.min;value.tm_hour=guest.hour;value.tm_mday=guest.mday;value.tm_mon=guest.mon;value.tm_year=guest.year;value.tm_wday=guest.wday;value.tm_yday=guest.yday;value.tm_isdst=guest.isdst;const size_t result=capacity?::strftime(static_cast<char*>(Span(h,output,capacity)),capacity,String(h,format_ptr),&value):0;j.Regs()[0]=static_cast<uint32_t>(result);
    });
    RegisterThunk("strptime",[](Jit& j,Host& h){
        char* text=const_cast<char*>(String(h,j.Regs()[0]));const char* format=String(h,j.Regs()[1]);const uint32_t output=j.Regs()[2];Span(h,output,sizeof(Tm32));tm value{};char* result=(text&&format)?::strptime(text,format,&value):nullptr;if(!result){j.Regs()[0]=0;return;}WriteTm(h,output,value);j.Regs()[0]=Address(h,result);
    });
    RegisterThunk("rewind",[](Jit& j,Host& h){auto file=Lookup(g_files,j.Regs()[0]);if(file&&file->direct){std::lock_guard lock(file->mutex);(void)AssetVfs::Seek(file->direct.get(),0,SEEK_SET);j.Regs()[0]=0;return;}(void)WithFile(j.Regs()[0],EOF,[](FILE* f){rewind(f);return 0;});j.Regs()[0]=0;});
    RegisterThunk("feof",[](Jit& j,Host& h){auto file=Lookup(g_files,j.Regs()[0]);if(file&&file->direct){std::lock_guard lock(file->mutex);const off64_t position=AssetVfs::Tell(file->direct.get()),size=AssetVfs::Size(file->direct.get());j.Regs()[0]=(position>=size)?1:0;return;}Result(j,h,WithFile(j.Regs()[0],EOF,[](FILE* f){return feof(f);}));});
    RegisterThunk("getc",[](Jit& j,Host& h){auto file=Lookup(g_files,j.Regs()[0]);if(file&&file->direct){std::lock_guard lock(file->mutex);unsigned char value=0;const ssize_t n=AssetVfs::Read(file->direct.get(),&value,1);j.Regs()[0]=n==1?value:EOF;return;}Result(j,h,WithFile(j.Regs()[0],EOF,[](FILE* f){return getc(f);}));});
    RegisterThunk("putc",[](Jit& j,Host& h){auto file=Lookup(g_files,j.Regs()[1]);if(file&&file->direct){Failure(j,h,EBADF);return;}Result(j,h,WithFile(j.Regs()[1],EOF,[&](FILE* f){return putc(static_cast<int>(j.Regs()[0]),f);}));});
    RegisterThunk("ungetc",[](Jit& j,Host& h){auto file=Lookup(g_files,j.Regs()[1]);if(file&&file->direct){Failure(j,h,EBADF);return;}Result(j,h,WithFile(j.Regs()[1],EOF,[&](FILE* f){return ungetc(static_cast<int>(j.Regs()[0]),f);}));});
    RegisterThunk("fdopen",[](Jit& j,Host& h){
        const int raw_fd=static_cast<int>(j.Regs()[0]);const char* mode=String(h,j.Regs()[1]);
        if (auto virtual_fd=LookupVirtualFd(raw_fd)) {
            if (!mode || !ReadOnlyMode(mode)) { Errno(h,EBADF); j.Regs()[0]=0; return; }
            virtual_fd=TakeVirtualFd(raw_fd);
            if (!virtual_fd || !virtual_fd->handle) { Errno(h,EBADF); j.Regs()[0]=0; return; }
            const uint32_t result=AddFile(h,std::move(virtual_fd->handle),virtual_fd->label.c_str());
            if(!result)Errno(h,errno);j.Regs()[0]=result;return;
        }
        const int fd=NativeFd(raw_fd);const int duplicate=fd>=0?dup(fd):-1;FILE* stream=duplicate>=0&&mode?::fdopen(duplicate,mode):nullptr;if(!stream&&duplicate>=0)close(duplicate);const uint32_t result=AddFile(h,stream);if(!result)Errno(h,errno);j.Regs()[0]=result;
    });
    RegisterThunk("setvbuf",[](Jit& j,Host& h){
        const uint32_t file=j.Regs()[0],buffer=j.Regs()[1],size=j.Regs()[3];if(size>16*1024*1024){Failure(j,h,EOVERFLOW);return;}void* data=buffer?Span(h,buffer,size):nullptr;Result(j,h,WithFile(file,EOF,[&](FILE* f){return setvbuf(f,static_cast<char*>(data),static_cast<int>(j.Regs()[2]),size);}));
    });
    RegisterThunk("fscanf",[](Jit& j,Host& h){
        VarArgs args(j,h,2);const int result=WithFile(j.Regs()[0],EOF,[&](FILE* f){return Scan(h, f?([&](){std::string input;char buffer[4096];while(fgets(buffer,sizeof(buffer),f))input+=buffer;return input;}().c_str()):nullptr, String(h,j.Regs()[1]),args);});j.Regs()[0]=result;
    });
    RegisterThunk("vfprintf",[](Jit& j,Host& h){
        VarArgs args(j,h,j.Regs()[2],true);const std::string text=Format(h,String(h,j.Regs()[1]),args);Result(j,h,WithFile(j.Regs()[0],-1,[&](FILE* f){return LogWrite(f,text.data(),text.size());}));
    });
    RegisterThunk("div",[](Jit& j,Host& h){
        // AAPCS32 returns the two-word div_t aggregate through a hidden
        // pointer in r0. The explicit numerator and denominator are r1/r2.
        const uint32_t output=j.Regs()[0];
        const int numerator=static_cast<int32_t>(j.Regs()[1]);
        const int denominator=static_cast<int32_t>(j.Regs()[2]);
        const div_t value=::div(numerator,denominator);
        static_assert(sizeof(div_t)==8);
        memcpy(Span(h,output,sizeof(value)),&value,sizeof(value));
    });
    RegisterThunk("sinh",[](Jit& j,Host&){WriteDF(j,0,std::sinh(ReadDF(j,0)));});
    RegisterThunk("cosh",[](Jit& j,Host&){WriteDF(j,0,std::cosh(ReadDF(j,0)));});
    RegisterThunk("tanh",[](Jit& j,Host&){WriteDF(j,0,std::tanh(ReadDF(j,0)));});
    RegisterThunk("sqrt",[](Jit& j,Host&){WriteDF(j,0,std::sqrt(ReadDF(j,0)));});
    RegisterThunk("atan",[](Jit& j,Host&){WriteDF(j,0,std::atan(ReadDF(j,0)));});
    RegisterThunk("atan2",[](Jit& j,Host&){WriteDF(j,0,std::atan2(ReadDF(j,0),ReadDF(j,1)));});
    RegisterThunk("ldexp",[](Jit& j,Host&){WriteDF(j,0,std::ldexp(ReadDF(j,0),static_cast<int>(j.Regs()[2])));});
    RegisterThunk("modf",[](Jit& j,Host& h){const uint32_t output=j.Regs()[2];Span(h,output,8);double integral=0;const double fraction=std::modf(ReadDF(j,0),&integral);memcpy(Span(h,output,8),&integral,8);WriteDF(j,0,fraction);});
    RegisterThunk("frexp",[](Jit& j,Host& h){const uint32_t output=j.Regs()[2];Span(h,output,4);int exponent=0;const double value=std::frexp(ReadDF(j,0),&exponent);h.MemoryWrite32(output,static_cast<uint32_t>(exponent));WriteDF(j,0,value);});
    RegisterThunk("swprintf",[](Jit& j,Host& h){
        const uint32_t output=j.Regs()[0],capacity=j.Regs()[1],format_ptr=j.Regs()[2];if(!capacity){j.Regs()[0]=0;return;}const size_t format_length=GuestWideLength(h,format_ptr);const wchar_t* format=static_cast<const wchar_t*>(Span(h,format_ptr,(format_length+1)*sizeof(wchar_t)));VarArgs args(j,h,3);std::wstring result;for(size_t i=0;i<format_length;++i){if(format[i]!=L'%'){result.push_back(format[i]);continue;}if(++i>=format_length)break;const wchar_t conversion=format[i];if(conversion==L'%'){result.push_back(L'%');continue;}if(conversion==L'd'||conversion==L'i')result+=std::to_wstring(static_cast<int32_t>(args.U32()));else if(conversion==L'u')result+=std::to_wstring(args.U32());else if(conversion==L'x'||conversion==L'X')result+=std::to_wstring(args.U32());else if(conversion==L'c')result.push_back(static_cast<wchar_t>(args.U32()));else if(conversion==L's'){const uint32_t text=args.U32();const size_t length=GuestWideLength(h,text);result.append(static_cast<const wchar_t*>(Span(h,text,(length+1)*sizeof(wchar_t))),length);}else if(conversion==L'f'||conversion==L'e'||conversion==L'g'){wchar_t spec[]={L'%',conversion,L'\0'};wchar_t formatted[128]{};const int count=std::swprintf(formatted,128,spec,args.F64());if(count<0||count>=128)Invalid("swprintf floating conversion exceeds bound");result.append(formatted,static_cast<size_t>(count));}else result.push_back(conversion);}const size_t count=std::min<size_t>(result.size(),capacity-1);Span(h,output,(count+1)*sizeof(wchar_t));memcpy(Span(h,output,(count+1)*sizeof(wchar_t)),result.data(),count*sizeof(wchar_t));h.MemoryWrite32(output+static_cast<uint32_t>(count*sizeof(wchar_t)),0);j.Regs()[0]=static_cast<uint32_t>(result.size());
    });
    SelfCheck();
}
