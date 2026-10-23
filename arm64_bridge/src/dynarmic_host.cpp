// SPDX-License-Identifier: GPL-3.0-or-later
#include "dynarmic_host.h"
#include "elf_loader.h"
#include "thunk_manager.h"
#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cinttypes>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <stdexcept>
#include <android/asset_manager.h>
#include <android/log.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define LOG_TAG "Asphalt7Bridge_Host"
#if defined(ASPHALT7_FINAL_SILENT)
#define LOGI(...) ((void)0)
#define LOGE(...) ((void)0)
#else
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#endif

namespace {
constexpr uint32_t kExitArm = 4;
constexpr uint32_t kExitThumb = 8;
constexpr uint32_t kBlockMagic = 0x41524D31;
constexpr uint32_t kFreedMagic = 0x41524D46;
constexpr uint32_t kHeaderSize = 16;
constexpr uint32_t kMainGuestBase = 0x40000000;
constexpr uint32_t kGraphicsIdleBranch = kMainGuestBase + 0x2A9CDC;
constexpr uint32_t kGraphicsSleep = kMainGuestBase + 0x272FF8;
constexpr uint32_t kGraphicsIdleLoop = kMainGuestBase + 0x2A9CA8;
constexpr uint32_t kGraphicsIdleStub = 0x40410000;
constexpr uint32_t kGraphicsIdleBranchBefore = 0x0AFFFFF1;
constexpr uint32_t kGraphicsIdleSleepUsec = 1000;
constexpr uint32_t kKuserCmpxchg64 = 0xFFFF0F60;
constexpr uint32_t kKuserMemoryBarrier = 0xFFFF0FA0;
constexpr uint32_t kKuserCmpxchg = 0xFFFF0FC0;
constexpr uint32_t kKuserGetTls = 0xFFFF0FE0;
constexpr uint32_t kKuserHelperVersion = 0xFFFF0FFC;

bool IsKuserHelperAddress(uint32_t address) {
    const uint32_t pc = address & ~1u;
    return pc == kKuserCmpxchg64 || pc == kKuserCmpxchg64 + 4 ||
           pc == kKuserMemoryBarrier || pc == kKuserMemoryBarrier + 4 ||
           pc == kKuserCmpxchg || pc == kKuserCmpxchg + 4 ||
           pc == kKuserGetTls || pc == kKuserGetTls + 4 ||
           pc == kKuserHelperVersion || pc == 0xFFFF1000;
}

std::optional<uint32_t> KuserInstruction(uint32_t address, ThunkManager* manager) {
    const uint32_t pc = address & ~1u;
    const auto syscall = [&](const char* name) -> std::optional<uint32_t> {
        if (!manager) return std::nullopt;
        const uint32_t id = manager->FindRegisteredThunkId(name);
        if (!id || id > 0x00FFFFFFu) return std::nullopt;
        return 0xEF000000u | id;
    };
    if (pc == kKuserMemoryBarrier) return syscall("__kuser_memory_barrier");
    if (pc == kKuserCmpxchg) return syscall("__kuser_cmpxchg");
    if (pc == kKuserGetTls) return syscall("__kuser_get_tls");
    if (pc == kKuserCmpxchg64) return syscall("__kuser_cmpxchg64");
    if (pc == kKuserHelperVersion) return 0xE3A00005u;
    if (pc == 0xFFFF1000u || pc == kKuserMemoryBarrier + 4 ||
        pc == kKuserCmpxchg + 4 || pc == kKuserGetTls + 4 ||
        pc == kKuserCmpxchg64 + 4) {
        return 0xE12FFF1Eu; // bx lr
    }
    return std::nullopt;
}

constexpr uint32_t EncodeArmBranch(uint32_t from, uint32_t target, uint32_t opcode) {
    const int64_t delta = int64_t(target) - (int64_t(from) + 8);
    return (delta % 4 || delta < -0x02000000LL || delta > 0x01FFFFFCLL)
        ? 0
        : opcode | (static_cast<uint32_t>(delta >> 2) & 0x00FFFFFFu);
}
static_assert(EncodeArmBranch(0x2A9CDC, 0x2A9CA8, 0x0A000000) == kGraphicsIdleBranchBefore);

bool PowerOfTwo(size_t value) { return value && !(value & (value - 1)); }

struct AssetMapping {
    const char* name = nullptr;
    int fd = -1;
    void* mapping = MAP_FAILED;
    size_t span = 0;
    const uint8_t* data = nullptr;
    size_t size = 0;

    bool Open(AAssetManager* manager, const char* asset_name, size_t page_size, uint32_t guest_base) {
        name = asset_name;
        AAsset* asset = AAssetManager_open(manager, name, AASSET_MODE_RANDOM);
        if (!asset) { LOGE("Missing guest asset: %s", name); return false; }
        off64_t offset = 0, length = 0;
        const int source_fd = AAsset_openFileDescriptor64(asset, &offset, &length);
        AAsset_close(asset);
        if (source_fd < 0) { LOGE("Guest asset must be STORED with a real APK fd: %s", name); return false; }
        fd = dup(source_fd);
        const int source_close = close(source_fd);
        if (fd < 0 || source_close != 0) { LOGE("Guest APK fd dup/close failed: %s", name); return false; }
        struct stat statbuf{};
        if (fstat(fd, &statbuf) != 0 || offset < 0 || length <= 0 || statbuf.st_size < 0 ||
            uint64_t(offset) > uint64_t(statbuf.st_size) || uint64_t(length) > uint64_t(statbuf.st_size) - uint64_t(offset)) {
            LOGE("Guest APK fd range failed: %s", name); return false;
        }
        const uint64_t aligned = uint64_t(offset) & ~(uint64_t(page_size) - 1);
        const size_t bias = uint64_t(offset) - aligned;
        if (uint64_t(length) > SIZE_MAX - bias) { LOGE("Guest mapping length overflow: %s", name); return false; }
        span = size_t(length) + bias;
        mapping = mmap(nullptr, span, PROT_READ, MAP_PRIVATE, fd, off_t(aligned));
        if (mapping == MAP_FAILED) { LOGE("Guest mmap failed: %s errno=%d", name, errno); return false; }
        data = static_cast<const uint8_t*>(mapping) + bias;
        size = size_t(length);
        LOGI("guest mmap: asset=%s fd=%d offset=%llu size=%zu -> 0x%08x (map=%p bias=%zu page=%zu)",
             name, fd, static_cast<unsigned long long>(offset), size, guest_base, mapping, bias, page_size);
        return true;
    }
    bool Close() {
        bool ok = true;
        if (mapping != MAP_FAILED) {
            const int result = munmap(mapping, span);
            LOGI("guest munmap: asset=%s size=%zu result=%d", name, span, result);
            ok = result == 0;
            mapping = MAP_FAILED;
        }
        if (fd >= 0) {
            const int old_fd = fd;
            fd = -1; // close must not be retried: Linux may have already reused an EINTR descriptor.
            const int result = close(old_fd);
            LOGI("guest close: asset=%s fd=%d result=%d", name, old_fd, result);
            ok = (result == 0) && ok;
        }
        return ok;
    }
    ~AssetMapping() { Close(); }
};
}

void GuestSyncForget(uint32_t addr, uint32_t size);
void GuestLibcThreadExit(DynarmicHost& host);

struct DynarmicHost::ThreadState {
    DynarmicHost* owner = nullptr;
    uint32_t slot = kMaxThreads;
    uint32_t stack_bottom = 0;
    uint32_t stack_top = 0;
    uint32_t errno_addr = 0;
    uint32_t fpscr = 0;
    size_t depth = 0;
    Dynarmic::A32::Jit* active = nullptr;
    bool exiting = false;
    uint32_t exit_value = 0;
    std::array<std::unique_ptr<Dynarmic::A32::Jit>, kMaxDepth> jits;
    ~ThreadState() { if (owner) owner->RetireThread(*this); }
};
thread_local std::unique_ptr<DynarmicHost::ThreadState> DynarmicHost::t_thread;

DynarmicHost::DynarmicHost() = default;
DynarmicHost::~DynarmicHost() {
    ReleaseCurrentThread();
    {
        std::lock_guard<std::mutex> lock(m_jits_mutex);
        if (m_stack_slots.any()) {
            LOGE("Host destroyed while guest threads remain");
            std::abort();
        }
    }
    if (m_memory) munmap(m_memory, m_memory_size);
}

bool DynarmicHost::Initialize() {
    if (m_memory) return false;
    const long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0 || !PowerOfTwo(page_size) || size_t(page_size) >= kStackSize) return false;
    m_page_size = size_t(page_size);
    m_memory_size = GUEST_ADDRESS_SPACE;
    void* memory = mmap(nullptr, m_memory_size, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (memory == MAP_FAILED) { m_memory_size = 0; LOGE("Cannot reserve guest 4-GiB address space"); return false; }
    m_memory = static_cast<uint8_t*>(memory);
    m_monitor = std::make_unique<Dynarmic::ExclusiveMonitor>(kMaxJits);
    m_config.callbacks = this;
    m_config.global_monitor = m_monitor.get();
    m_config.arch_version = Dynarmic::A32::ArchVersion::v7;
    m_config.enable_cycle_counting = false;
    m_config.always_little_endian = true;
    m_config.define_unpredictable_behaviour = true;
    m_config.fastmem_pointer = reinterpret_cast<uintptr_t>(m_memory);
    m_config.code_cache_size = 16 * 1024 * 1024;
    // ponytail: this backend does not invalidate live RSB entries on cache rollover; re-enable after generation/reset handling.
    m_config.optimizations &= ~Dynarmic::OptimizationFlag::ReturnStackBuffer;
    MemoryWrite32(kExitArm, 0xEF000000);
    MemoryWrite16(kExitThumb, 0xDF00);
    AddExecutableRange(kExitArm, 4);
    AddExecutableRange(kExitThumb, 2);
    if (!HeapSelfCheck() || !ElfLoader::SelfCheck(m_memory, m_memory_size)) {
        Fail("Startup heap/ELF self-check failed"); return false;
    }
    m_thunk_manager = std::make_unique<ThunkManager>(*this);
    m_thunk_manager->RegisterAllThunks();
    if (!RuntimeSelfCheck()) { Fail("Startup JIT self-check failed"); return false; }
    LOGI("Dynarmic Host initialized: AArch64 host, A32 guest, %zu bytes, page=%zu, per-thread JIT", m_memory_size, m_page_size);
    return true;
}

bool DynarmicHost::LoadGuestLibraries(AAssetManager* assets) {
    if (!assets || !m_memory || !m_libraries.empty() || HasFailed()) return false;
    struct Input { const char* name; const char* asset; uint32_t base; uint32_t limit; };
    const Input inputs[] = {
        {"libAndroid.so", "guest_libs/libAndroid.so", 0x40000000, 0x42000000},
    };
    m_libraries.reserve(1);
    for (const auto& input : inputs) {
        AssetMapping mapping;
        if (!mapping.Open(assets, input.asset, m_page_size, input.base)) {
            mapping.Close(); Fail("Direct guest asset mapping failed"); return false;
        }
        auto elf = std::make_unique<ElfLoader>(m_memory, m_memory_size, input.base, input.limit);
        const bool loaded = elf->LoadFromMemory(mapping.data, mapping.size);
        const bool released = mapping.Close();
        if (!loaded || !released) { Fail("Guest parse/mapping release failed"); return false; }
        for (const auto& previous : m_libraries) {
            if (uint64_t(elf->GetBaseAddress()) < uint64_t(previous.elf->GetBaseAddress()) + previous.elf->GetImageSize() &&
                uint64_t(previous.elf->GetBaseAddress()) < uint64_t(elf->GetBaseAddress()) + elf->GetImageSize()) {
                Fail("Guest ELF address overlap"); return false;
            }
        }
        m_libraries.push_back({input.name, std::move(elf), false});
    }
    const std::array<std::string, 9> system_libraries = {
        "libc.so", "libm.so", "libdl.so", "liblog.so", "libstdc++.so", "libGLESv2.so", "libEGL.so", "libz.so", "libandroid.so"
    };
    for (size_t index = 0; index < m_libraries.size(); ++index) {
        const auto& library = m_libraries[index];
        for (const auto& needed : library.elf->GetNeededLibraries()) {
            const bool known_system = std::find(system_libraries.begin(), system_libraries.end(), needed) != system_libraries.end();
            const bool known_guest = std::any_of(m_libraries.begin(), m_libraries.begin() + index,
                                                [&](const Library& prior) { return prior.name == needed; });
            if (!known_system && !known_guest) {
                LOGE("Unsupported dependency %s needed by %s", needed.c_str(), library.name.c_str());
                Fail("Guest dependency order/closure failed"); return false;
            }
        }
        auto resolver = [&](const std::string& name, uint8_t type) -> uint32_t {
            // Defined local symbols are handled by ElfLoader. Imm cannot borrow main's uninitialized exports.
            if (uint32_t address = m_thunk_manager->ResolveSymbol(name, type)) return address;
            for (size_t prior = 0; prior < index; ++prior)
                if (uint32_t address = m_libraries[prior].elf->GetSymbolAddress(name, type)) return address;
            return 0;
        };
        if (!library.elf->Relocate(resolver)) { Fail("Typed guest import closure failed"); return false; }
        for (const auto& segment : library.elf->GetSegments())
            if (segment.flags & PF_X) InvalidateGuestCode(library.elf->GetBaseAddress() + segment.vaddr, segment.filesz);
    }
    m_libraries_ready.store(true);
    LOGI("Asphalt guest ELF mapped/relocated; constructors intentionally deferred");
    return true;
}

bool DynarmicHost::PatchGraphicsIdleLoop() {
    // Reserved for an Asphalt-specific, signature-gated pacing overlay.  The
    // Conduit address patch is intentionally not carried into this bridge.
    return true;
}

bool DynarmicHost::RunLibraryConstructors(const std::string& name) {
    if (!m_libraries_ready.load() || HasFailed()) return false;
    for (auto& library : m_libraries) {
        if (library.name != name) continue;
        if (library.constructors_ran) return false;
        for (uint32_t function : library.elf->GetInitArray()) {
            if (!IsExecutableAddress(function)) { Fail("Initializer is not executable guest code"); return false; }
            RunFunction(function);
            if (HasFailed()) return false;
        }
        library.constructors_ran = true;
        LOGI("Guest constructors complete: %s (%zu)", name.c_str(), library.elf->GetInitArray().size());
        return true;
    }
    return false;
}

uint32_t DynarmicHost::FindLibrarySymbol(const std::string& library_name, const std::string& symbol) const {
    if (!m_libraries_ready.load()) return 0;
    for (const auto& library : m_libraries)
        if (library.name == library_name) return library.elf->GetSymbolAddress(symbol);
    return 0;
}

uint32_t DynarmicHost::FindSymbol(const std::string& name) {
    if (m_libraries_ready.load()) {
        // Main library has process-facing precedence; dependency relocation has its own checked scope.
        for (auto it = m_libraries.rbegin(); it != m_libraries.rend(); ++it)
            if (uint32_t address = it->elf->GetSymbolAddress(name)) return address;
    }
    return m_thunk_manager ? m_thunk_manager->FindRegisteredSymbol(name) : 0;
}

DynarmicHost::ThreadState& DynarmicHost::EnsureThread() {
    if (t_thread) {
        if (t_thread->owner != this) { LOGE("Multiple guest hosts on one thread"); std::abort(); }
        return *t_thread;
    }
    auto thread = std::make_unique<ThreadState>();
    thread->owner = this;
    {
        std::lock_guard<std::mutex> lock(m_jits_mutex);
        for (size_t slot = 0; slot < kMaxThreads; ++slot) {
            if (!m_stack_slots[slot]) { m_stack_slots.set(slot); thread->slot = slot; break; }
        }
    }
    if (thread->slot == kMaxThreads) { LOGE("Guest thread pool exhausted"); std::abort(); }
    const uint32_t bottom = kStackBase + thread->slot * kStackStride;
    thread->stack_bottom = bottom + m_page_size;
    thread->stack_top = bottom + kStackSize;
    if (mprotect(m_memory + bottom, m_page_size, PROT_NONE) != 0 ||
        mprotect(m_memory + thread->stack_top, m_page_size, PROT_NONE) != 0) {
        LOGE("Could not protect guest stack guards"); std::abort();
    }
    thread->errno_addr = GuestAlloc(4);
    if (!thread->errno_addr) { LOGE("Could not allocate thread errno"); std::abort(); }
    t_thread = std::move(thread);
    return *t_thread;
}

Dynarmic::A32::Jit& DynarmicHost::EnsureJit(ThreadState& thread, size_t depth) {
    if (depth >= kMaxDepth) { LOGE("Guest nested JIT depth exhausted"); std::abort(); }
    if (!thread.jits[depth]) {
        auto config = m_config;
        const size_t id = thread.slot * kMaxDepth + depth;
        config.processor_id = id;
        auto jit = std::make_unique<Dynarmic::A32::Jit>(config);
        {
            std::lock_guard<std::mutex> lock(m_jits_mutex);
            m_monitor->ClearProcessor(id);
            m_live_jits[id] = jit.get();
            thread.jits[depth] = std::move(jit);
        }
    }
    return *thread.jits[depth];
}

Dynarmic::A32::Jit& DynarmicHost::CurrentJit() {
    auto& thread = EnsureThread();
    return thread.active ? *thread.active : EnsureJit(thread, 0);
}

uint32_t DynarmicHost::ReadStackWord(Dynarmic::A32::Jit& jit, uint32_t spilled_word_index) {
    if (!t_thread || t_thread->owner != this || t_thread->active != &jit || !t_thread->depth)
        throw std::out_of_range("Stack read requires this thread's active guest JIT");
    const uint64_t sp = jit.Regs()[13];
    const uint64_t address = sp + uint64_t(spilled_word_index) * sizeof(uint32_t);
    if ((sp & 3) || sp < t_thread->stack_bottom || sp > t_thread->stack_top ||
        address < t_thread->stack_bottom || address + sizeof(uint32_t) > t_thread->stack_top ||
        address + sizeof(uint32_t) > m_memory_size)
        throw std::out_of_range("Guest argument lies outside the active thread's usable stack");
    uint32_t value;
    memcpy(&value, m_memory + address, sizeof(value));
    return value;
}

bool DynarmicHost::IsJitRunning() const {
    return t_thread && t_thread->owner == this && t_thread->depth != 0;
}

uint32_t DynarmicHost::GuestErrnoAddress() { return EnsureThread().errno_addr; }

void DynarmicHost::RetireThread(ThreadState& thread) {
    if (thread.depth) { LOGE("Attempted to free executing guest thread"); std::abort(); }
    if (thread.slot == kMaxThreads) return;
    {
        std::lock_guard<std::mutex> lock(m_jits_mutex);
        for (size_t depth = 0; depth < kMaxDepth; ++depth) {
            const size_t id = thread.slot * kMaxDepth + depth;
            m_live_jits[id] = nullptr;
            m_monitor->ClearProcessor(id);
        }
    }
    for (auto& jit : thread.jits) jit.reset();
    GuestFree(thread.errno_addr);
    const uint32_t bottom = kStackBase + thread.slot * kStackStride;
    if (madvise(m_memory + bottom, kStackStride, MADV_DONTNEED) != 0) Fail("Guest stack discard failed");
    std::lock_guard<std::mutex> lock(m_jits_mutex);
    m_stack_slots.reset(thread.slot);
}

void DynarmicHost::ReleaseCurrentThread() {
    if (!t_thread || t_thread->owner != this) return;
    if (t_thread->depth) { Fail("Guest thread release while executing"); return; }
    BeginThreadCleanup();
    GuestLibcThreadExit(*this);
    t_thread.reset();
}

bool DynarmicHost::IsCurrentGuestThreadExiting() const {
    return t_thread && t_thread->owner == this && t_thread->exiting;
}

void DynarmicHost::BeginThreadCleanup() {
    if (!t_thread || t_thread->owner != this) return;
    if (t_thread->depth) { Fail("Thread cleanup attempted inside guest execution"); return; }
    t_thread->exiting = false;
    for (auto& jit : t_thread->jits)
        if (jit) jit->ClearHalt(Dynarmic::HaltReason::UserDefined1);
}

void DynarmicHost::ExitCurrentGuestThread(uint32_t result) {
    auto& thread = EnsureThread();
    thread.exiting = true;
    thread.exit_value = result;
    for (auto& jit : thread.jits)
        if (jit) jit->HaltExecution(Dynarmic::HaltReason::UserDefined1);
}

void DynarmicHost::Fail(const char* reason) {
    if (!m_failed.exchange(true)) {
#if defined(ASPHALT7_FAILURE_TELEMETRY)
        __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "Bridge FAILED: %s", reason);
#else
        LOGE("Bridge FAILED: %s", reason);
#endif
    }
    std::lock_guard<std::mutex> lock(m_jits_mutex);
    for (auto* jit : m_live_jits)
        if (jit) jit->HaltExecution(Dynarmic::HaltReason::UserDefined2);
}

uint32_t DynarmicHost::RunFunction(uint32_t target, const std::vector<uint32_t>& args) {
    if (HasFailed() || !m_memory) return 0;
    if (!IsExecutableAddress(target)) { Fail("Guest entry is not executable"); return 0; }
    auto& thread = EnsureThread();
    if (thread.exiting) return thread.exit_value;
    const size_t depth = thread.depth;
    auto& jit = EnsureJit(thread, depth);
    auto* outer = thread.active;
    const uint32_t old_sp = outer ? outer->Regs()[13] : thread.stack_top;
    if (old_sp < thread.stack_bottom || old_sp > thread.stack_top || (depth && old_sp - thread.stack_bottom < 256)) {
        Fail("Invalid guest stack at call boundary"); return 0;
    }
    const uint32_t top = depth ? old_sp - 256 : thread.stack_top;
    const uint64_t extra = args.size() > 4 ? uint64_t(args.size() - 4) * 4 : 0;
    if (extra > uint64_t(top) - thread.stack_bottom) { Fail("Guest arguments exceed stack"); return 0; }
    const uint32_t sp = (top - uint32_t(extra)) & ~7u;
    if (sp < thread.stack_bottom) { Fail("Guest argument alignment crosses stack guard"); return 0; }
    jit.Regs().fill(0);
    jit.ExtRegs().fill(0);
    jit.SetCpsr(0x10 | ((target & 1) ? 0x20 : 0));
    jit.SetFpscr(outer ? outer->Fpscr() : thread.fpscr);
    jit.ClearExclusiveState();
    m_monitor->ClearProcessor(thread.slot * kMaxDepth + depth);
    for (size_t i = 0; i < std::min(args.size(), size_t(4)); ++i) jit.Regs()[i] = args[i];
    for (size_t i = 4; i < args.size(); ++i) MemoryWrite32(sp + uint32_t(i - 4) * 4, args[i]);
    jit.Regs()[13] = sp;
    jit.Regs()[14] = (target & 1) ? (kExitThumb | 1) : kExitArm;
    jit.Regs()[15] = target & ~1u;
    thread.active = &jit;
    ++thread.depth;
    // No host registry/allocator/JIT lock is held over Run or a blocking/reentrant thunk.
    for (;;) {
        const auto reason = jit.Run();
        if (thread.exiting || HasFailed()) break;
        const uint32_t bits = static_cast<uint32_t>(reason);
        const uint32_t cache = static_cast<uint32_t>(Dynarmic::HaltReason::CacheInvalidation);
        if (bits && !(bits & ~cache)) continue;
        const uint32_t pc = jit.Regs()[15];
        const uint32_t returned = static_cast<uint32_t>(Dynarmic::HaltReason::UserDefined1);
        if ((bits & returned) && !(bits & ~(cache | returned)) &&
            (pc == kExitArm || pc == kExitArm + 4 || pc == kExitThumb || pc == kExitThumb + 2)) break;
        LOGE("Unexpected guest halt: entry=0x%08x PC=0x%08x LR=0x%08x reason=0x%x", target, pc, jit.Regs()[14], bits);
        Fail("Unexpected guest halt"); break;
    }
    thread.fpscr = jit.Fpscr();
    if (outer) outer->SetFpscr(thread.fpscr);
    const uint32_t result = thread.exiting ? thread.exit_value : jit.Regs()[0];
    --thread.depth;
    thread.active = outer;
    return result;
}

uint32_t DynarmicHost::CallGuestNested(uint32_t target, const std::vector<uint32_t>& args) {
    return RunFunction(target, args);
}

void DynarmicHost::InvalidateGuestCode(uint32_t address, size_t size) {
    std::lock_guard<std::mutex> lock(m_jits_mutex);
    for (auto* jit : m_live_jits)
        if (jit) jit->InvalidateCacheRange(address, size);
}

uint32_t DynarmicHost::GuestAlloc(size_t size, size_t alignment) {
    if (!PowerOfTwo(alignment) || size > kHeapLimit - kHeapBase || alignment > kHeapLimit - kHeapBase) return 0;
    if (!size) size = 1;
    alignment = std::max(alignment, size_t(8));
    const uint64_t need = uint64_t(size) + alignment + kHeaderSize;
    if (need > kHeapLimit - kHeapBase) return 0;
    std::lock_guard<std::mutex> lock(m_heap_mutex);
    uint32_t base = 0, capacity = 0;
    if (need <= kMaxClassSize) {
        int cls = 0;
        while ((1u << (cls + kMinClassShift)) < need) ++cls;
        capacity = 1u << (cls + kMinClassShift);
        auto& list = m_free_small[cls];
        if (!list.empty()) { base = list.back(); list.pop_back(); }
    } else {
        capacity = uint32_t((need + 15) & ~15ull);
        auto found = m_free_huge.find(capacity);
        if (found != m_free_huge.end() && !found->second.empty()) {
            base = found->second.back(); found->second.pop_back();
        }
    }
    const bool reused = base != 0;
    if (!base) {
        if (uint64_t(m_heap_current) + capacity > kHeapLimit) {
            uint64_t free_capacity = 0;
            for (int index = 0; index < kNumSizeClasses; ++index)
                free_capacity += uint64_t(m_free_small[index].size()) << (index + kMinClassShift);
            for (const auto& [free_capacity_class, blocks] : m_free_huge)
                free_capacity += uint64_t(free_capacity_class) * blocks.size();
            uint32_t pc = 0, lr = 0, sp = 0, stack0 = 0, stack1 = 0, stack2 = 0, stack3 = 0;
            if (IsJitRunning()) {
                auto& jit = CurrentJit(); pc = jit.Regs()[15]; lr = jit.Regs()[14]; sp = jit.Regs()[13];
                if (uint64_t(sp) + 16 <= m_memory_size) {
                    stack0 = MemoryRead32(sp); stack1 = MemoryRead32(sp + 4);
                    stack2 = MemoryRead32(sp + 8); stack3 = MemoryRead32(sp + 12);
                }
            }
            LOGE("Guest heap exhausted: request=%zu alignment=%zu capacity=%u current=0x%08x limit=0x%08x live=%" PRIu64 " free_cached=%" PRIu64 " allocs=%" PRIu64 " frees=%" PRIu64 " rejected_frees=%" PRIu64 " pc=0x%08x lr=0x%08x sp=0x%08x stack=%08x,%08x,%08x,%08x",
                 size, alignment, capacity, m_heap_current, kHeapLimit, m_heap_live_capacity,
                 free_capacity, m_heap_alloc_count, m_heap_free_count, m_heap_rejected_free_count,
                 pc, lr, sp, stack0, stack1, stack2, stack3);
            return 0;
        }
        base = m_heap_current;
        m_heap_current += capacity;
    }
    m_heap_live_capacity += capacity;
    ++m_heap_alloc_count;
    const uint32_t payload = uint32_t((uint64_t(base) + kHeaderSize + alignment - 1) & ~(uint64_t(alignment) - 1));
    if (reused) memset(m_memory + payload, 0, size);
    MemoryWrite32(payload - 16, kBlockMagic);
    MemoryWrite32(payload - 12, base);
    MemoryWrite32(payload - 8, capacity);
    MemoryWrite32(payload - 4, uint32_t(size));
    return payload;
}

bool DynarmicHost::ValidAllocation(uint32_t address) const {
    if (address < kHeapBase + kHeaderSize || address >= m_heap_current) return false;
    uint32_t header[4]; memcpy(header, m_memory + address - kHeaderSize, sizeof(header));
    const uint32_t base = header[1], capacity = header[2], size = header[3];
    return header[0] == kBlockMagic && base >= kHeapBase && (base & 15) == 0 &&
           capacity >= (1u << kMinClassShift) && !(capacity & 15) &&
           (capacity > kMaxClassSize || PowerOfTwo(capacity)) &&
           uint64_t(base) + capacity <= m_heap_current && address >= base + kHeaderSize &&
           size && uint64_t(address) + size <= uint64_t(base) + capacity;
}

void DynarmicHost::GuestFree(uint32_t address) {
    // The C/POSIX free contract explicitly permits free(NULL).  The guest
    // libc calls free(0) during normal optional-resource/error cleanup, so it
    // must not be treated as a corrupt guest allocation.
    if (!address) return;
    uint32_t base, capacity, size;
    {
        std::lock_guard<std::mutex> lock(m_heap_mutex);
        if (!ValidAllocation(address)) {
            ++m_heap_rejected_free_count;
            if (m_heap_rejected_free_count <= 32 || (m_heap_rejected_free_count & (m_heap_rejected_free_count - 1)) == 0) {
                uint32_t pc = 0, lr = 0;
                if (IsJitRunning()) { auto& jit = CurrentJit(); pc = jit.Regs()[15]; lr = jit.Regs()[14]; }
                LOGE("GuestFree rejected: address=0x%08x count=%" PRIu64 " pc=0x%08x lr=0x%08x",
                     address, m_heap_rejected_free_count, pc, lr);
            }
            return;
        }
        base = MemoryRead32(address - 12); capacity = MemoryRead32(address - 8); size = MemoryRead32(address - 4);
        MemoryWrite32(address - 16, kFreedMagic);
        m_heap_live_capacity -= capacity;
        ++m_heap_free_count;
    }
    // Retire address-keyed synchronization before another allocator can recycle this block.
    GuestSyncForget(address, size);
    std::lock_guard<std::mutex> lock(m_heap_mutex);
    if (capacity <= kMaxClassSize) {
        int cls = 0;
        while ((1u << (cls + kMinClassShift)) < capacity) ++cls;
        m_free_small[cls].push_back(base);
    } else m_free_huge[capacity].push_back(base);
}

uint32_t DynarmicHost::GuestAllocSize(uint32_t address) {
    std::lock_guard<std::mutex> lock(m_heap_mutex);
    return ValidAllocation(address) ? MemoryRead32(address - 4) : 0;
}

uint32_t DynarmicHost::GuestAllocMapping(size_t size, size_t alignment) {
    if (!size || !PowerOfTwo(alignment)) return 0;
    std::lock_guard<std::mutex> lock(m_heap_mutex);
    const uint64_t aligned = (uint64_t(m_map_current) + alignment - 1) & ~(uint64_t(alignment) - 1);
    if (aligned >= kMapLimit || size > kMapLimit - aligned) return 0;
    m_map_current = uint32_t(aligned + size);
    return uint32_t(aligned);
}

bool DynarmicHost::HeapSelfCheck() {
    bool ok = true;
#define CHECK_HEAP(test) do { if (!(test)) { LOGE("HeapSelfCheck FAILED: %s", #test); ok = false; } } while (0)
    const uint32_t a = GuestAlloc(100), b = GuestAlloc(100), aligned = GuestAlloc(64, 0x1000);
    CHECK_HEAP(a && b && a != b && !(a & 7) && !(b & 7));
    CHECK_HEAP(a + 100 <= b - kHeaderSize || b + 100 <= a - kHeaderSize);
    CHECK_HEAP(aligned && !(aligned & 0xFFF));
    CHECK_HEAP(GuestAllocSize(a) == 100);
    MemoryWrite32(a, 0xDEADBEEF); GuestFree(a);
    CHECK_HEAP(GuestAllocSize(a) == 0 && !ValidAllocation(a));
    const uint32_t reused = GuestAlloc(100);
    CHECK_HEAP(reused == a && MemoryRead32(reused) == 0);
    CHECK_HEAP(!ValidAllocation(0x40000000));
    CHECK_HEAP(!ValidAllocation(kHeapBase + 4));
    CHECK_HEAP(!ValidAllocation(b + 8));
    CHECK_HEAP(GuestAllocSize(b) == 100);
    const uint32_t big = GuestAlloc(8 * 1024 * 1024, 0x10000);
    CHECK_HEAP(big && !(big & 0xFFFF));
    GuestFree(big);
    const uint32_t big2 = GuestAlloc(8 * 1024 * 1024, 0x10000);
    CHECK_HEAP(big2 == big);
    CHECK_HEAP(GuestAlloc(SIZE_MAX) == 0 && GuestAlloc(8, 3) == 0);
    GuestFree(big2); GuestFree(b); GuestFree(reused); GuestFree(aligned);
    LOGI("HeapSelfCheck %s", ok ? "OK" : "FAILED");
#undef CHECK_HEAP
    return ok;
}

bool DynarmicHost::RuntimeSelfCheck() {
    const uint32_t sum = 0x2000, align = 0x2100, thumb = 0x2200;
    std::vector<uint32_t> code = {0xE0800001, 0xE0800002, 0xE0800003};
    for (uint32_t offset = 0; offset < 20; offset += 4) { code.push_back(0xE59D1000 | offset); code.push_back(0xE0800001); }
    code.push_back(0xE12FFF1E);
    for (size_t i = 0; i < code.size(); ++i) MemoryWrite32(sum + i * 4, code[i]);
    MemoryWrite32(align, 0xE1A0000D); MemoryWrite32(align + 4, 0xE2000007); MemoryWrite32(align + 8, 0xE12FFF1E);
    MemoryWrite32(thumb, 0x4770202A);
    AddExecutableRange(sum, code.size() * 4); AddExecutableRange(align, 12); AddExecutableRange(thumb, 4);
    const std::vector<uint32_t> arguments{1, 2, 3, 4, 5, 6, 7, 8, 9};
    bool ok = RunFunction(sum, arguments) == 45 && RunFunction(align, arguments) == 0 && RunFunction(thumb | 1) == 42;
    const uint32_t nested = m_thunk_manager->RegisterThunk("__bridge_selfcheck_nested", [sum, arguments](auto& jit, auto& host) {
        const uint32_t sp = jit.Regs()[13], lr = jit.Regs()[14];
        const uint32_t result = host.CallGuestNested(sum, arguments);
        if (&host.CurrentJit() != &jit || jit.Regs()[13] != sp || jit.Regs()[14] != lr) host.Fail("Nested JIT corrupted caller");
        jit.Regs()[0] = result;
    });
    ok &= RunFunction(nested) == 45;
    const uint32_t checked_stack = m_thunk_manager->RegisterThunk("__bridge_selfcheck_stack", [](auto& jit, auto& host) {
        uint32_t total = 0;
        for (uint32_t word = 0; word < 5; ++word) total += host.ReadStackWord(jit, word);
        bool overflow_rejected = false;
        try { host.ReadStackWord(jit, UINT32_MAX); }
        catch (const std::out_of_range&) { overflow_rejected = true; }
        const uint32_t saved_sp = jit.Regs()[13];
        const auto& thread = host.EnsureThread();
        bool guards_rejected = true;
        for (uint32_t bad_sp : {thread.stack_bottom - 4, thread.stack_top, UINT32_MAX - 3}) {
            jit.Regs()[13] = bad_sp;
            bool rejected = false;
            try { host.ReadStackWord(jit, 0); }
            catch (const std::out_of_range&) { rejected = true; }
            guards_rejected &= rejected;
        }
        jit.Regs()[13] = saved_sp;
        if (!overflow_rejected || !guards_rejected) host.Fail("Guest stack reader failed bounds self-check");
        jit.Regs()[0] = total;
    });
    ok &= RunFunction(checked_stack, arguments) == 35;
    const uint32_t parent_errno = GuestErrnoAddress();
    MemoryWrite32(parent_errno, 0x1234);
    const uint32_t concurrent = m_thunk_manager->RegisterThunk("__bridge_selfcheck_thread", [sum, arguments, parent_errno](auto& jit, auto& host) {
        uint32_t result = 0;
        std::thread worker([&] {
            const uint32_t child_errno = host.GuestErrnoAddress();
            if (child_errno == parent_errno) host.Fail("Thread errno alias");
            host.MemoryWrite32(child_errno, 0x5678);
            result = host.RunFunction(sum, arguments);
            host.ReleaseCurrentThread();
        });
        worker.join();
        jit.Regs()[0] = result;
    });
    // Join while the caller is inside a thunk proves no common JIT/registry lock spans execution.
    ok &= RunFunction(concurrent) == 45 && RunFunction(concurrent) == 45 && MemoryRead32(parent_errno) == 0x1234;
    MemoryWrite32(parent_errno, 0);
    ok &= !HasFailed();
    LOGI("BridgeAbiThreadSelfCheck %s (ARM/Thumb, 9-word spill, nested calls, thread/errno recycling)", ok ? "OK" : "FAILED");
    return ok;
}

void DynarmicHost::AddExecutableRange(uint32_t base, uint32_t size) {
    if (!size || uint64_t(base) + size > m_memory_size || uint64_t(base) + size > UINT32_MAX) {
        Fail("Invalid executable range"); return;
    }
    std::lock_guard<std::mutex> lock(m_code_mutex);
    m_code_ranges.emplace_back(base, base + size);
}

bool DynarmicHost::IsExecutableAddress(uint32_t address) const {
    const uint32_t pc = address & ~1u;
    if (IsKuserHelperAddress(pc)) return true;
    if (m_libraries_ready.load())
        for (const auto& library : m_libraries)
            if (library.elf->IsExecutable(address)) return true;
    std::lock_guard<std::mutex> lock(m_code_mutex);
    for (const auto& [begin, end] : m_code_ranges)
        if (pc >= begin && uint64_t(pc) + 2 <= end) return true;
    return false;
}

std::optional<std::uint32_t> DynarmicHost::MemoryReadCode(std::uint32_t address) {
    if (auto instruction = KuserInstruction(address, m_thunk_manager.get()))
        return instruction;
    if (!IsExecutableAddress(address)) {
        uint32_t r0 = 0, r1 = 0, r2 = 0, r3 = 0, r4 = 0, r5 = 0, pc = 0, lr = 0, sp = 0;
        uint32_t object_vtable = 0, virtual_target = 0;
        uint32_t stack0 = 0, stack1 = 0, stack2 = 0, stack3 = 0;
        if (IsJitRunning()) {
            auto& regs = CurrentJit().Regs();
            r0 = regs[0]; r1 = regs[1]; r2 = regs[2]; r3 = regs[3]; r4 = regs[4];
            r5 = regs[5]; pc = regs[15];
            lr = regs[14]; sp = regs[13];
            if (uint64_t(r5) + 4 <= m_memory_size) {
                object_vtable = MemoryRead32(r5);
                if (uint64_t(object_vtable) + 0x28 <= m_memory_size)
                    virtual_target = MemoryRead32(object_vtable + 0x24);
            }
            if (uint64_t(sp) + 16 <= m_memory_size) {
                stack0 = MemoryRead32(sp); stack1 = MemoryRead32(sp + 4);
                stack2 = MemoryRead32(sp + 8); stack3 = MemoryRead32(sp + 12);
            }
        }
#if defined(ASPHALT7_FAILURE_TELEMETRY)
        __android_log_print(ANDROID_LOG_ERROR, LOG_TAG,
            "[RUNAWAY] code fetch 0x%08x pc=0x%08x r0=0x%08x r1=0x%08x r2=0x%08x r3=0x%08x r4=0x%08x r5=0x%08x this_vtable=0x%08x vslot24=0x%08x lr=0x%08x sp=0x%08x stack=%08x,%08x,%08x,%08x",
            address, pc, r0, r1, r2, r3, r4, r5, object_vtable, virtual_target, lr, sp, stack0, stack1, stack2, stack3);
#endif
        LOGE("[RUNAWAY] code fetch 0x%08x r0=0x%08x r1=0x%08x r2=0x%08x r3=0x%08x r4=0x%08x lr=0x%08x sp=0x%08x stack=%08x,%08x,%08x,%08x",
             address, r0, r1, r2, r3, r4, lr, sp, stack0, stack1, stack2, stack3);
        Fail("Invalid guest code fetch"); return 0xE7FEDEFFu;
    }
    if (uint64_t(address) + 4 > m_memory_size) return std::nullopt;
    return MemoryRead32(address);
}

#define MEMORY_READ(bits, type) type DynarmicHost::MemoryRead##bits(uint32_t address) { \
    type value = 0; \
    if (uint64_t(address) + sizeof(value) <= m_memory_size) memcpy(&value, m_memory + address, sizeof(value)); \
    else Fail("Guest memory read out of bounds"); \
    return value; \
}
MEMORY_READ(8, uint8_t)
MEMORY_READ(16, uint16_t)
MEMORY_READ(32, uint32_t)
MEMORY_READ(64, uint64_t)
#undef MEMORY_READ

bool DynarmicHost::IsReadOnlyMemory(uint32_t address) {
    if (!m_read_only_memory_finalized.load(std::memory_order_acquire)) return false;

    // PT_LOAD segments without PF_W had immutable mappings in the original
    // process.  Keeping the largest folded read wholly inside such a segment
    // lets Dynarmic safely constant-fold ARM literal and rodata loads.
    constexpr uint64_t kMaximumFoldedRead = sizeof(uint64_t);
    for (const auto& library : m_libraries) {
        const uint64_t image_base = library.elf->GetBaseAddress();
        for (const auto& segment : library.elf->GetSegments()) {
            if (!(segment.flags & PF_R) || (segment.flags & PF_W)) continue;
            const uint64_t begin = image_base + segment.vaddr;
            const uint64_t end = begin + segment.memsz;
            if (address >= begin && uint64_t(address) + kMaximumFoldedRead <= end)
                return true;
        }
    }
    return false;
}

bool DynarmicHost::FinalizeReadOnlyMemory() {
    if (!m_libraries_ready.load(std::memory_order_acquire) || HasFailed() ||
        m_read_only_memory_finalized.exchange(true, std::memory_order_acq_rel)) {
        Fail("Invalid guest read-only memory finalization");
        return false;
    }

    uint64_t immutable_bytes = 0;
    for (const auto& library : m_libraries)
        for (const auto& segment : library.elf->GetSegments())
            if ((segment.flags & PF_R) && !(segment.flags & PF_W))
                immutable_bytes += segment.memsz;
    LOGI("Guest read-only memory finalized: %" PRIu64 " bytes available to JIT constant folding",
         immutable_bytes);
    return true;
}

#define MEMORY_WRITE(bits, type) void DynarmicHost::MemoryWrite##bits(uint32_t address, type value) { \
    if (uint64_t(address) + sizeof(value) <= m_memory_size) memcpy(m_memory + address, &value, sizeof(value)); \
    else Fail("Guest memory write out of bounds"); \
}
MEMORY_WRITE(8, uint8_t)
MEMORY_WRITE(16, uint16_t)
MEMORY_WRITE(32, uint32_t)
MEMORY_WRITE(64, uint64_t)
#undef MEMORY_WRITE

void DynarmicHost::InterpreterFallback(uint32_t pc, size_t) {
    LOGE("Interpreter fallback at 0x%08x", pc); Fail("Unsupported guest instruction");
}
void DynarmicHost::CallSVC(uint32_t swi) {
    auto& jit = CurrentJit();
    if (!swi) {
        const uint32_t pc = jit.Regs()[15];
        if (pc == kExitArm || pc == kExitArm + 4 || pc == kExitThumb || pc == kExitThumb + 2)
            jit.HaltExecution(Dynarmic::HaltReason::UserDefined1);
        else Fail("Unexpected guest SVC 0");
        return;
    }
    m_thunk_manager->DispatchThunk(swi, jit);
}
void DynarmicHost::ExceptionRaised(uint32_t pc, Dynarmic::A32::Exception exception) {
    LOGE("Guest exception PC=0x%08x type=%d", pc, int(exception)); Fail("Guest instruction exception");
}

template<class T> static bool CompareAndSwap(uint8_t* memory, size_t size, uint32_t address, T value, T expected) {
    if (uint64_t(address) + sizeof(T) > size || address % alignof(T)) return false;
    return __atomic_compare_exchange_n(reinterpret_cast<T*>(memory + address), &expected, value, false,
                                       __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
}
#define EXCLUSIVE(bits, type) bool DynarmicHost::MemoryWriteExclusive##bits(uint32_t address, type value, type expected) { \
    return CompareAndSwap(m_memory, m_memory_size, address, value, expected); \
}
EXCLUSIVE(8, uint8_t)
EXCLUSIVE(16, uint16_t)
EXCLUSIVE(32, uint32_t)
EXCLUSIVE(64, uint64_t)
#undef EXCLUSIVE
