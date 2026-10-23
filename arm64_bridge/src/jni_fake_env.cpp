// SPDX-License-Identifier: GPL-3.0-or-later
#include "jni_fake_env.h"
#include "dynarmic_host.h"
#include "thunk_manager.h"
#include "thunks_gl.h"
#include <android/log.h>
#include <algorithm>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <unordered_set>

#if defined(ASPHALT7_FINAL_SILENT)
#define LOGI(...) ((void)0)
#define LOGE(...) ((void)0)
#else
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, "Asphalt7JNI", __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "Asphalt7JNI", __VA_ARGS__)
#endif
#define SLOT(name) (offsetof(JNINativeInterface, name) / sizeof(void*))

namespace {
constexpr char kTypes[] = "LZBCSIJFDV";
constexpr char kArrayTypes[] = "ZBCSIJFD";
constexpr size_t kArrayWidths[] = {1, 1, 2, 2, 4, 8, 4, 8};
constexpr unsigned kEnvSlots = SLOT(GetObjectRefType) + 1;

#if defined(ASPHALT7_JNI_TELEMETRY)
std::atomic<uint32_t> g_audio_method_logs{0};
std::atomic<uint32_t> g_audio_buffer_logs{0};
#endif

// JNI ref bookkeeping must preserve a pending guest exception, not swallow it.
// Some ART versions reject New{Local,Global}Ref while an exception is pending.
struct PendingException {
    JNIEnv* env;
    jthrowable saved;
    explicit PendingException(JNIEnv* e) : env(e), saved(e->ExceptionOccurred()) {
        if (saved) env->ExceptionClear();
    }
    ~PendingException() {
        if (saved) {
            if (env->ExceptionCheck()) env->ExceptionClear();
            env->Throw(saved);
            env->DeleteLocalRef(saved);
        }
    }
};
struct HostFrame {
    JNIEnv* env;
    bool valid;
    explicit HostFrame(JNIEnv* e) : env(e), valid(e->PushLocalFrame(32) == JNI_OK) {}
    ~HostFrame() { if (valid) env->PopLocalFrame(nullptr); }
};

bool ParseSignature(const std::string& signature, std::vector<char>& params, char& result) {
    if (signature.empty() || signature[0] != '(' || signature.size() > 4096) return false;
    size_t p = 1;
    auto type = [&](bool allow_void, char& out) {
        if (p >= signature.size()) return false;
        bool array = false;
        while (p < signature.size() && signature[p] == '[') { array = true; ++p; }
        if (p >= signature.size()) return false;
        char t = signature[p++];
        if (t == 'L') {
            size_t end = signature.find(';', p);
            if (end == std::string::npos || end == p) return false;
            p = end + 1;
        } else if (!std::strchr("ZBCSIJFD", t) && !(allow_void && !array && t == 'V')) {
            return false;
        }
        out = array ? 'L' : t;
        return true;
    };
    while (p < signature.size() && signature[p] != ')') {
        char t;
        if (!type(false, t) || params.size() >= 255) return false;
        params.push_back(t);
    }
    if (p >= signature.size() || signature[p++] != ')') return false;
    return type(true, result) && p == signature.size();
}

void ReturnValue(Dynarmic::A32::Jit& jit, char type, const jvalue& value) {
    uint64_t bits = 0;
    switch (type) {
        case 'Z': bits = value.z ? 1 : 0; break;
        case 'B': bits = static_cast<uint32_t>(value.b); break;
        case 'C': bits = value.c; break;
        case 'S': bits = static_cast<uint32_t>(value.s); break;
        case 'I': bits = static_cast<uint32_t>(value.i); break;
        case 'J': std::memcpy(&bits, &value.j, 8); break;
        case 'F': std::memcpy(&bits, &value.f, 4); break;
        case 'D': std::memcpy(&bits, &value.d, 8); break;
        default: break;
    }
    jit.Regs()[0] = static_cast<uint32_t>(bits);
    if (type == 'J' || type == 'D') jit.Regs()[1] = static_cast<uint32_t>(bits >> 32);
}
} // namespace

struct FakeJniEnv::ThreadState {
    struct Frame {
        uint64_t id;
        bool explicit_frame;
        std::unordered_set<uint32_t> refs;
    };
    JNIEnv* env = nullptr;
    bool bridge_attached = false;
    bool guest_attached = false;
    uint32_t env_pointer = 0;
    uint64_t next_frame = 1;
    std::vector<Frame> frames;
    std::vector<size_t> native_boundaries;
    ~ThreadState() {
        auto& jni = FakeJniEnv::Instance();
        // Java entries construct host TLS first, so it is still alive here.
        if (env && jni.m_host) jni.m_host->ReleaseCurrentThread();
        jni.ReleaseCurrentThread();
    }
};

FakeJniEnv::ThreadState& FakeJniEnv::Thread() {
    static thread_local ThreadState state;
    return state;
}

FakeJniEnv& FakeJniEnv::Instance() {
    // Guests/Java callbacks can outlive static destructors during process exit.
    static auto* instance = new FakeJniEnv;
    return *instance;
}

void FakeJniEnv::Fail(const char* reason) {
#if defined(ASPHALT7_FAILURE_TELEMETRY)
    __android_log_print(ANDROID_LOG_ERROR, "Asphalt7JNI", "JNI contract failure: %s", reason);
#else
    LOGE("JNI contract failure: %s", reason);
#endif
    m_failed.store(true);
    if (m_host && m_host->IsJitRunning())
        m_host->CurrentJit().HaltExecution(Dynarmic::HaltReason::UserDefined2);
}

void FakeJniEnv::ThrowJava(const char* cls, const char* message) {
    JNIEnv* env = GetEnv();
    if (!env || env->ExceptionCheck()) return;
    jclass type = env->FindClass(cls);
    if (type) { env->ThrowNew(type, message); env->DeleteLocalRef(type); }
}

void* FakeJniEnv::Memory(uint32_t address, size_t bytes) {
    if (!m_host || !address || bytes > m_host->GetGuestMemorySize() ||
        address > m_host->GetGuestMemorySize() - bytes) {
        Fail("invalid guest memory range");
        return nullptr;
    }
    return m_host->GetGuestMemoryBase() + address;
}

std::string FakeJniEnv::String(uint32_t address) {
    const char* value = static_cast<const char*>(Memory(address, 1));
    if (!value) return {};
    size_t limit = std::min<size_t>(1024 * 1024, m_host->GetGuestMemorySize() - address);
    size_t length = strnlen(value, limit);
    if (length == limit) { Fail("unterminated guest JNI string"); return {}; }
    return std::string(value, length);
}

uint32_t FakeJniEnv::Word(Dynarmic::A32::Jit& jit, size_t index) {
    if (index < 4) return jit.Regs()[index];
    return m_host->ReadStackWord(jit, index - 4);
}

uint64_t FakeJniEnv::Wide(Dynarmic::A32::Jit& jit, size_t& index) {
    index = (index + 1) & ~size_t(1);
    uint64_t low = Word(jit, index++);
    return low | (uint64_t(Word(jit, index++)) << 32);
}

bool FakeJniEnv::CacheClassLoader(JNIEnv* env, jclass activity_class) {
    HostFrame frame(env);
    if (!frame.valid) return false;
    jclass class_class = env->FindClass("java/lang/Class");
    jclass loader_class = env->FindClass("java/lang/ClassLoader");
    if (!class_class || !loader_class) return false;
    jmethodID get_loader = env->GetMethodID(class_class, "getClassLoader", "()Ljava/lang/ClassLoader;");
    m_load_class = env->GetMethodID(loader_class, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
    if (!get_loader || !m_load_class) return false;
    jobject loader = env->CallObjectMethod(activity_class, get_loader);
    if (!loader || env->ExceptionCheck()) return false;
    m_class_loader = env->NewGlobalRef(loader);
    for (size_t i = 0; i < 8; ++i) {
        char descriptor[] = {'[', kArrayTypes[i], '\0'};
        jclass cls = env->FindClass(descriptor);
        if (!cls) return false;
        m_primitive_classes[i] = static_cast<jclass>(env->NewGlobalRef(cls));
        if (!m_primitive_classes[i]) return false;
    }
    jclass objects = env->FindClass("[Ljava/lang/Object;");
    if (!objects) return false;
    m_object_array_class = static_cast<jclass>(env->NewGlobalRef(objects));
    return m_class_loader && m_object_array_class && !env->ExceptionCheck();
}

bool FakeJniEnv::DeclareNatives(JNIEnv* env, jclass cls, const JNINativeMethod* methods, size_t count) {
    std::lock_guard lock(m_mutex);
    for (size_t i = 0; i < count; ++i) {
        std::vector<char> params;
        char result;
        if (!ParseSignature(methods[i].signature, params, result)) return false;
        jclass owner = static_cast<jclass>(env->NewGlobalRef(cls));
        if (!owner) return false;
        m_natives.push_back({owner, methods[i].name, methods[i].signature, 0});
    }
    return true;
}

uint32_t FakeJniEnv::FindNative(JNIEnv* env, jclass cls, const char* name, const char* signature) {
    std::lock_guard lock(m_mutex);
    for (const auto& native : m_natives)
        if (native.name == name && native.signature == signature && env->IsSameObject(native.owner, cls))
            return native.address;
    return 0;
}

bool FakeJniEnv::AllNativesRegistered() const {
    std::lock_guard lock(m_mutex);
    for (const auto& native : m_natives) if (!native.address) return false;
    return m_natives.size() == 15;
}

bool FakeJniEnv::Init(DynarmicHost& host) {
    if (m_host) return m_host == &host && !HasFailed();
    m_host = &host;
    m_free_refs.reserve(8192);
    m_env_functions = host.GuestAlloc(kEnvSlots * 4, 4);
    uint32_t vm_functions = host.GuestAlloc(8 * 4, 4);
    m_vm_pointer = host.GuestAlloc(4, 4);
    if (!m_env_functions || !vm_functions || !m_vm_pointer) { Fail("JNI table allocation"); return false; }
    auto& thunks = host.GetThunkManager();
    for (unsigned slot = 4; slot < kEnvSlots; ++slot) {
        uint32_t address = thunks.RegisterThunk("jni_env_" + std::to_string(slot * 4),
            [this, slot](Dynarmic::A32::Jit& jit, DynarmicHost&) { DispatchEnvSlot(slot * 4, jit); });
        host.MemoryWrite32(m_env_functions + slot * 4, address);
    }
    for (unsigned slot = 3; slot < 8; ++slot) {
        uint32_t address = thunks.RegisterThunk("jni_vm_" + std::to_string(slot * 4),
            [this, slot](Dynarmic::A32::Jit& jit, DynarmicHost&) { DispatchVmSlot(slot * 4, jit); });
        host.MemoryWrite32(vm_functions + slot * 4, address);
    }
    host.MemoryWrite32(m_vm_pointer, vm_functions);
    LOGI("JNI tables: %u env slots; guest JavaVM=%08x", kEnvSlots, m_vm_pointer);
    if (!SelfCheck() || HasFailed()) return false;
    thunks.FreezeDispatch();
    return true;
}

void FakeJniEnv::AttachHostEnv(JNIEnv* env) {
    auto& thread = Thread();
    thread.env = env;
    thread.guest_attached = true;
}

JNIEnv* FakeJniEnv::GetEnv() {
    auto& thread = Thread();
    if (thread.env) return thread.env;
    if (!m_vm) return nullptr;
    jint status = m_vm->GetEnv(reinterpret_cast<void**>(&thread.env), JNI_VERSION_1_6);
    if (status == JNI_EDETACHED) {
        if (m_vm->AttachCurrentThread(&thread.env, nullptr) != JNI_OK) return nullptr;
        thread.bridge_attached = true;
    } else if (status != JNI_OK) return nullptr;
    return thread.env;
}

uint32_t FakeJniEnv::EnvTableGuestAddr() {
    auto& thread = Thread();
    if (!m_host || !m_env_functions || !thread.guest_attached) return 0;
    if (!thread.env_pointer) {
        thread.env_pointer = m_host->GuestAlloc(4, 4);
        if (!thread.env_pointer) { Fail("thread JNIEnv allocation"); return 0; }
        m_host->MemoryWrite32(thread.env_pointer, m_env_functions);
    }
    if (thread.frames.empty()) PushFrame(false);
    return thread.env_pointer;
}

bool FakeJniEnv::PushFrame(bool explicit_frame) {
    auto& thread = Thread();
    if (thread.frames.size() >= 128) { Fail("JNI local-frame depth exhausted"); return false; }
    thread.frames.push_back({thread.next_frame++, explicit_frame, {}});
    return true;
}

bool FakeJniEnv::BeginNativeCall(JNIEnv* env) {
    AttachHostEnv(env);
    auto& thread = Thread();
    thread.native_boundaries.push_back(thread.frames.size());
    if (!PushFrame(false)) { thread.native_boundaries.pop_back(); return false; }
    if (!EnvTableGuestAddr()) { EndNativeCall(); return false; }
    return true;
}

void FakeJniEnv::EndNativeCall() {
    auto& thread = Thread();
    if (thread.native_boundaries.empty()) { Fail("unbalanced JNI native frame"); return; }
    size_t boundary = thread.native_boundaries.back();
    while (thread.frames.size() > boundary) PopFrame(0, false);
    thread.native_boundaries.pop_back();
}

uint32_t FakeJniEnv::NewRef(jobject object, RefKind kind) {
    if (!object) return 0;
    JNIEnv* env = GetEnv();
    if (!env) { Fail("no JVM environment for reference"); return 0; }
    auto& thread = Thread();
    if (kind == RefKind::Local && thread.frames.empty() && !PushFrame(false)) return 0;
    PendingException pending(env);
    jobject copy = kind == RefKind::Weak ? env->NewWeakGlobalRef(object) : env->NewGlobalRef(object);
    if (!copy) { Fail("JNI reference allocation failed"); return 0; }
    std::lock_guard lock(m_mutex);
    if ((m_free_refs.empty() && m_next_ref >= 0x40000000) || m_refs.size() >= 8192) {
        if (kind == RefKind::Weak) env->DeleteWeakGlobalRef(static_cast<jweak>(copy));
        else env->DeleteGlobalRef(copy);
        Fail("JNI live-reference limit reached (live locals are never evicted)");
        return 0;
    }
    uint32_t handle;
    if (m_free_refs.empty()) { handle = m_next_ref; m_next_ref += 4; }
    else { handle = m_free_refs.back(); m_free_refs.pop_back(); }
    uint64_t frame = kind == RefKind::Local ? thread.frames.back().id : 0;
    auto ref = std::shared_ptr<Ref>(new Ref{copy, kind, std::this_thread::get_id(), frame}, [this](Ref* value) {
        // This deleter can run while FakeJniEnv::ThreadState is being torn
        // down. Do not call GetEnv() here: it re-enters that thread-local
        // bookkeeping during its destructor. Query/attach through JavaVM
        // directly so the last shared owner can safely release the ART ref.
        JNIEnv* current = nullptr;
        bool attached = false;
        if (m_vm) {
            const jint status = m_vm->GetEnv(reinterpret_cast<void**>(&current), JNI_VERSION_1_6);
            if (status == JNI_EDETACHED) {
                if (m_vm->AttachCurrentThread(&current, nullptr) == JNI_OK)
                    attached = true;
            } else if (status != JNI_OK) {
                current = nullptr;
            }
        }
        if (current) {
            if (value->kind == RefKind::Weak) current->DeleteWeakGlobalRef(static_cast<jweak>(value->object));
            else current->DeleteGlobalRef(value->object);
            if (attached) m_vm->DetachCurrentThread();
        } else {
            m_failed.store(true);
        }
        delete value;
    });
    m_refs.emplace(handle, std::move(ref));
    if (kind == RefKind::Local) thread.frames.back().refs.insert(handle);
    return handle;
}

uint32_t FakeJniEnv::AddObjectRef(jobject object) { return NewRef(object, RefKind::Local); }

jobject FakeJniEnv::ResolveObject(uint32_t handle) {
    if (!handle) return nullptr;
    JNIEnv* env = GetEnv();
    if (!env) { Fail("no JVM environment for reference lookup"); return nullptr; }
    PendingException pending(env);
    std::lock_guard lock(m_mutex);
    auto it = m_refs.find(handle);
    if (it == m_refs.end() || (it->second->kind == RefKind::Local &&
                             it->second->thread != std::this_thread::get_id())) {
        Fail("invalid or cross-thread JNI local reference");
        return nullptr;
    }
    // This local clone pins the receiver/argument while registry locks are dropped.
    return env->NewLocalRef(it->second->object);
}

void FakeJniEnv::DeleteRef(uint32_t handle, RefKind kind) {
    if (!handle) return;
    JNIEnv* env = GetEnv();
    if (!env) { Fail("no JVM environment for reference deletion"); return; }
    std::shared_ptr<Ref> ref;
    uint64_t frame = 0;
    {
        std::lock_guard lock(m_mutex);
        auto it = m_refs.find(handle);
        if (it == m_refs.end() || it->second->kind != kind ||
            (kind == RefKind::Local && it->second->thread != std::this_thread::get_id())) {
            Fail("invalid JNI reference deletion");
            return;
        }
        ref = it->second;
        frame = ref->frame;
        m_refs.erase(it);
        m_free_refs.push_back(handle);
    }
    if (kind == RefKind::Local)
        for (auto& scope : Thread().frames) if (scope.id == frame) { scope.refs.erase(handle); break; }
    // Outstanding borrowers (e.g. JavaVM attach's ThreadGroup) retain the real
    // global ref until the last borrower returns, without retaining the mutex.
}

uint32_t FakeJniEnv::PopFrame(uint32_t result, bool explicit_only) {
    auto& thread = Thread();
    if (thread.frames.empty() || (explicit_only && !thread.frames.back().explicit_frame)) {
        Fail("unbalanced PopLocalFrame");
        return 0;
    }
    JNIEnv* env = GetEnv();
    jobject survivor = result ? ResolveObject(result) : nullptr;
    while (!thread.frames.back().refs.empty())
        DeleteRef(*thread.frames.back().refs.begin(), RefKind::Local);
    thread.frames.pop_back();
    uint32_t handle = survivor ? AddObjectRef(survivor) : 0;
    if (survivor) env->DeleteLocalRef(survivor);
    return handle;
}

void FakeJniEnv::ReleaseCurrentThread() {
    auto& thread = Thread();
    if (!thread.env && !thread.env_pointer && thread.frames.empty()) return;
    while (!thread.frames.empty()) PopFrame(0, false);
    thread.native_boundaries.clear();
    {
        std::lock_guard lock(m_mutex);
        for (const auto& [address, buffer] : m_buffers)
            if (buffer.thread == std::this_thread::get_id()) {
                LOGE("unreleased JNI buffer at thread exit: %08x", address);
                Fail("unreleased JNI buffer at thread detach");
                // Do not free storage that another thread could still own.
            }
    }
    if (m_host && thread.env_pointer) m_host->GuestFree(thread.env_pointer);
    thread.env_pointer = 0;
    thread.guest_attached = false;
    if (thread.bridge_attached && m_vm) m_vm->DetachCurrentThread();
    thread.bridge_attached = false;
    thread.env = nullptr;
}

std::shared_ptr<FakeJniEnv::Method> FakeJniEnv::GetMethod(uint32_t handle) {
    std::lock_guard lock(m_mutex);
    auto found = m_methods.find(handle);
    if (found == m_methods.end()) return {};
    return found->second;
}
std::shared_ptr<FakeJniEnv::Field> FakeJniEnv::GetField(uint32_t handle) {
    std::lock_guard lock(m_mutex);
    auto found = m_fields.find(handle);
    if (found == m_fields.end()) { Fail("unknown jfieldID"); return {}; }
    return found->second;
}

std::vector<jvalue> FakeJniEnv::Arguments(Dynarmic::A32::Jit& jit, const std::string& signature,
                                        unsigned variant, size_t first_word) {
    std::vector<char> params;
    char result;
    if (!ParseSignature(signature, params, result)) { Fail("invalid JNI descriptor"); return {}; }
    std::vector<jvalue> values(params.size());
    uint64_t cursor = variant ? Word(jit, first_word) : 0;
    size_t word = first_word;
    for (size_t i = 0; i < params.size(); ++i) {
        char type = params[i];
        bool wide = type == 'J' || type == 'D' || (type == 'F' && variant != 2);
        uint64_t bits = 0;
        if (variant == 0) {
            bits = wide ? Wide(jit, word) : Word(jit, word++);
        } else {
            if (variant == 1 && wide) cursor = (cursor + 7) & ~uint64_t(7);
            size_t bytes = wide ? 8 : 4;
            if (cursor > UINT32_MAX) { Fail("JNI argument pointer overflow"); return {}; }
            void* data = Memory(static_cast<uint32_t>(cursor), bytes);
            if (!data) return {};
            std::memcpy(&bits, data, bytes);
            cursor += variant == 2 ? 8 : bytes;
        }
        auto& value = values[i];
        switch (type) {
            case 'L': value.l = ResolveObject(static_cast<uint32_t>(bits)); break;
            case 'Z': value.z = static_cast<jboolean>(bits) ? JNI_TRUE : JNI_FALSE; break;
            case 'B': value.b = static_cast<jbyte>(bits); break;
            case 'C': value.c = static_cast<jchar>(bits); break;
            case 'S': value.s = static_cast<jshort>(bits); break;
            case 'I': value.i = static_cast<jint>(bits); break;
            case 'J': std::memcpy(&value.j, &bits, 8); break;
            case 'D': std::memcpy(&value.d, &bits, 8); break;
            case 'F':
                if (variant == 2) std::memcpy(&value.f, &bits, 4);
                else { double promoted; std::memcpy(&promoted, &bits, 8); value.f = static_cast<jfloat>(promoted); }
                break;
        }
    }
    return values;
}

bool FakeJniEnv::SelfCheck() {
    bool ok = true;
    for (const char* malformed : {"", "(", "([)V", "(L;)V", "(V)V", "()VV"}) {
        std::vector<char> params;
        char result;
        ok = !ParseSignature(malformed, params, result) && ok;
    }
    std::vector<char> params;
    char result;
    ok = ParseSignature("(I[JLjava/lang/String;DF)Z", params, result) &&
         params == std::vector<char>({'I', 'L', 'L', 'D', 'F'}) && result == 'Z' && ok;
    // Exercise the real RunFunction stack packer and the JNI reader together.
    // The permanent private thunk captures only the process-lived dispatcher.
    uint32_t check = m_host->GetThunkManager().RegisterThunk("jni_aapcs_selfcheck",
        [this](Dynarmic::A32::Jit& jit, DynarmicHost&) {
            bool pass = (jit.Regs()[13] & 7u) == 0;
            switch (jit.Regs()[2]) {
                case 0: {
                    auto plain = Arguments(jit, "(IFJ)I", 0, 3);
                    pass = plain.size() == 3 && plain[0].i == 7 && plain[1].f == 1.25f &&
                           uint64_t(plain[2].j) == 0x1122334455667788ULL && pass;
                    break;
                }
                case 1: {
                    auto first_float = Arguments(jit, "(F)F", 0, 3);
                    pass = first_float.size() == 1 && first_float[0].f == 1.25f && pass;
                    break;
                }
                case 2: {
                    auto array = Arguments(jit, "(FJ)I", 2, 3);
                    pass = array.size() == 2 && array[0].f == -2.5f &&
                           uint64_t(array[1].j) == 0x1122334455667788ULL && pass;
                    break;
                }
                case 3: {
                    auto va = Arguments(jit, "(ZDF)I", 1, 3);
                    pass = va.size() == 3 && va[0].z == JNI_FALSE && va[1].d == 3.5 && va[2].f == -2.25f && pass;
                    break;
                }
                default: pass = false; break;
            }
            jvalue value{};
            value.j = 0x1122334455667788LL;
            ReturnValue(jit, 'J', value);
            pass = jit.Regs()[0] == 0x55667788 && jit.Regs()[1] == 0x11223344 && pass;
            jit.Regs()[0] = pass ? 1 : 0;
        });
    ok = m_host->RunFunction(check, {0, 0, 0, 7, 0, 0x3ff40000, 0x55667788, 0x11223344}) == 1 && ok;
    ok = m_host->RunFunction(check, {0, 0, 1, 0, 0, 0x3ff40000}) == 1 && ok;
    uint32_t scratch = m_host->GuestAlloc(64, 8);
    if (!scratch) { Fail("JNI self-check allocation"); return false; }
    auto* memory = static_cast<uint8_t*>(Memory(scratch, 64));
    if (!memory) { m_host->GuestFree(scratch); return false; }
    const uint64_t integer = 0x1122334455667788ULL;
    float scalar = -2.5f;
    std::memcpy(memory, &scalar, 4);
    std::memcpy(memory + 8, &integer, 8);
    ok = m_host->RunFunction(check, {0, 0, 2, scratch}) == 1 && ok;
    uint32_t boolean = 0x100;
    double promoted = 3.5;
    std::memcpy(memory + 4, &boolean, 4);
    std::memcpy(memory + 8, &promoted, 8);
    promoted = -2.25;
    std::memcpy(memory + 16, &promoted, 8);
    ok = m_host->RunFunction(check, {0, 0, 3, scratch + 4}) == 1 && ok;
    m_host->GuestFree(scratch);
    ok = !m_host->HasFailed() && ok;
    if (!ok || HasFailed()) { Fail("JNI AAPCS/descriptor self-check failed"); return false; }
    LOGI("JNI AAPCS self-check OK: varargs promotions, 64-bit alignment, jvalue arrays, return pairs");
    return true;
}

void FakeJniEnv::Invoke(Dynarmic::A32::Jit& jit, unsigned slot) {
    JNIEnv* env = GetEnv();
    bool constructor = slot >= SLOT(NewObject) && slot <= SLOT(NewObjectA);
    bool nonvirtual = slot >= SLOT(CallNonvirtualObjectMethod) && slot <= SLOT(CallNonvirtualVoidMethodA);
    bool is_static = slot >= SLOT(CallStaticObjectMethod) && slot <= SLOT(CallStaticVoidMethodA);
    unsigned base = constructor ? SLOT(NewObject) : nonvirtual ? SLOT(CallNonvirtualObjectMethod) :
                    is_static ? SLOT(CallStaticObjectMethod) : SLOT(CallObjectMethod);
    unsigned variant = (slot - base) % 3;
    char type = constructor ? 'L' : kTypes[(slot - base) / 3];
    auto method = GetMethod(Word(jit, nonvirtual ? 3 : 2));
    if (!method) return;
    std::vector<char> params;
    char actual_result;
    if (!ParseSignature(method->signature, params, actual_result) || method->is_static != is_static ||
        (constructor ? actual_result != 'V' : actual_result != type)) {
        Fail("JNI call type does not match its method descriptor");
        return;
    }
    jobject object = ResolveObject(jit.Regs()[1]);
    jclass explicit_class = nonvirtual ? static_cast<jclass>(ResolveObject(jit.Regs()[2])) : nullptr;
    if (!object || (nonvirtual && !explicit_class)) {
        if (!HasFailed()) ThrowJava("java/lang/NullPointerException", "JNI method receiver is null");
        return;
    }
    auto args = Arguments(jit, method->signature, variant, nonvirtual ? 4 : 3);
    if (HasFailed() || env->ExceptionCheck()) return;
#if defined(ASPHALT7_JNI_TELEMETRY)
    const bool audio_method = method->name == "<init>" || method->name == "getMinBufferSize" ||
                              method->name == "play" || method->name == "pause" ||
                              method->name == "stop" || method->name == "flush" ||
                              method->name == "release" || method->name == "write" ||
                              method->name == "setStereoVolume" || method->name == "setVolume";
    const uint32_t audio_log = audio_method
        ? g_audio_method_logs.fetch_add(1, std::memory_order_relaxed) : 1000000u;
    if (audio_method && audio_log < 96) {
        if (method->name == "write" && !args.empty() && args[0].l &&
            method->signature == "([BII)I" && args.size() >= 3) {
            const jint offset = args[1].i;
            const jint count = args[2].i;
            const jint length = env->GetArrayLength(static_cast<jarray>(args[0].l));
            const jint safe_offset = std::max<jint>(0, std::min(offset, length));
            const jint safe_count = std::max<jint>(0, std::min(count, length - safe_offset));
            std::vector<jbyte> pcm(static_cast<size_t>(std::min<jint>(safe_count, 4096)));
            if (!pcm.empty()) env->GetByteArrayRegion(static_cast<jbyteArray>(args[0].l),
                                                       safe_offset, pcm.size(), pcm.data());
            size_t nonzero = 0;
            int peak = 0;
            for (jbyte sample : pcm) {
                const int value = std::abs(static_cast<int>(sample));
                nonzero += value != 0;
                peak = std::max(peak, value);
            }
            LOGI("AudioTrack.%s%s offset=%d count=%d length=%d sample_nonzero=%zu sample_peak=%d",
                 method->name.c_str(), method->signature.c_str(), offset, count, length,
                 nonzero, peak);
        } else if (method->name == "<init>" && method->signature == "(IIIIII)V" && args.size() >= 6) {
            LOGI("AudioTrack.%s%s stream=%d rate=%d channel=0x%x format=0x%x buffer=%d mode=%d",
                 method->name.c_str(), method->signature.c_str(), args[0].i, args[1].i,
                 args[2].i, args[3].i, args[4].i, args[5].i);
        } else if (method->name == "setStereoVolume" && args.size() >= 2) {
            LOGI("AudioTrack.%s%s left=%f right=%f", method->name.c_str(),
                 method->signature.c_str(), args[0].f, args[1].f);
        } else {
            LOGI("AudioTrack.%s%s", method->name.c_str(), method->signature.c_str());
        }
    }
#endif
    jvalue value{};
    // No registry/host execution mutex survives into these potentially blocking,
    // reentrant Java calls. HostFrame and method metadata retain all references.
    if (constructor) value.l = env->NewObjectA(static_cast<jclass>(object), method->id, args.data());
    else {
#define CALL(T, member) \
        if (is_static) value.member = env->CallStatic##T##MethodA(static_cast<jclass>(object), method->id, args.data()); \
        else if (nonvirtual) value.member = env->CallNonvirtual##T##MethodA(object, explicit_class, method->id, args.data()); \
        else value.member = env->Call##T##MethodA(object, method->id, args.data())
        switch (type) {
            case 'L': CALL(Object, l); break;
            case 'Z': CALL(Boolean, z); break;
            case 'B': CALL(Byte, b); break;
            case 'C': CALL(Char, c); break;
            case 'S': CALL(Short, s); break;
            case 'I': CALL(Int, i); break;
            case 'J': CALL(Long, j); break;
            case 'F': CALL(Float, f); break;
            case 'D': CALL(Double, d); break;
            case 'V':
                if (is_static) env->CallStaticVoidMethodA(static_cast<jclass>(object), method->id, args.data());
                else if (nonvirtual) env->CallNonvirtualVoidMethodA(object, explicit_class, method->id, args.data());
                else env->CallVoidMethodA(object, method->id, args.data());
                break;
        }
#undef CALL
    }
    if (env->ExceptionCheck()) { jit.Regs()[0] = 0; jit.Regs()[1] = 0; return; }
    if (is_static && type == 'I' &&
        method->name == "getMinBufferSize" &&
        method->signature == "(III)I" && value.i > 0 &&
        args.size() == 3 && args[0].i == 44100 &&
        args[1].i == 12 && args[2].i == 2) {
        // The guest uses this result for its AudioTrack allocation. Its
        // original ~43 ms buffer is too short for occasional translated race
        // frames; reserve 93 ms while the mixer keeps 1024-frame writes.
        value.i = std::max<jint>(value.i, 16384);
    }
    if (is_static && type == 'Z' && value.z == JNI_TRUE &&
        method->name == "setCurrentContext" &&
        method->signature == "(I)Z") {
        // GL2JNILib.setCurrentContext returns after Java's eglMakeCurrent.
        // Reassert the window-system rectangle at that exact ownership
        // boundary; the guest's 1x1 pbuffer contexts are rejected by the
        // authority helper and remain untouched.
        RestoreHostDefaultFramebufferState();
        TraceHostDefaultFramebufferState("setCurrentContext");
    }
    if (type == 'L') jit.Regs()[0] = AddObjectRef(value.l);
    else ReturnValue(jit, type, value);
}

void FakeJniEnv::AccessField(Dynarmic::A32::Jit& jit, unsigned slot) {
    bool is_static = slot >= SLOT(GetStaticObjectField);
    bool write = is_static ? slot >= SLOT(SetStaticObjectField) : slot >= SLOT(SetObjectField);
    unsigned base = is_static ? (write ? SLOT(SetStaticObjectField) : SLOT(GetStaticObjectField)) :
                               (write ? SLOT(SetObjectField) : SLOT(GetObjectField));
    char type = kTypes[slot - base];
    auto field = GetField(jit.Regs()[2]);
    if (!field) return;
    if (field->is_static != is_static || field->type != type) { Fail("JNI field type mismatch"); return; }
    JNIEnv* env = GetEnv();
    jobject object = ResolveObject(jit.Regs()[1]);
    if (!object) { ThrowJava("java/lang/NullPointerException", "JNI field receiver is null"); return; }
    jclass cls = static_cast<jclass>(object);
    jvalue value{};
    if (write) {
        size_t index = 3;
        uint64_t bits = (type == 'J' || type == 'D') ? Wide(jit, index) : Word(jit, index);
        switch (type) {
            case 'L': value.l = ResolveObject(static_cast<uint32_t>(bits)); break;
            case 'Z': value.z = static_cast<jboolean>(bits) ? JNI_TRUE : JNI_FALSE; break;
            case 'B': value.b = static_cast<jbyte>(bits); break;
            case 'C': value.c = static_cast<jchar>(bits); break;
            case 'S': value.s = static_cast<jshort>(bits); break;
            case 'I': value.i = static_cast<jint>(bits); break;
            case 'J': std::memcpy(&value.j, &bits, 8); break;
            case 'F': std::memcpy(&value.f, &bits, 4); break;
            case 'D': std::memcpy(&value.d, &bits, 8); break;
        }
    }
    if (HasFailed() || env->ExceptionCheck()) return;
#define FIELD(T, member) \
    if (write) { if (is_static) env->SetStatic##T##Field(cls, field->id, value.member); else env->Set##T##Field(object, field->id, value.member); } \
    else value.member = is_static ? env->GetStatic##T##Field(cls, field->id) : env->Get##T##Field(object, field->id)
    switch (type) {
        case 'L': FIELD(Object, l); break;
        case 'Z': FIELD(Boolean, z); break;
        case 'B': FIELD(Byte, b); break;
        case 'C': FIELD(Char, c); break;
        case 'S': FIELD(Short, s); break;
        case 'I': FIELD(Int, i); break;
        case 'J': FIELD(Long, j); break;
        case 'F': FIELD(Float, f); break;
        case 'D': FIELD(Double, d); break;
    }
#undef FIELD
    if (!write && !env->ExceptionCheck()) {
        if (type == 'L') jit.Regs()[0] = AddObjectRef(value.l);
        else ReturnValue(jit, type, value);
    }
}

char FakeJniEnv::ArrayType(jarray array) {
    JNIEnv* env = GetEnv();
    for (size_t i = 0; i < 8; ++i)
        if (env->IsInstanceOf(array, m_primitive_classes[i])) return kArrayTypes[i];
    return 0;
}

void FakeJniEnv::ArrayRegion(jarray array, char type, jsize start, jsize count, void* data, bool write) {
    JNIEnv* env = GetEnv();
#define REGION(T, C, A) \
    if (write) env->Set##T##ArrayRegion(static_cast<A>(array), start, count, static_cast<const C*>(data)); \
    else env->Get##T##ArrayRegion(static_cast<A>(array), start, count, static_cast<C*>(data))
    switch (type) {
        case 'Z': REGION(Boolean, jboolean, jbooleanArray); break;
        case 'B': REGION(Byte, jbyte, jbyteArray); break;
        case 'C': REGION(Char, jchar, jcharArray); break;
        case 'S': REGION(Short, jshort, jshortArray); break;
        case 'I': REGION(Int, jint, jintArray); break;
        case 'J': REGION(Long, jlong, jlongArray); break;
        case 'F': REGION(Float, jfloat, jfloatArray); break;
        case 'D': REGION(Double, jdouble, jdoubleArray); break;
        default: Fail("non-primitive array buffer"); break;
    }
#undef REGION
}

void FakeJniEnv::ReleaseBuffer(Dynarmic::A32::Jit& jit, char expected_type, jint mode) {
    if (mode != 0 && mode != JNI_COMMIT && mode != JNI_ABORT) { Fail("invalid JNI buffer release mode"); return; }
    uint32_t pointer = jit.Regs()[2];
    if (!pointer) { Fail("null JNI buffer release"); return; }
    JNIEnv* env = GetEnv();
    PendingException pending(env);
    jobject array = ResolveObject(jit.Regs()[1]);
    Buffer buffer{};
    {
        std::lock_guard lock(m_mutex);
        auto found = m_buffers.find(pointer);
        if (found == m_buffers.end() || (expected_type && found->second.type != expected_type) ||
            (!expected_type && !std::strchr(kArrayTypes, found->second.type)) ||
            !env->IsSameObject(found->second.owner, array)) {
            Fail("JNI buffer release without matching acquisition");
            return;
        }
        buffer = found->second;
        // JNI_COMMIT retains the lease; all other modes consume it atomically.
        if (mode != JNI_COMMIT) m_buffers.erase(found);
    }
    const char* kind = std::strchr(kArrayTypes, buffer.type);
    if (kind && mode != JNI_ABORT) {
        size_t bytes = size_t(buffer.length) * kArrayWidths[kind - kArrayTypes];
        void* data = Memory(pointer, bytes);
#if defined(ASPHALT7_JNI_TELEMETRY)
        if (buffer.type == 'B' && data &&
            g_audio_buffer_logs.fetch_add(1, std::memory_order_relaxed) < 32) {
            const size_t sample_bytes = std::min<size_t>(bytes, 4096);
            const auto* pcm = static_cast<const int8_t*>(data);
            size_t nonzero = 0;
            int peak = 0;
            for (size_t index = 0; index < sample_bytes; ++index) {
                const int value = std::abs(static_cast<int>(pcm[index]));
                nonzero += value != 0;
                peak = std::max(peak, value);
            }
            LOGI("Audio JNI release byte[] mode=%d length=%d sample_nonzero=%zu sample_peak=%d",
                 mode, buffer.length, nonzero, peak);
        }
#endif
        if (data) ArrayRegion(static_cast<jarray>(array), buffer.type, 0, buffer.length, data, true);
    }
    if (mode != JNI_COMMIT) {
        env->DeleteGlobalRef(buffer.owner);
        m_host->GuestFree(pointer);
    }
}

void FakeJniEnv::PrimitiveArray(Dynarmic::A32::Jit& jit, unsigned slot) {
    JNIEnv* env = GetEnv();
    if (slot >= SLOT(NewBooleanArray) && slot <= SLOT(NewDoubleArray)) {
        jint count = static_cast<jint>(jit.Regs()[1]);
        if (count < 0) { ThrowJava("java/lang/NegativeArraySizeException", "negative guest array size"); return; }
        jobject array = nullptr;
        switch (kArrayTypes[slot - SLOT(NewBooleanArray)]) {
            case 'Z': array = env->NewBooleanArray(count); break;
            case 'B': array = env->NewByteArray(count); break;
            case 'C': array = env->NewCharArray(count); break;
            case 'S': array = env->NewShortArray(count); break;
            case 'I': array = env->NewIntArray(count); break;
            case 'J': array = env->NewLongArray(count); break;
            case 'F': array = env->NewFloatArray(count); break;
            case 'D': array = env->NewDoubleArray(count); break;
        }
        jit.Regs()[0] = array ? AddObjectRef(array) : 0;
        return;
    }
    if (slot >= SLOT(ReleaseBooleanArrayElements) && slot <= SLOT(ReleaseDoubleArrayElements)) {
        ReleaseBuffer(jit, kArrayTypes[slot - SLOT(ReleaseBooleanArrayElements)], static_cast<jint>(jit.Regs()[3]));
        return;
    }
    if (slot == SLOT(ReleasePrimitiveArrayCritical)) {
        ReleaseBuffer(jit, 0, static_cast<jint>(jit.Regs()[3]));
        return;
    }
    jarray array = static_cast<jarray>(ResolveObject(jit.Regs()[1]));
    if (!array) { ThrowJava("java/lang/NullPointerException", "null guest array"); return; }
    char type = ArrayType(array);
    if (!type) { Fail("wrong JNI primitive-array type"); return; }
    size_t width = kArrayWidths[std::strchr(kArrayTypes, type) - kArrayTypes];
    jsize length = env->GetArrayLength(array);
    bool elements = (slot >= SLOT(GetBooleanArrayElements) && slot <= SLOT(GetDoubleArrayElements)) ||
                     slot == SLOT(GetPrimitiveArrayCritical);
    char expected = elements ? (slot == SLOT(GetPrimitiveArrayCritical) ? type : kArrayTypes[slot - SLOT(GetBooleanArrayElements)]) :
                    kArrayTypes[slot >= SLOT(SetBooleanArrayRegion) ? slot - SLOT(SetBooleanArrayRegion) : slot - SLOT(GetBooleanArrayRegion)];
    if (type != expected) { Fail("JNI primitive-array element type mismatch"); return; }
    if (!elements) {
        jint start = static_cast<jint>(jit.Regs()[2]);
        jint count = static_cast<jint>(jit.Regs()[3]);
        if (start < 0 || count < 0 || start > length || count > length - start) {
            ThrowJava("java/lang/ArrayIndexOutOfBoundsException", "guest array region exceeds length");
            return;
        }
        uint32_t address = Word(jit, 4); // env/array/start/count occupy r0-r3.
        uint64_t dummy = 0;
        void* data = count ? Memory(address, size_t(count) * width) : &dummy;
        if (data) ArrayRegion(array, type, start, count, data, slot >= SLOT(SetBooleanArrayRegion));
        return;
    }
    size_t bytes = size_t(length) * width;
    if (bytes >= m_host->GetGuestMemorySize()) { ThrowJava("java/lang/OutOfMemoryError", "guest array copy too large"); return; }
    uint32_t is_copy = jit.Regs()[2];
    if (is_copy && !Memory(is_copy, 1)) return;
    uint32_t address = m_host->GuestAlloc(std::max<size_t>(bytes, 1), 8);
    if (!address) { ThrowJava("java/lang/OutOfMemoryError", "guest array copy allocation"); return; }
    ArrayRegion(array, type, 0, length, Memory(address, std::max<size_t>(bytes, 1)), false);
    if (env->ExceptionCheck()) { m_host->GuestFree(address); return; }
    jobject owner = env->NewGlobalRef(array);
    if (!owner) { m_host->GuestFree(address); return; }
    {
        std::lock_guard lock(m_mutex);
        m_buffers.emplace(address, Buffer{owner, type, length, std::this_thread::get_id()});
    }
    if (is_copy) m_host->MemoryWrite8(is_copy, JNI_TRUE);
    jit.Regs()[0] = address;
}

void FakeJniEnv::DispatchVmSlot(uint32_t offset, Dynarmic::A32::Jit& jit) {
    if (jit.Regs()[0] != m_vm_pointer) { Fail("invalid guest JavaVM pointer"); return; }
    auto& thread = Thread();
    unsigned slot = offset / 4;
    if (slot == 5) { // DetachCurrentThread cannot detach through a Java native frame.
        if (!thread.native_boundaries.empty()) { jit.Regs()[0] = static_cast<uint32_t>(JNI_ERR); return; }
        if (!thread.guest_attached) { jit.Regs()[0] = static_cast<uint32_t>(JNI_EDETACHED); return; }
        ReleaseCurrentThread();
        jit.Regs()[0] = JNI_OK;
        return;
    }
    if (slot != 4 && slot != 6 && slot != 7) {
        Fail("unsupported JavaVM slot");
        jit.Regs()[0] = static_cast<uint32_t>(JNI_ERR);
        return;
    }
    uint32_t out = jit.Regs()[1];
    if (!Memory(out, 4)) return;
    m_host->MemoryWrite32(out, 0);
    jint version = slot == 6 ? static_cast<jint>(jit.Regs()[2]) : JNI_VERSION_1_2;
    JavaVMAttachArgs args{JNI_VERSION_1_2, nullptr, nullptr};
    std::shared_ptr<Ref> group;
    std::string name;
    if (slot != 6 && jit.Regs()[2]) {
        void* data = Memory(jit.Regs()[2], 12);
        if (!data) return;
        uint32_t words[3];
        std::memcpy(words, data, 12);
        version = static_cast<jint>(words[0]);
        args.version = version;
        if (words[1]) { name = String(words[1]); args.name = name.data(); }
        if (words[2]) {
            std::lock_guard lock(m_mutex);
            auto found = m_refs.find(words[2]);
            if (found == m_refs.end() || found->second->kind != RefKind::Global) {
                Fail("AttachCurrentThread requires a global ThreadGroup reference");
                jit.Regs()[0] = static_cast<uint32_t>(JNI_ERR);
                return;
            }
            group = found->second;
            args.group = group->object;
        }
    }
    if (version != JNI_VERSION_1_1 && version != JNI_VERSION_1_2 && version != JNI_VERSION_1_4 && version != JNI_VERSION_1_6) {
        jit.Regs()[0] = static_cast<uint32_t>(JNI_EVERSION);
        return;
    }
    if (slot == 6 && !thread.guest_attached) {
        jit.Regs()[0] = static_cast<uint32_t>(JNI_EDETACHED);
        return;
    }
    JNIEnv* actual = nullptr;
    jint status = m_vm->GetEnv(reinterpret_cast<void**>(&actual), version);
    if (status == JNI_EDETACHED && slot != 6) {
        void* attach_args = jit.Regs()[2] ? &args : nullptr;
        status = slot == 7 ? m_vm->AttachCurrentThreadAsDaemon(&actual, attach_args) : m_vm->AttachCurrentThread(&actual, attach_args);
        if (status == JNI_OK) thread.bridge_attached = true;
    }
    if (status == JNI_OK) {
        thread.env = actual;
        thread.guest_attached = true;
        uint32_t guest_env = EnvTableGuestAddr();
        if (!guest_env) status = JNI_ERR;
        else m_host->MemoryWrite32(out, guest_env);
    }
    jit.Regs()[0] = static_cast<uint32_t>(status);
}

void FakeJniEnv::DispatchEnvSlot(uint32_t offset, Dynarmic::A32::Jit& jit) {
    if (HasFailed()) { jit.HaltExecution(Dynarmic::HaltReason::UserDefined2); return; }
    unsigned slot = offset / 4;
    auto& thread = Thread();
    if (!thread.guest_attached || jit.Regs()[0] != EnvTableGuestAddr()) {
        Fail("JNIEnv used by an unattached or different guest thread");
        return;
    }
    JNIEnv* env = GetEnv();
    if (!env) { Fail("host JVM attachment failed"); return; }
    jit.Regs()[0] = 0; // Defined failure return; r1-r3 still contain live arguments.
    HostFrame frame(env);
    if (!frame.valid) { Fail("host JNI local-frame allocation"); return; }
    if ((slot >= SLOT(NewObject) && slot <= SLOT(NewObjectA)) ||
        (slot >= SLOT(CallObjectMethod) && slot <= SLOT(CallNonvirtualVoidMethodA)) ||
        (slot >= SLOT(CallStaticObjectMethod) && slot <= SLOT(CallStaticVoidMethodA))) {
        Invoke(jit, slot);
        return;
    }
    if ((slot >= SLOT(GetObjectField) && slot <= SLOT(SetDoubleField)) ||
        (slot >= SLOT(GetStaticObjectField) && slot <= SLOT(SetStaticDoubleField))) {
        AccessField(jit, slot);
        return;
    }
    if ((slot >= SLOT(NewBooleanArray) && slot <= SLOT(SetDoubleArrayRegion)) ||
        slot == SLOT(GetPrimitiveArrayCritical) || slot == SLOT(ReleasePrimitiveArrayCritical)) {
        PrimitiveArray(jit, slot);
        return;
    }
    switch (slot) {
        case SLOT(GetVersion): jit.Regs()[0] = static_cast<uint32_t>(env->GetVersion()); break;
        case SLOT(FindClass): {
            std::string name = String(jit.Regs()[1]);
            if (HasFailed()) return;
            jclass cls = nullptr;
            if (!name.empty() && name[0] == '[') cls = env->FindClass(name.c_str());
            else {
                std::replace(name.begin(), name.end(), '/', '.');
                jstring binary_name = env->NewStringUTF(name.c_str());
                if (binary_name) cls = static_cast<jclass>(env->CallObjectMethod(m_class_loader, m_load_class, binary_name));
            }
            // A missing UnityPlayer is a real pending exception for Imm to clear.
            jit.Regs()[0] = cls ? AddObjectRef(cls) : 0;
            break;
        }
        case SLOT(GetSuperclass): {
            jclass cls = static_cast<jclass>(ResolveObject(jit.Regs()[1]));
            jit.Regs()[0] = cls ? AddObjectRef(env->GetSuperclass(cls)) : 0;
            break;
        }
        case SLOT(IsAssignableFrom): {
            jclass first = static_cast<jclass>(ResolveObject(jit.Regs()[1]));
            jclass second = static_cast<jclass>(ResolveObject(jit.Regs()[2]));
            if (!first || !second) { ThrowJava("java/lang/NullPointerException", "null JNI class"); break; }
            jit.Regs()[0] = env->IsAssignableFrom(first, second) ? 1 : 0;
            break;
        }
        case SLOT(NewGlobalRef):
            jit.Regs()[0] = NewRef(ResolveObject(jit.Regs()[1]), RefKind::Global); break;
        case SLOT(NewWeakGlobalRef):
            jit.Regs()[0] = NewRef(ResolveObject(jit.Regs()[1]), RefKind::Weak); break;
        case SLOT(NewLocalRef):
            jit.Regs()[0] = AddObjectRef(ResolveObject(jit.Regs()[1])); break;
        case SLOT(DeleteGlobalRef): DeleteRef(jit.Regs()[1], RefKind::Global); break;
        case SLOT(DeleteWeakGlobalRef): DeleteRef(jit.Regs()[1], RefKind::Weak); break;
        case SLOT(DeleteLocalRef): DeleteRef(jit.Regs()[1], RefKind::Local); break;
        case SLOT(IsSameObject): {
            jobject first = ResolveObject(jit.Regs()[1]);
            jobject second = ResolveObject(jit.Regs()[2]);
            jit.Regs()[0] = env->IsSameObject(first, second) ? 1 : 0;
            break;
        }
        case SLOT(GetObjectRefType): {
            std::lock_guard lock(m_mutex);
            auto found = m_refs.find(jit.Regs()[1]);
            jit.Regs()[0] = found == m_refs.end() ? JNIInvalidRefType :
                found->second->kind == RefKind::Local ? JNILocalRefType :
                found->second->kind == RefKind::Global ? JNIGlobalRefType : JNIWeakGlobalRefType;
            break;
        }
        case SLOT(PushLocalFrame): {
            jint capacity = static_cast<jint>(jit.Regs()[1]);
            if (capacity < 0) { jit.Regs()[0] = static_cast<uint32_t>(JNI_ERR); break; }
            jit.Regs()[0] = PushFrame(true) ? JNI_OK : static_cast<uint32_t>(JNI_ERR);
            break;
        }
        case SLOT(PopLocalFrame): jit.Regs()[0] = PopFrame(jit.Regs()[1], true); break;
        case SLOT(EnsureLocalCapacity): {
            jint capacity = static_cast<jint>(jit.Regs()[1]);
            jit.Regs()[0] = static_cast<uint32_t>(capacity < 0 ? JNI_ERR : env->EnsureLocalCapacity(capacity));
            break;
        }
        case SLOT(AllocObject): {
            jclass cls = static_cast<jclass>(ResolveObject(jit.Regs()[1]));
            if (!cls) { ThrowJava("java/lang/NullPointerException", "null allocation class"); break; }
            jit.Regs()[0] = AddObjectRef(env->AllocObject(cls));
            break;
        }
        case SLOT(GetObjectClass): {
            jobject object = ResolveObject(jit.Regs()[1]);
            if (!object) { ThrowJava("java/lang/NullPointerException", "null JNI object"); break; }
            jit.Regs()[0] = AddObjectRef(env->GetObjectClass(object));
            break;
        }
        case SLOT(IsInstanceOf): {
            jobject object = ResolveObject(jit.Regs()[1]);
            jclass cls = static_cast<jclass>(ResolveObject(jit.Regs()[2]));
            if (!cls) { ThrowJava("java/lang/NullPointerException", "null instance class"); break; }
            jit.Regs()[0] = env->IsInstanceOf(object, cls) ? 1 : 0;
            break;
        }
        case SLOT(GetMethodID): case SLOT(GetStaticMethodID): {
            jclass cls = static_cast<jclass>(ResolveObject(jit.Regs()[1]));
            std::string name = String(jit.Regs()[2]);
            std::string signature = String(jit.Regs()[3]);
            if (!cls || HasFailed()) break;
            std::vector<char> params;
            char result;
            if (!ParseSignature(signature, params, result)) { Fail("malformed method lookup descriptor"); break; }
            bool is_static = slot == SLOT(GetStaticMethodID);
            jmethodID id = is_static ? env->GetStaticMethodID(cls, name.c_str(), signature.c_str()) :
                                      env->GetMethodID(cls, name.c_str(), signature.c_str());
            if (!id) {
                jit.Regs()[0] = 0;
                break;
            }
            std::lock_guard lock(m_mutex);
            auto known = m_method_ids.find(id);
            if (known != m_method_ids.end()) { jit.Regs()[0] = known->second; break; }
            if (m_next_method >= 0x60000000) { Fail("jmethodID handle exhaustion"); break; }
            jclass owner = static_cast<jclass>(env->NewGlobalRef(cls));
            if (!owner) { jit.Regs()[0] = 0; break; }
            uint32_t handle = m_next_method;
            m_next_method += 4;
            m_methods.emplace(handle, std::make_shared<Method>(Method{id, owner, is_static,
                                                                      name, signature}));
            m_method_ids.emplace(id, handle);
            jit.Regs()[0] = handle;
            break;
        }
        case SLOT(GetFieldID): case SLOT(GetStaticFieldID): {
            jclass cls = static_cast<jclass>(ResolveObject(jit.Regs()[1]));
            std::string name = String(jit.Regs()[2]);
            std::string signature = String(jit.Regs()[3]);
            if (!cls || HasFailed()) break;
            std::vector<char> unused;
            char type;
            if (!ParseSignature("()" + signature, unused, type) || type == 'V') { Fail("malformed field descriptor"); break; }
            bool is_static = slot == SLOT(GetStaticFieldID);
            jfieldID id = is_static ? env->GetStaticFieldID(cls, name.c_str(), signature.c_str()) :
                                     env->GetFieldID(cls, name.c_str(), signature.c_str());
            if (!id) { jit.Regs()[0] = 0; break; }
            std::lock_guard lock(m_mutex);
            auto known = m_field_ids.find(id);
            if (known != m_field_ids.end()) { jit.Regs()[0] = known->second; break; }
            if (m_next_field >= 0x80000000) { Fail("jfieldID handle exhaustion"); break; }
            jclass owner = static_cast<jclass>(env->NewGlobalRef(cls));
            if (!owner) { jit.Regs()[0] = 0; break; }
            uint32_t handle = m_next_field;
            m_next_field += 4;
            m_fields.emplace(handle, std::make_shared<Field>(Field{id, owner, is_static, type}));
            m_field_ids.emplace(id, handle);
            jit.Regs()[0] = handle;
            break;
        }
        case SLOT(NewString): {
            jint length = static_cast<jint>(jit.Regs()[2]);
            if (length < 0) { Fail("negative NewString length"); break; }
            jchar empty = 0;
            const jchar* text = length ? static_cast<const jchar*>(Memory(jit.Regs()[1], size_t(length) * 2)) : &empty;
            if (text) jit.Regs()[0] = AddObjectRef(env->NewString(text, length));
            break;
        }
        case SLOT(NewStringUTF): {
            if (!jit.Regs()[1]) { jit.Regs()[0] = 0; break; }
            std::string value = String(jit.Regs()[1]);
            if (!HasFailed()) jit.Regs()[0] = AddObjectRef(env->NewStringUTF(value.c_str()));
            break;
        }
        case SLOT(GetStringLength): case SLOT(GetStringUTFLength): {
            jstring text = static_cast<jstring>(ResolveObject(jit.Regs()[1]));
            if (!text) { ThrowJava("java/lang/NullPointerException", "null JNI string"); break; }
            jit.Regs()[0] = slot == SLOT(GetStringLength) ? env->GetStringLength(text) : env->GetStringUTFLength(text);
            break;
        }
        case SLOT(GetStringChars): case SLOT(GetStringCritical): case SLOT(GetStringUTFChars): {
            jstring text = static_cast<jstring>(ResolveObject(jit.Regs()[1]));
            if (!text) { ThrowJava("java/lang/NullPointerException", "null JNI string"); break; }
            uint32_t is_copy = jit.Regs()[2];
            if (is_copy && !Memory(is_copy, 1)) break;
            bool utf = slot == SLOT(GetStringUTFChars);
            jsize length = utf ? env->GetStringUTFLength(text) : env->GetStringLength(text);
            size_t bytes = (size_t(length) + 1) * (utf ? 1 : 2);
            uint32_t address = m_host->GuestAlloc(bytes, 8);
            if (!address) { ThrowJava("java/lang/OutOfMemoryError", "guest string allocation"); break; }
            void* data = Memory(address, bytes);
            if (utf) {
                const char* chars = env->GetStringUTFChars(text, nullptr);
                if (!chars) { m_host->GuestFree(address); jit.Regs()[0] = 0; break; }
                std::memcpy(data, chars, bytes);
                env->ReleaseStringUTFChars(text, chars);
            } else {
                env->GetStringRegion(text, 0, length, static_cast<jchar*>(data));
                static_cast<jchar*>(data)[length] = 0;
            }
            if (env->ExceptionCheck()) { m_host->GuestFree(address); break; }
            jobject owner = env->NewGlobalRef(text);
            if (!owner) { m_host->GuestFree(address); break; }
            {
                std::lock_guard lock(m_mutex);
                m_buffers.emplace(address, Buffer{owner, utf ? 'u' : 'c', length, std::this_thread::get_id()});
            }
            if (is_copy) m_host->MemoryWrite8(is_copy, JNI_TRUE);
            jit.Regs()[0] = address;
            break;
        }
        case SLOT(ReleaseStringChars): case SLOT(ReleaseStringCritical):
            ReleaseBuffer(jit, 'c', JNI_ABORT); break;
        case SLOT(ReleaseStringUTFChars): ReleaseBuffer(jit, 'u', JNI_ABORT); break;
        case SLOT(GetStringRegion): case SLOT(GetStringUTFRegion): {
            jstring text = static_cast<jstring>(ResolveObject(jit.Regs()[1]));
            if (!text) { ThrowJava("java/lang/NullPointerException", "null JNI string"); break; }
            jint start = static_cast<jint>(jit.Regs()[2]);
            jint length = static_cast<jint>(jit.Regs()[3]);
            jsize total = env->GetStringLength(text);
            if (start < 0 || length < 0 || start > total || length > total - start) {
                ThrowJava("java/lang/StringIndexOutOfBoundsException", "guest string region exceeds length"); break;
            }
            uint32_t address = Word(jit, 4);
            if (!length) break;
            if (slot == SLOT(GetStringRegion)) {
                jchar* target = static_cast<jchar*>(Memory(address, size_t(length) * 2));
                if (target) env->GetStringRegion(text, start, length, target);
            } else {
                std::vector<jchar> chars(static_cast<size_t>(length));
                env->GetStringRegion(text, start, length, chars.data());
                if (env->ExceptionCheck()) break;
                size_t bytes = 0;
                for (jchar c : chars) bytes += c && c < 0x80 ? 1 : c < 0x800 ? 2 : 3;
                char* target = static_cast<char*>(Memory(address, bytes));
                if (!target) break;
                for (jchar c : chars) {
                    if (c && c < 0x80) *target++ = static_cast<char>(c);
                    else if (c < 0x800) { *target++ = char(0xc0 | (c >> 6)); *target++ = char(0x80 | (c & 63)); }
                    else { *target++ = char(0xe0 | (c >> 12)); *target++ = char(0x80 | ((c >> 6) & 63)); *target++ = char(0x80 | (c & 63)); }
                }
            }
            break;
        }
        case SLOT(GetArrayLength): {
            jarray array = static_cast<jarray>(ResolveObject(jit.Regs()[1]));
            if (!array) { ThrowJava("java/lang/NullPointerException", "null JNI array"); break; }
            if (!ArrayType(array) && !env->IsInstanceOf(array, m_object_array_class)) { Fail("GetArrayLength on non-array"); break; }
            jit.Regs()[0] = static_cast<uint32_t>(env->GetArrayLength(array));
            break;
        }
        case SLOT(NewObjectArray): {
            jsize length = static_cast<jsize>(jit.Regs()[1]);
            jclass cls = static_cast<jclass>(ResolveObject(jit.Regs()[2]));
            jobject initial = ResolveObject(jit.Regs()[3]);
            if (!cls) { ThrowJava("java/lang/NullPointerException", "null array class"); break; }
            jit.Regs()[0] = AddObjectRef(env->NewObjectArray(length, cls, initial));
            break;
        }
        case SLOT(GetObjectArrayElement): case SLOT(SetObjectArrayElement): {
            jobjectArray array = static_cast<jobjectArray>(ResolveObject(jit.Regs()[1]));
            if (!array) { ThrowJava("java/lang/NullPointerException", "null object array"); break; }
            if (!env->IsInstanceOf(array, m_object_array_class)) { Fail("wrong object array type"); break; }
            jint index = static_cast<jint>(jit.Regs()[2]);
            if (slot == SLOT(GetObjectArrayElement)) jit.Regs()[0] = AddObjectRef(env->GetObjectArrayElement(array, index));
            else env->SetObjectArrayElement(array, index, ResolveObject(jit.Regs()[3]));
            break;
        }
        case SLOT(ExceptionOccurred): jit.Regs()[0] = AddObjectRef(env->ExceptionOccurred()); break;
        case SLOT(ExceptionCheck): jit.Regs()[0] = env->ExceptionCheck() ? 1 : 0; break;
        case SLOT(ExceptionDescribe): env->ExceptionDescribe(); break;
        case SLOT(ExceptionClear): env->ExceptionClear(); break;
        case SLOT(Throw): {
            jthrowable exception = static_cast<jthrowable>(ResolveObject(jit.Regs()[1]));
            jit.Regs()[0] = static_cast<uint32_t>(exception ? env->Throw(exception) : JNI_ERR);
            break;
        }
        case SLOT(ThrowNew): {
            jclass cls = static_cast<jclass>(ResolveObject(jit.Regs()[1]));
            uint32_t message_address = jit.Regs()[2];
            std::string message = message_address ? String(message_address) : std::string{};
            jit.Regs()[0] = static_cast<uint32_t>(cls && !HasFailed() ? env->ThrowNew(cls, message_address ? message.c_str() : nullptr) : JNI_ERR);
            break;
        }
        case SLOT(FatalError): {
            std::string message = String(jit.Regs()[1]);
            Fail(message.c_str());
            break;
        }
        case SLOT(RegisterNatives): {
            jclass cls = static_cast<jclass>(ResolveObject(jit.Regs()[1]));
            jint count = static_cast<jint>(jit.Regs()[3]);
            jit.Regs()[0] = static_cast<uint32_t>(JNI_ERR);
            if (!cls || count < 0 || count > 256) { Fail("invalid RegisterNatives class/count"); break; }
            const uint8_t* table = count ? static_cast<const uint8_t*>(Memory(jit.Regs()[2], size_t(count) * 12)) : nullptr;
            if (count && !table) break;
            struct Entry { std::string name, signature; uint32_t address; };
            std::vector<Entry> entries;
            for (jint i = 0; i < count; ++i) {
                uint32_t words[3];
                std::memcpy(words, table + i * 12, 12);
                entries.push_back({String(words[0]), String(words[1]), words[2]});
                if (!words[2] || !m_host->IsExecutableAddress(words[2] & ~1u)) Fail("RegisterNatives target is not guest code");
            }
            if (HasFailed()) break;
            std::lock_guard lock(m_mutex);
            std::vector<size_t> matches;
            for (const auto& entry : entries) {
                auto found = std::find_if(m_natives.begin(), m_natives.end(), [&](const Native& native) {
                    return entry.name == native.name && entry.signature == native.signature && env->IsSameObject(cls, native.owner);
                });
                if (found == m_natives.end() || (found->address && found->address != entry.address)) {
                    Fail("unexpected/mismatched guest native registration"); break;
                }
                size_t index = size_t(found - m_natives.begin());
                if (std::find(matches.begin(), matches.end(), index) != matches.end()) { Fail("duplicate guest native registration"); break; }
                matches.push_back(index);
            }
            if (HasFailed()) break;
            for (size_t i = 0; i < matches.size(); ++i) {
                m_natives[matches[i]].address = entries[i].address;
                LOGI("guest RegisterNatives: %s%s -> %08x", entries[i].name.c_str(), entries[i].signature.c_str(), entries[i].address);
            }
            jit.Regs()[0] = JNI_OK;
            break;
        }
        case SLOT(UnregisterNatives): {
            jclass cls = static_cast<jclass>(ResolveObject(jit.Regs()[1]));
            if (!cls) { jit.Regs()[0] = static_cast<uint32_t>(JNI_ERR); break; }
            std::lock_guard lock(m_mutex);
            for (auto& native : m_natives) if (env->IsSameObject(cls, native.owner)) native.address = 0;
            jit.Regs()[0] = JNI_OK;
            break;
        }
        case SLOT(GetJavaVM): {
            uint32_t out = jit.Regs()[1];
            if (Memory(out, 4)) { m_host->MemoryWrite32(out, m_vm_pointer); jit.Regs()[0] = JNI_OK; }
            break;
        }
        case SLOT(MonitorEnter): case SLOT(MonitorExit): {
            jobject object = ResolveObject(jit.Regs()[1]);
            if (!object) { ThrowJava("java/lang/NullPointerException", "null monitor"); break; }
            jit.Regs()[0] = static_cast<uint32_t>(slot == SLOT(MonitorEnter) ? env->MonitorEnter(object) : env->MonitorExit(object));
            break;
        }
        case SLOT(NewDirectByteBuffer): {
            size_t index = 2;
            uint64_t capacity = Wide(jit, index);
            uint32_t address = jit.Regs()[1];
            void* data = Memory(address, static_cast<size_t>(capacity));
            if (data && capacity <= static_cast<uint64_t>(INT64_MAX))
                jit.Regs()[0] = AddObjectRef(env->NewDirectByteBuffer(data, static_cast<jlong>(capacity)));
            break;
        }
        case SLOT(GetDirectBufferAddress): case SLOT(GetDirectBufferCapacity): {
            jobject buffer = ResolveObject(jit.Regs()[1]);
            if (!buffer) { jit.Regs()[0] = 0; break; }
            if (slot == SLOT(GetDirectBufferCapacity)) {
                jvalue value{}; value.j = env->GetDirectBufferCapacity(buffer); ReturnValue(jit, 'J', value);
            } else {
                auto address = reinterpret_cast<uintptr_t>(env->GetDirectBufferAddress(buffer));
                auto base = reinterpret_cast<uintptr_t>(m_host->GetGuestMemoryBase());
                if (!address) jit.Regs()[0] = 0;
                else if (address >= base && address - base < m_host->GetGuestMemorySize()) jit.Regs()[0] = static_cast<uint32_t>(address - base);
                else Fail("host-only direct buffer cannot be exposed as a guest address");
            }
            break;
        }
        default:
            LOGE("unsupported JNI slot %u (offset %u)", slot, offset);
            Fail("unsupported JNI slot reached");
            jit.Regs()[0] = 0;
            jit.Regs()[1] = 0;
            break;
    }
}
