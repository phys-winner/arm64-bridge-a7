// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <jni.h>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace Dynarmic::A32 { class Jit; }
class DynarmicHost;

// The guest owns JNI references, not raw ART pointers. Local handles die with
// their native/PushLocalFrame scope; global handles live until DeleteGlobalRef.
class FakeJniEnv {
public:
    static FakeJniEnv& Instance();
    void SetJavaVM(JavaVM* vm) { m_vm = vm; }
    bool CacheClassLoader(JNIEnv* env, jclass activity_class);
    bool DeclareNatives(JNIEnv* env, jclass cls, const JNINativeMethod* methods, size_t count);
    uint32_t FindNative(JNIEnv* env, jclass cls, const char* name, const char* signature);
    bool AllNativesRegistered() const;
    bool Init(DynarmicHost& host);
    bool HasFailed() const { return m_failed.load(); }

    void AttachHostEnv(JNIEnv* env);
    JNIEnv* GetEnv();
    bool BeginNativeCall(JNIEnv* env);
    void EndNativeCall();
    // Called on actual thread exit, after guest pthread-key destructors.
    void ReleaseCurrentThread();
    uint32_t EnvTableGuestAddr();
    uint32_t VmTableGuestAddr() const { return m_vm_pointer; }
    uint32_t AddObjectRef(jobject object);
    // Returns a real host LOCAL ref; callers must DeleteLocalRef/PopLocalFrame.
    jobject ResolveObject(uint32_t handle);

    void DispatchEnvSlot(uint32_t offset, Dynarmic::A32::Jit& jit);
    void DispatchVmSlot(uint32_t offset, Dynarmic::A32::Jit& jit);

private:
    enum class RefKind { Local, Global, Weak };
    struct Ref {
        jobject object;
        RefKind kind;
        std::thread::id thread;
        uint64_t frame;
    };
    struct Method {
        jmethodID id;
        jclass owner;
        bool is_static;
        std::string name;
        std::string signature;
    };
    struct Field {
        jfieldID id;
        jclass owner;
        bool is_static;
        char type;
    };
    struct Native {
        jclass owner;
        std::string name;
        std::string signature;
        uint32_t address = 0;
    };
    struct Buffer {
        jobject owner;
        char type;
        jsize length;
        std::thread::id thread;
    };
    struct ThreadState;
    static ThreadState& Thread();

    JavaVM* m_vm = nullptr;
    DynarmicHost* m_host = nullptr;
    std::atomic<bool> m_failed{false};
    mutable std::mutex m_mutex;
    uint32_t m_env_functions = 0;
    uint32_t m_vm_pointer = 0;
    uint32_t m_next_ref = 0x00020000;
    uint32_t m_next_method = 0x40000000;
    uint32_t m_next_field = 0x60000000;
    std::vector<uint32_t> m_free_refs;
    std::unordered_map<uint32_t, std::shared_ptr<Ref>> m_refs;
    std::unordered_map<uint32_t, std::shared_ptr<Method>> m_methods;
    std::unordered_map<jmethodID, uint32_t> m_method_ids;
    std::unordered_map<uint32_t, std::shared_ptr<Field>> m_fields;
    std::unordered_map<jfieldID, uint32_t> m_field_ids;
    std::unordered_map<uint32_t, Buffer> m_buffers;
    std::vector<Native> m_natives;
    // Class/ID metadata is deliberately retained for the process, like the
    // loaded guests. No Activity instance is kept in these caches.
    jobject m_class_loader = nullptr;
    jmethodID m_load_class = nullptr;
    jclass m_primitive_classes[8]{};
    jclass m_object_array_class = nullptr;

    bool SelfCheck();
    void Fail(const char* reason);
    void ThrowJava(const char* cls, const char* message);
    void* Memory(uint32_t address, size_t bytes);
    std::string String(uint32_t address);
    uint32_t Word(Dynarmic::A32::Jit& jit, size_t index);
    uint64_t Wide(Dynarmic::A32::Jit& jit, size_t& index);
    uint32_t NewRef(jobject object, RefKind kind);
    void DeleteRef(uint32_t handle, RefKind kind);
    bool PushFrame(bool explicit_frame);
    uint32_t PopFrame(uint32_t result, bool explicit_only);
    std::shared_ptr<Method> GetMethod(uint32_t handle);
    std::shared_ptr<Field> GetField(uint32_t handle);
    std::vector<jvalue> Arguments(Dynarmic::A32::Jit& jit, const std::string& signature,
                                 unsigned variant, size_t first_word);
    void Invoke(Dynarmic::A32::Jit& jit, unsigned slot);
    void AccessField(Dynarmic::A32::Jit& jit, unsigned slot);
    char ArrayType(jarray array);
    void ArrayRegion(jarray array, char type, jsize start, jsize count, void* data, bool write);
    void PrimitiveArray(Dynarmic::A32::Jit& jit, unsigned slot);
    void ReleaseBuffer(Dynarmic::A32::Jit& jit, char expected_type, jint mode);
};
