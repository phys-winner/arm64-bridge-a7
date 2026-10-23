// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <functional>
#include <mutex>
#include <atomic>

namespace Dynarmic::A32 {
    class Jit;
}

class DynarmicHost;

using ThunkHandler = std::function<void(Dynarmic::A32::Jit& jit, DynarmicHost& host)>;

class ThunkManager {
public:
    ThunkManager(DynarmicHost& host);
    ~ThunkManager();

    void RegisterAllThunks();
    // Returns the guest address of this thunk's trampoline.
    uint32_t RegisterThunk(const std::string& name, ThunkHandler handler);
    void RegisterSymbol(const std::string& name, uint32_t address);

    // Historical name retained for callers; missing symbols now return zero, never a fabricated stub.
    uint32_t GetOrCreateThunkAddress(const std::string& name);
    uint32_t FindRegisteredSymbol(const std::string& name) const;
    uint32_t FindRegisteredThunkId(const std::string& name) const;
    uint32_t ResolveSymbol(const std::string& name, uint8_t expected_type) const;
    void DispatchThunk(uint32_t thunk_id, Dynarmic::A32::Jit& jit);
    void FreezeDispatch();

    // A short guest sequence may defer asynchronous SIGALRM delivery while it
    // owns transient guest memory across several thunk calls.  Deferral is
    // thread-local, nestable, and must be balanced by the owner.
    static void BeginGuestSignalPollDeferral();
    static bool EndGuestSignalPollDeferral();
    static bool IsGuestSignalPollDeferred();

    std::unordered_map<std::string, uint32_t> GetThunkSymbolTable() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_symbol_to_address;
    }

    static uint32_t s_screenWidth;
    static uint32_t s_screenHeight;
    // Virtual screen size reported to the guest for UI scaling; 0 = report the real one.
    static uint32_t s_virtualWidth;
    static uint32_t s_virtualHeight;
    static uint32_t s_forced_dpi;
    static uint32_t s_ui_inset;

private:
    void RegisterGLThunks();
    void RegisterLibcThunks();
    DynarmicHost& m_host;
    uint32_t m_next_thunk_addr = 0x00010000; // Base address for thunk trampolines
    mutable std::mutex m_mutex;
    std::unordered_map<std::string, uint32_t> m_symbol_to_address;
    std::unordered_map<std::string, uint8_t> m_symbol_types;
    std::vector<ThunkHandler> m_id_to_handler;
    std::atomic<bool> m_dispatch_frozen{false};
};
