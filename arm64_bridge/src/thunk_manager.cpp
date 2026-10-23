// SPDX-License-Identifier: GPL-3.0-or-later
#include "thunk_manager.h"
#include "dynarmic_host.h"
#include "thunks_opensles.h"
#include "thunks_gl.h"
#include <android/log.h>
#include <elf.h>
#include <cstdlib>
#include <exception>

#define LOG_TAG "Arm32Bridge_Thunks"
#if defined(ASPHALT7_FINAL_SILENT)
#define LOGI(...) ((void)0)
#define LOGE(...) ((void)0)
#else
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#endif

extern bool GuestSignalPoll(DynarmicHost&, Dynarmic::A32::Jit&);

namespace {
thread_local uint32_t g_guest_signal_poll_deferral_depth = 0;
}

uint32_t ThunkManager::s_screenWidth = 1213;
uint32_t ThunkManager::s_screenHeight = 540;
uint32_t ThunkManager::s_virtualWidth = 0;
uint32_t ThunkManager::s_virtualHeight = 0;
uint32_t ThunkManager::s_forced_dpi = 0;
uint32_t ThunkManager::s_ui_inset = 0;

ThunkManager::ThunkManager(DynarmicHost& host) : m_host(host) {}
ThunkManager::~ThunkManager() = default;

void ThunkManager::RegisterAllThunks() {
    RegisterLibcThunks();
    RegisterGLThunks();
    RegisterOpenSLESThunks(*this, m_host);
    // FlashFXHandler::Load queries the menu HD flag for every SWF. The HUD
    // needs the HD movie name for the correct widescreen bounds, although the
    // shipped movie itself is the same vector SWF. Keep ordinary menus on the
    // bundled base names and select the HUD variant only for MenuHud.
    RegisterThunk("a7_hud_movie_variant", [](Dynarmic::A32::Jit& jit,
                                             DynarmicHost& host) {
        constexpr uint32_t kMenuHudVtable = 0x413907f0;
        constexpr uint32_t kGetConfigBool = 0x40932974;
        const uint32_t handler = jit.Regs()[4];
        if (handler && host.MemoryRead32(handler) == kMenuHudVtable) {
            jit.Regs()[0] = 1;
        } else {
            const uint32_t attribute = jit.Regs()[0];
            jit.Regs()[0] = host.CallGuestNested(kGetConfigBool, {attribute});
        }
    });
    RegisterThunk("a7_skybox_mesh_render", [](Dynarmic::A32::Jit& jit,
                                               DynarmicHost& host) {
        const uint32_t node = jit.Regs()[0];
        const uint32_t context = jit.Regs()[1];
        BeginHostSkyboxDraw();
        host.CallGuestNested(0x407454f8, {node, context});
        EndHostSkyboxDraw();
    });
    // FakeJniEnv adds its tables after the real JavaVM is known.
}

uint32_t ThunkManager::RegisterThunk(const std::string& name, ThunkHandler handler) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_dispatch_frozen.load(std::memory_order_relaxed) || name.empty() || !handler ||
        m_symbol_to_address.contains(name) || m_next_thunk_addr > 0x00020000 - 8) {
        LOGE("Invalid/duplicate thunk registration or exhausted trampoline range: %s", name.c_str());
        std::abort();
    }
    const uint32_t id = static_cast<uint32_t>(m_id_to_handler.size() + 1);
    const uint32_t address = m_next_thunk_addr;
    m_next_thunk_addr += 8;
    m_host.MemoryWrite32(address, 0xEF000000 | id);
    m_host.MemoryWrite32(address + 4, 0xE12FFF1E);
    m_host.AddExecutableRange(address, 8);
    m_host.InvalidateGuestCode(address, 8);
    m_symbol_to_address.emplace(name, address);
    m_symbol_types.emplace(name, STT_FUNC);
    m_id_to_handler.push_back(std::move(handler));
    return address;
}

void ThunkManager::RegisterSymbol(const std::string& name, uint32_t address) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (name.empty() || !address || address >= m_host.GetGuestMemorySize() || m_symbol_to_address.contains(name)) {
        LOGE("Invalid/duplicate data symbol: %s", name.c_str());
        std::abort();
    }
    m_symbol_to_address.emplace(name, address);
    m_symbol_types.emplace(name, STT_OBJECT);
}

uint32_t ThunkManager::FindRegisteredSymbol(const std::string& name) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    const auto found = m_symbol_to_address.find(name);
    return found == m_symbol_to_address.end() ? 0 : found->second;
}

uint32_t ThunkManager::FindRegisteredThunkId(const std::string& name) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    const auto found = m_symbol_to_address.find(name);
    if (found == m_symbol_to_address.end()) return 0;
    const uint32_t address = found->second;
    if (address < 0x00010000 || address >= 0x00020000 || ((address - 0x00010000) & 7))
        return 0;
    const uint32_t id = (address - 0x00010000) / 8 + 1;
    return id <= m_id_to_handler.size() ? id : 0;
}

uint32_t ThunkManager::ResolveSymbol(const std::string& name, uint8_t expected_type) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    const auto found = m_symbol_to_address.find(name);
    if (found == m_symbol_to_address.end()) return 0;
    if (expected_type != STT_NOTYPE && m_symbol_types.at(name) != expected_type) {
        LOGE("Provider type mismatch: %s expects %u, registered %u", name.c_str(), expected_type, m_symbol_types.at(name));
        return 0;
    }
    return found->second;
}

uint32_t ThunkManager::GetOrCreateThunkAddress(const std::string& name) {
    return FindRegisteredSymbol(name);
}

void ThunkManager::DispatchThunk(uint32_t id, Dynarmic::A32::Jit& jit) {
    try {
        ThunkHandler startup_handler;
        const ThunkHandler* handler = nullptr;
        if (m_dispatch_frozen.load(std::memory_order_acquire)) {
            if (id && id <= m_id_to_handler.size()) handler = &m_id_to_handler[id - 1];
        } else {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (id && id <= m_id_to_handler.size()) startup_handler = m_id_to_handler[id - 1];
            if (startup_handler) handler = &startup_handler;
        }
        // Frozen dispatch is immutable; callbacks can block or re-enter the guest.
        if (handler) (*handler)(jit, m_host);
        else m_host.Fail("Unknown thunk ID");
        if (!m_host.HasFailed() && !IsGuestSignalPollDeferred())
            GuestSignalPoll(m_host, jit);
    } catch (const std::exception& error) {
        LOGE("Thunk %u failed: %s", id, error.what());
        m_host.Fail("C++ exception inside thunk");
    } catch (...) {
        m_host.Fail("Unknown exception inside thunk");
    }
}

void ThunkManager::FreezeDispatch() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_dispatch_frozen.store(true, std::memory_order_release);
    LOGI("Thunk dispatch frozen: %zu handlers", m_id_to_handler.size());
}

void ThunkManager::BeginGuestSignalPollDeferral() {
    if (g_guest_signal_poll_deferral_depth == UINT32_MAX) {
        LOGE("Guest signal-poll deferral depth overflow");
        std::abort();
    }
    ++g_guest_signal_poll_deferral_depth;
}

bool ThunkManager::EndGuestSignalPollDeferral() {
    if (!g_guest_signal_poll_deferral_depth) {
        LOGE("Unbalanced guest signal-poll deferral end");
        return false;
    }
    --g_guest_signal_poll_deferral_depth;
    return true;
}

bool ThunkManager::IsGuestSignalPollDeferred() {
    return g_guest_signal_poll_deferral_depth != 0;
}
