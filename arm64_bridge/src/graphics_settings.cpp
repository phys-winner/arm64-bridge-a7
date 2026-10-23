// SPDX-License-Identifier: GPL-3.0-or-later
#include "graphics_settings.h"
#include "dynarmic_host.h"
#include "thunk_manager.h"
#include <array>
#include <bit>

namespace {
// Matches GraphicsSettings.java. Values are immutable after bootstrap.
std::array<jint, 5> options{127, 3, 16, 0, 1};
bool Enabled(unsigned bit) { return (options[0] & (1u << bit)) != 0; }

uint32_t ConfigBool(uint32_t index, uint32_t original) {
    switch (index) {
    case 13: case 22: return Enabled(3); // car and traffic shadows
    case 14: return Enabled(4);         // nitro blur
    case 15: return Enabled(5);         // impact blur
    case 16: return Enabled(6);         // high-resolution track textures
    case 55: case 57: return Enabled(2);// dynamic/garage car reflections
    case 72: return Enabled(7);         // VBO geometry path
    case 73: return Enabled(8);         // dynamic geometry batching
    default: return original;
    }
}
uint32_t ConfigInt(uint32_t index, uint32_t original) {
    switch (index) {
    case 0: case 1: return options[1]; // menu/race car detail
    case 46: return options[3];        // texture mip levels to skip
    case 74: return options[4];        // reflection update interval
    default: return original;
    }
}
}

bool InitializeGraphicsSettings(JNIEnv* env) {
    jclass type = env->FindClass("com/gameloft/android/ANMP/GloftA7HM/GraphicsSettings");
    if (!type) return false;
    const jmethodID read = env->GetStaticMethodID(type, "readOptions", "()[I");
    auto values = read ? static_cast<jintArray>(env->CallStaticObjectMethod(type, read)) : nullptr;
    bool valid = values && !env->ExceptionCheck() && env->GetArrayLength(values) == 5;
    if (valid) env->GetIntArrayRegion(values, 0, 5, options.data());
    if (values) env->DeleteLocalRef(values);
    env->DeleteLocalRef(type);
    valid = valid && !env->ExceptionCheck() && options[0] >= 0 && options[0] <= 511 &&
        options[1] >= 1 && options[1] <= 3 &&
        (options[2] == 1 || options[2] == 4 || options[2] == 8 || options[2] == 16) &&
        options[3] >= 0 && options[3] <= 2 &&
        (options[4] == 1 || options[4] == 2 || options[4] == 4);
    return valid;
}

bool RegisterGraphicsSettings(DynarmicHost& host) {
    // Register before FakeJniEnv::Init freezes the dispatch table.
    auto& manager = host.GetThunkManager();
    const std::array<uint32_t, 3> thunks{
        manager.RegisterThunk("a7_graphics_bool", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
            jit.Regs()[5] = ConfigBool(jit.Regs()[5], jit.Regs()[0]); // mov r5,r0
        }),
        manager.RegisterThunk("a7_graphics_int", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
            jit.Regs()[5] = ConfigInt(jit.Regs()[5], jit.Regs()[0]);
        }),
        manager.RegisterThunk("a7_graphics_float", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
            jit.ExtRegs()[16] = jit.Regs()[5] == 71
                ? std::bit_cast<uint32_t>(static_cast<float>(options[2]))
                : jit.Regs()[0]; // vmov s16,r0
        })
    };
    return thunks[0] && thunks[1] && thunks[2] && !host.HasFailed();
}

bool PatchGraphicsSettings(DynarmicHost& host) {
    // Intercept the result of each original lookup, retaining its full bounds,
    // profile priority and capability checks. These instructions are AFTER
    // getBool/getInt/getFloat; r5 still contains the requested attribute ID.
    constexpr std::array<std::array<uint32_t, 2>, 3> sites{{
        {0x409329c0, 0xe1a05000}, {0x40932a9c, 0xe1a05000},
        {0x40932ed0, 0xee080a10}
    }};
    for (const auto& site : sites) {
        if (!host.IsExecutableAddress(site[0]) || host.MemoryRead32(site[0]) != site[1]) {
            host.Fail("Graphics settings getter signature mismatch");
            return false;
        }
    }
    auto& manager = host.GetThunkManager();
    const std::array<uint32_t, 3> thunks{
        manager.FindRegisteredSymbol("a7_graphics_bool"),
        manager.FindRegisteredSymbol("a7_graphics_int"),
        manager.FindRegisteredSymbol("a7_graphics_float")
    };
    for (size_t i = 0; i < sites.size(); ++i) {
        if (!thunks[i]) {
            host.Fail("Graphics settings thunk was not registered before dispatch freeze");
            return false;
        }
        const uint32_t svc = host.MemoryRead32(thunks[i]);
        if ((svc & 0xff000000) != 0xef000000) {
            host.Fail("Graphics settings thunk is not an ARM SVC");
            return false;
        }
        host.MemoryWrite32(sites[i][0], svc);
        host.InvalidateGuestCode(sites[i][0], 4);
    }
    return !host.HasFailed();
}

bool GraphicsAntialiasingEnabled() { return Enabled(0); }
bool GraphicsRoadReflectionsEnabled() { return Enabled(1); }
