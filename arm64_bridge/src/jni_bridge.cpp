// SPDX-License-Identifier: GPL-3.0-or-later
#include <jni.h>
#include <android/asset_manager_jni.h>
#include <android/log.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <bit>
#include <condition_variable>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <deque>
#include <exception>
#include <mutex>
#include <limits>
#include <string>
#include <thread>
#include <utility>
#include <vector>
#include "asset_vfs.h"
#include "dynarmic_host.h"
#include "jni_fake_env.h"
#include "thunk_manager.h"
#include "thunks_gl.h"
#include "thunks_opensles.h"
#include "offline_academy.h"
#include "graphics_settings.h"
#include "postprocess_aa.h"

#if defined(ASPHALT7_FINAL_SILENT)
#define LOGI(...) ((void)0)
#define LOGE(...) ((void)0)
#define JNI_LOGI(...) ((void)0)
#define INPUT_LOGI(...) ((void)0)
#elif defined(ASPHALT7_JNI_TELEMETRY)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, "Asphalt7Bridge", __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "Asphalt7Bridge", __VA_ARGS__)
#define JNI_LOGI(...) LOGI(__VA_ARGS__)
#if defined(ASPHALT7_INPUT_TELEMETRY)
#define INPUT_LOGI(...) LOGI(__VA_ARGS__)
#else
#define INPUT_LOGI(...) ((void)0)
#endif
#else
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, "Asphalt7Bridge", __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "Asphalt7Bridge", __VA_ARGS__)
#define JNI_LOGI(...) ((void)0)
#define INPUT_LOGI(...) ((void)0)
#endif

JavaVM* g_jvm = nullptr;
JavaVM* GetHostJavaVM() { return g_jvm; }

namespace {

enum class ClassId : size_t {
    Game,
    GLGame,
    C2DMAndroidUtils,
    GLUtilsDevice,
    NetworkStateReceiver,
    SUtils,
    InAppBilling,
    IabS,
    IabDevice,
    IGPFreemiumActivity,
    GameInstaller,
    GDRMPolicy,
    Misc,
    SendInfo,
    GL2JNILib,
    FacebookAndroidGLSocialLib,
    PlatformAndroid,
    Count,
};

constexpr size_t kClassCount = static_cast<size_t>(ClassId::Count);
constexpr const char* kClassNames[kClassCount] = {
    "com/gameloft/android/ANMP/GloftA7HM/Game",
    "com/gameloft/android/ANMP/GloftA7HM/GLGame",
    "com/gameloft/android/ANMP/GloftA7HM/PushNotification/C2DMAndroidUtils",
    "com/gameloft/android/ANMP/GloftA7HM/GLUtils/Device",
    "com/gameloft/android/ANMP/GloftA7HM/GLUtils/NetworkStateReceiver",
    "com/gameloft/android/ANMP/GloftA7HM/GLUtils/SUtils",
    "com/gameloft/android/ANMP/GloftA7HM/iab/InAppBilling",
    "com/gameloft/android/ANMP/GloftA7HM/iab/s",
    "com/gameloft/android/ANMP/GloftA7HM/iab/utils/Device",
    "com/gameloft/android/ANMP/GloftA7HM/IGPFreemiumActivity",
    "com/gameloft/android/ANMP/GloftA7HM/installer/GameInstaller",
    "com/gameloft/android/ANMP/GloftA7HM/installer/GDRMPolicy",
    "com/gameloft/android/ANMP/GloftA7HM/Misc",
    "com/gameloft/android/ANMP/GloftA7HM/SendInfo",
    "com/gameloft/glf/GL2JNILib",
    "com/gameloft/GLSocialLib/facebook/FacebookAndroidGLSocialLib",
    "com/gameloft/GLSocialLib/PlatformAndroid",
};

jclass g_classes[kClassCount]{};
jobject g_asset_manager_ref = nullptr;
uint32_t g_offline_store_callback_thunk = 0;

// The loaded guest, class metadata and its arena intentionally live until
// process exit. Guest audio and pthread callbacks can outlive the Activity.
DynarmicHost* g_host = nullptr;
enum class LoadState { Empty, Loading, Ready, Failed };
std::atomic<LoadState> g_load_state{LoadState::Empty};
std::mutex g_load_mutex;
std::condition_variable g_load_changed;
std::thread::id g_loading_thread;

void ThrowBridgeError(JNIEnv* env, const char* message) {
    LOGE("%s", message);
    if (!env || env->ExceptionCheck()) return;
    jclass type = env->FindClass("java/lang/IllegalStateException");
    if (type) {
        env->ThrowNew(type, message);
        env->DeleteLocalRef(type);
    }
}

struct NativeFrame {
    bool active = false;

    explicit NativeFrame(JNIEnv* env) {
        // Keep FakeJNI TLS established before guest pthread/TLS teardown can
        // run. This ordering is required when a guest callback returns.
        if (!g_host) return;
        g_host->CurrentJit();
        active = FakeJniEnv::Instance().BeginNativeCall(env);
    }

    ~NativeFrame() {
        if (active) FakeJniEnv::Instance().EndNativeCall();
    }
};

bool ResolveAssetManager(JNIEnv* env, jobject seed, AAssetManager** manager,
                         std::string* external_files_dir,
                         std::string* external_obb_dir) {
    if (!env || !seed || !manager || !external_files_dir || !external_obb_dir) return false;
    *manager = nullptr;
    external_files_dir->clear();
    external_obb_dir->clear();

    jclass context_class = env->FindClass("android/content/Context");
    if (!context_class || env->ExceptionCheck()) return false;

    jobject context = nullptr;
    if (env->IsInstanceOf(seed, context_class)) {
        context = env->NewLocalRef(seed);
    } else {
        jclass activity_thread = env->FindClass("android/app/ActivityThread");
        if (!activity_thread || env->ExceptionCheck()) return false;
        jmethodID current_application = env->GetStaticMethodID(
            activity_thread, "currentApplication", "()Landroid/app/Application;");
        if (!current_application || env->ExceptionCheck()) return false;
        context = env->CallStaticObjectMethod(activity_thread, current_application);
    }
    if (!context || env->ExceptionCheck()) return false;

    jmethodID get_external_files_dir = env->GetMethodID(
        context_class, "getExternalFilesDir", "(Ljava/lang/String;)Ljava/io/File;");
    if (!get_external_files_dir || env->ExceptionCheck()) return false;
    jobject external_dir = env->CallObjectMethod(context, get_external_files_dir, nullptr);
    if (!external_dir || env->ExceptionCheck()) return false;
    jclass file_class = env->FindClass("java/io/File");
    if (!file_class || env->ExceptionCheck()) return false;
    jmethodID get_absolute_path = env->GetMethodID(
        file_class, "getAbsolutePath", "()Ljava/lang/String;");
    if (!get_absolute_path || env->ExceptionCheck()) return false;
    jstring external_path = static_cast<jstring>(
        env->CallObjectMethod(external_dir, get_absolute_path));
    if (!external_path || env->ExceptionCheck()) return false;
    const char* utf_path = env->GetStringUTFChars(external_path, nullptr);
    if (!utf_path || env->ExceptionCheck()) return false;
    external_files_dir->assign(utf_path);
    env->ReleaseStringUTFChars(external_path, utf_path);
    if (external_files_dir->empty()) return false;

    jmethodID get_obb_dir = env->GetMethodID(
        context_class, "getObbDir", "()Ljava/io/File;");
    if (!get_obb_dir || env->ExceptionCheck()) return false;
    jobject obb_dir = env->CallObjectMethod(context, get_obb_dir);
    if (!obb_dir || env->ExceptionCheck()) return false;
    jstring obb_path = static_cast<jstring>(
        env->CallObjectMethod(obb_dir, get_absolute_path));
    if (!obb_path || env->ExceptionCheck()) return false;
    const char* obb_utf_path = env->GetStringUTFChars(obb_path, nullptr);
    if (!obb_utf_path || env->ExceptionCheck()) return false;
    external_obb_dir->assign(obb_utf_path);
    env->ReleaseStringUTFChars(obb_path, obb_utf_path);
    if (external_obb_dir->empty()) return false;

    jmethodID get_assets = env->GetMethodID(
        context_class, "getAssets", "()Landroid/content/res/AssetManager;");
    if (!get_assets || env->ExceptionCheck()) return false;
    jobject assets = env->CallObjectMethod(context, get_assets);
    if (!assets || env->ExceptionCheck()) return false;

    AAssetManager* native_manager = AAssetManager_fromJava(env, assets);
    if (!native_manager || env->ExceptionCheck()) return false;
    g_asset_manager_ref = env->NewGlobalRef(assets);
    if (!g_asset_manager_ref) return false;
    *manager = native_manager;
    return true;
}

bool PatchOfflineGuestNetwork() {
    if (!g_host) return false;

    // GLXPlayerSereverConfig::GLXPlayerSereverConfig() constructs a fresh
    // 12,372-byte GLXPlayerHttp object after loading the local config.  The
    // retired server makes that object retry forever. Keep the config object
    // and its vtable valid, but leave its HTTP member null and return from the
    // constructor before the network object is allocated.
    constexpr uint32_t kServerConfigCtor = 0x40dddfe4;
    constexpr uint32_t kOfflineReturn = 0x40dde080;
    if (!g_host->IsExecutableAddress(kServerConfigCtor) ||
        !g_host->IsExecutableAddress(kOfflineReturn)) {
        LOGE("offline guest network patch target is not executable");
        return false;
    }

    // ARM32 instructions at guest image base + 0xDDE080:
    //   mov r1, #0
    //   str r1, [r4, #0x20]
    //   strb r1, [r4, #0x2c]
    //   mov r0, r4
    //   pop {r4-r8, pc}
    g_host->MemoryWrite32(0x40dde080, 0xe3a01000);
    g_host->MemoryWrite32(0x40dde084, 0xe5841020);
    g_host->MemoryWrite32(0x40dde088, 0xe5c4102c);
    g_host->MemoryWrite32(0x40dde08c, 0xe1a00004);
    g_host->MemoryWrite32(0x40dde090, 0xe8bd81f0);

    // The ABI-compatible C2 constructor is a separate body on this ELF and
    // is the one used by the live server-config call path.
    constexpr uint32_t kServerConfigCtorC2 = 0x40dde0b8;
    constexpr uint32_t kOfflineReturnC2 = 0x40dde154;
    if (!g_host->IsExecutableAddress(kServerConfigCtorC2) ||
        !g_host->IsExecutableAddress(kOfflineReturnC2)) {
        LOGE("offline guest network C2 patch target is not executable");
        return false;
    }
    g_host->MemoryWrite32(0x40dde154, 0xe3a01000);              // mov r1, #0
    g_host->MemoryWrite32(0x40dde158, 0xe5841020);              // str r1, [r4, #0x20]
    g_host->MemoryWrite32(0x40dde15c, 0xe5c4102c);              // strb r1, [r4, #0x2c]
    g_host->MemoryWrite32(0x40dde160, 0xe1a00004);              // mov r0, r4
    g_host->MemoryWrite32(0x40dde164, 0xe8bd81f0);              // pop {r4-r8, pc}

    // GLXPlayerSereverConfig::SendGetServerConfig() otherwise dereferences
    // the null HTTP member at +0x20 for a virtual request.  Branch to its
    // existing failure path: return 1 and clear the caller's result without
    // touching the retired network stack.
    constexpr uint32_t kSendServerConfig = 0x40dde3e4;
    constexpr uint32_t kSendServerConfigFailure = 0x40dde1d0;
    if (!g_host->IsExecutableAddress(kSendServerConfig) ||
        !g_host->IsExecutableAddress(kSendServerConfigFailure)) {
        LOGE("offline guest network send patch target is not executable");
        return false;
    }
    g_host->MemoryWrite32(kSendServerConfig, 0xe3a00001);       // mov r0, #1
    g_host->MemoryWrite32(kSendServerConfig + 4, 0xe5878000);   // str r8, [r7]
    g_host->MemoryWrite32(kSendServerConfig + 8, 0xeaffff77);   // b 0x40dde1d0

    // The main-loop update has its own HTTP virtual-call sequence.  Offline
    // mode has no server state to refresh, so return the native failure value
    // before it reaches that sequence.
    constexpr uint32_t kServerConfigUpdate = 0x40ddfa5c;
    if (!g_host->IsExecutableAddress(kServerConfigUpdate)) {
        LOGE("offline guest network update patch target is not executable");
        return false;
    }
    g_host->MemoryWrite32(kServerConfigUpdate, 0xe3a00000);     // mov r0, #0
    g_host->MemoryWrite32(kServerConfigUpdate + 4, 0xe12fff1e); // bx lr
    LOGI("offline guest network patch installed: GLXPlayerSereverConfig HTTP disabled");
    return !g_host->HasFailed();
}

bool PatchGameplayCameraAspectSetter() {
    if (!g_host || g_host->HasFailed()) return false;

    constexpr uint32_t kCameraSetAspectRatio = 0x405f9af8;
    constexpr std::array<uint32_t, 6> kExpectedInstructions = {
        0xe3a03c03, // mov r3, #0x300
        0xe19020b3, // ldrh r2, [r0, r3]
        0xe580112c, // str r1, [r0, #0x12c]
        0xe3822002, // orr r2, r2, #2
        0xe18020b3, // strh r2, [r0, r3]
        0xe12fff1e, // bx lr
    };
    if (!g_host->IsExecutableAddress(kCameraSetAspectRatio)) {
        LOGE("camera aspect setter patch target is not executable");
        return false;
    }

    const uint32_t thunk_id = g_host->GetThunkManager().FindRegisteredThunkId(
        "a7_CCameraSceneNode_setAspectRatio");
    if (!thunk_id || thunk_id > 0x00ffffffu) {
        LOGE("camera aspect override thunk is unavailable");
        return false;
    }

    if (g_host->MemoryRead32(kCameraSetAspectRatio) ==
        (0xef000000u | thunk_id)) {
        return true;
    }
    for (size_t index = 0; index < kExpectedInstructions.size(); ++index) {
        if (g_host->MemoryRead32(kCameraSetAspectRatio +
                                 static_cast<uint32_t>(index * 4)) !=
            kExpectedInstructions[index]) {
            LOGE("camera aspect setter signature mismatch at +0x%zx", index * 4);
            return false;
        }
    }

    g_host->MemoryWrite32(kCameraSetAspectRatio, 0xef000000u | thunk_id);
    g_host->InvalidateGuestCode(kCameraSetAspectRatio, sizeof(uint32_t));
    LOGI("camera aspect setter hook installed at 0x%08x", kCameraSetAspectRatio);
    return !g_host->HasFailed();
}

bool PatchHudMovieVariant() {
    if (!g_host || g_host->HasFailed()) return false;

    // ARM32 FlashFXHandler::Load calls GetDeviceConfigAttributeBool(19) here.
    // Route that one call through a MenuHud-only override. The menu flag in
    // DeviceConfig.xml stays false, so other SWFs never request missing HD
    // movies. HUD_hd.swf is included as a real vector-movie alias in the OBB.
    constexpr uint32_t kQuery = 0x40d54eb8;
    constexpr uint32_t kExpectedBranch = 0xebef76ad;
    const uint32_t thunk_id = g_host->GetThunkManager().FindRegisteredThunkId(
        "a7_hud_movie_variant");
    if (!thunk_id || thunk_id > 0x00ffffffu ||
        !g_host->IsExecutableAddress(kQuery) ||
        g_host->MemoryRead32(kQuery) != kExpectedBranch) {
        LOGE("HUD movie variant patch signature mismatch");
        return false;
    }
    g_host->MemoryWrite32(kQuery, 0xef000000u | thunk_id);
    g_host->InvalidateGuestCode(kQuery, sizeof(uint32_t));
    return !g_host->HasFailed();
}

bool PatchHudVehicleMotion() {
    if (!g_host || g_host->HasFailed()) return false;

    // BaseHud::SetPosition applies this multiplier to the camera target's
    // vehicle motion before positioning the complete race HUD movie. A fast
    // Class 7 car can push its upper edge outside the logical viewport.
    // Keep the HUD at the movie's own viewport anchor instead.
    constexpr uint32_t kTranslationMultiplier = 0x413b40dc;
    constexpr uint32_t kOriginalValue = 0x3fc00000; // 1.5f
    if (g_host->MemoryRead32(kTranslationMultiplier) != kOriginalValue) {
        LOGE("HUD motion multiplier signature mismatch");
        return false;
    }
    g_host->MemoryWrite32(kTranslationMultiplier, 0);
    return !g_host->HasFailed();
}

void OpenOfflinePurchaseCatalog() {
    JNIEnv* env = FakeJniEnv::Instance().GetEnv();
    const jclass game = g_classes[static_cast<size_t>(ClassId::Game)];
    if (!env || !game) {
        LOGE("offline purchase callback has no live Java environment/Game class");
        return;
    }

    const jmethodID open = env->GetStaticMethodID(game, "OpenAndroidMarket", "()V");
    if (!open || env->ExceptionCheck()) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        LOGE("offline purchase callback cannot resolve Game.OpenAndroidMarket");
        return;
    }
    env->CallStaticVoidMethod(game, open);
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        LOGE("Game.OpenAndroidMarket failed to schedule the offline catalog");
    }
}

bool PatchOfflineFreemiumStoreHandler() {
    if (!g_host || g_host->HasFailed()) return false;

    constexpr char kFreemiumStoreCallback[] =
        "_ZN12MenuFreemium20CBCopenFreemiumStoreERKN7gameswf12FunctionCallE";
    const uint32_t entry = g_host->FindLibrarySymbol("libAndroid.so", kFreemiumStoreCallback);
    if (!entry || !g_host->IsExecutableAddress(entry)) {
        LOGE("freemium store callback symbol is missing or not executable");
        return false;
    }

    const uint32_t thunk = g_offline_store_callback_thunk;
    if (!thunk || !g_host->GetThunkManager().FindRegisteredThunkId(
            "a7_offline_freemium_store")) {
        LOGE("offline freemium store thunk is unavailable");
        return false;
    }

    constexpr uint32_t kLoadPcLiteral = 0xe51ff004; // ldr pc, [pc, #-4]
    if (g_host->MemoryRead32(entry) == kLoadPcLiteral &&
        g_host->MemoryRead32(entry + 4) == thunk) {
        return true;
    }
    if (g_host->MemoryRead32(entry) != 0xe92d41f0 ||
        g_host->MemoryRead32(entry + 4) != 0xe59f423c) {
        LOGE("freemium store callback prologue signature mismatch at 0x%08x", entry);
        return false;
    }

    // FreemiumBar calls this exact guest function after either plus button.
    // Replace its online IAP refresh body with the UI-thread local catalog.
    g_host->MemoryWrite32(entry, kLoadPcLiteral);
    g_host->MemoryWrite32(entry + 4, thunk);
    g_host->InvalidateGuestCode(entry, 8);
    LOGI("offline freemium store handler hook installed at 0x%08x", entry);
    return !g_host->HasFailed();
}

bool PatchObsoleteMenuPrompts() {
    if (!g_host || g_host->HasFailed()) return false;

    struct InstructionPatch {
        uint32_t address;
        uint32_t expected;
        uint32_t replacement;
        const char* name;
    };
    constexpr std::array<InstructionPatch, 5> kPatches = {{
        // These callbacks only display retired online/social or rating UI.
        {0x40b70480, 0xe92d4ff0, 0xe12fff1e, "Facebook invitation"},
        {0x40b6e8b0, 0xe92d4010, 0xe12fff1e, "rate-game invitation"},
        // The help-popup getter gates the one-time garage and tier prompts.
        {0x40b24298, 0xe0801001, 0xe3a00001, "shop help getter"},
        {0x40b2429c, 0xe5d101b4, 0xe12fff1e, "shop help return"},
        // Preserve the tutorial callback's bookkeeping, but return false to
        // the menu movie when the first event has no stars yet.
        {0x40ba3da4, 0x03a05001, 0x03a05000, "tutorial invitation"},
    }};
    for (const auto& patch : kPatches) {
        if (!g_host->IsExecutableAddress(patch.address) ||
            g_host->MemoryRead32(patch.address) != patch.expected) {
            LOGE("obsolete menu prompt signature mismatch: %s at 0x%08x",
                 patch.name, patch.address);
            return false;
        }
    }
    for (const auto& patch : kPatches) {
        g_host->MemoryWrite32(patch.address, patch.replacement);
        g_host->InvalidateGuestCode(patch.address, sizeof(uint32_t));
    }
    return !g_host->HasFailed();
}

bool PatchAudioPlaybackStatusPoll() {
    if (!g_host || g_host->HasFailed()) return false;

    // EmitterObj::IsPlaying is a read-only query of two aligned 32-bit state
    // words at +0x90/+0x94. During a race the render thread polls it while
    // the audio callback owns the emitter mutex for 5-16 ms. The result is
    // only a playback-status hint, so a concurrent transition can be seen on
    // the next poll without blocking a game frame.
    constexpr uint32_t kLockCall = 0x40ec3704;
    constexpr uint32_t kUnlockCall = 0x40ec372c;
    constexpr uint32_t kArmNop = 0xe1a00000;
    if (!g_host->IsExecutableAddress(kLockCall) ||
        !g_host->IsExecutableAddress(kUnlockCall) ||
        g_host->MemoryRead32(kLockCall) != 0xeb010284 ||
        g_host->MemoryRead32(kUnlockCall) != 0xeb010275) {
        LOGE("audio playback-status poll signature mismatch");
        return false;
    }
    g_host->MemoryWrite32(kLockCall, kArmNop);
    g_host->MemoryWrite32(kUnlockCall, kArmNop);
    g_host->InvalidateGuestCode(kLockCall, sizeof(uint32_t));
    g_host->InvalidateGuestCode(kUnlockCall, sizeof(uint32_t));
    return !g_host->HasFailed();
}

bool PatchSkyboxMeshDrawCall() {
    if (!g_host || g_host->HasFailed()) return false;
    constexpr uint32_t kDrawCall = 0x40d8e124;
    constexpr uint32_t kExpected = 0xebe6dcf3;
    const uint32_t thunk_id = g_host->GetThunkManager().FindRegisteredThunkId(
        "a7_skybox_mesh_render");
    if (!thunk_id || !g_host->IsExecutableAddress(kDrawCall) ||
        g_host->MemoryRead32(kDrawCall) != kExpected) {
        LOGE("skybox mesh render call signature mismatch");
        return false;
    }
    g_host->MemoryWrite32(kDrawCall, 0xef000000u | thunk_id);
    g_host->InvalidateGuestCode(kDrawCall, sizeof(uint32_t));
    return !g_host->HasFailed();
}

// Only ordinary loaded cars use the ground/suspension visual target.
static bool HasFilteredVehicleTilt(DynarmicHost& host, uint32_t car) {
    if (!car || uint64_t(car) + 0x15fd > host.GetGuestMemorySize() || host.MemoryRead32(car) != 0x413924a8 ||
        !host.MemoryRead8(car + 0x15fc) || (host.MemoryRead32(car + 0x39c) & 1) ||
        host.MemoryRead32(car + 0x394) == 5 || host.MemoryRead32(car + 0xff4) != 0xffffffffu ||
        (host.MemoryRead32(car + 0xdb8) & 0x2000)) return false;
    const uint32_t rigid = host.MemoryRead32(car + 0x101c);
    if (!rigid) return true;
    if (uint64_t(rigid) + 4 > host.GetGuestMemorySize()) return false;
    const uint32_t body = host.MemoryRead32(rigid);
    return body && uint64_t(body) + 0xd0 <= host.GetGuestMemorySize() &&
        (host.MemoryRead32(body + 0xcc) & 2);
}

static float VehicleTiltAlpha(float reference, uint32_t milliseconds) {
    if (!(reference > 0 && reference < 1)) return reference;
    return static_cast<float>(1 - std::pow(1 - static_cast<double>(reference), milliseconds * .03));
}

// q = swing * twistY; twist leaves the road-up vector unchanged.
static bool SplitVehicleTilt(const std::array<float, 4>& q,
                             std::array<float, 4>& swing, std::array<float, 4>& twist) {
    const double norm = std::sqrt(double(q[0])*q[0] + double(q[1])*q[1] +
                                  double(q[2])*q[2] + double(q[3])*q[3]);
    if (!std::isfinite(norm) || norm < 1e-6) return false;
    const double x=q[0]/norm, y=q[1]/norm, z=q[2]/norm, w=q[3]/norm;
    const double length = std::hypot(y, w);
    if (!std::isfinite(length) || length < 1e-6) return false;
    swing = {float((w*x+y*z)/length), 0, float((w*z-y*x)/length), float(length)};
    twist = {0, float(y/length), 0, float(w/length)};
    return true;
}

static bool RegisterVehicleVisualTilt(DynarmicHost& host) {
    // Executed at bootstrap: force/reset weights and the original 30-Hz response.
    if (VehicleTiltAlpha(.25f, 0) != 0 || VehicleTiltAlpha(1, 0) != 1 ||
        std::abs(VehicleTiltAlpha(.25f, 100) - .578125f) > 1e-6f ||
        std::abs(VehicleTiltAlpha(.9f, 100) - .999f) > 1e-6f) return false;
    std::array<float, 4> swing{}, twist{};
    const float root_half = std::sqrt(.5f);
    if (!SplitVehicleTilt({.5f,.5f,.5f,.5f}, swing, twist) ||
        std::abs(swing[0]-root_half) > 1e-6f || swing[2] != 0 ||
        std::abs(swing[3]-root_half) > 1e-6f ||
        std::abs(twist[1]-root_half) > 1e-6f || std::abs(twist[3]-root_half) > 1e-6f ||
        SplitVehicleTilt({1,0,0,0}, swing, twist)) return false;
    auto& thunks = host.GetThunkManager();
    if (!thunks.RegisterThunk("a7_vehicle_bank_pitch",
            [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                auto& fp = jit.ExtRegs();
                const float spring = std::bit_cast<float>(fp[14]);
                const float ground = std::bit_cast<float>(fp[15]);
                // Preserve the alternate physics/crash path's original subtraction.
                fp[15] = std::bit_cast<uint32_t>(HasFilteredVehicleTilt(host, jit.Regs()[4])
                    ? ground - spring : spring - ground);
            })) return false;
    if (!thunks.RegisterThunk("a7_vehicle_bank_output",
            [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                auto& regs = jit.Regs();
                const uint32_t caller = regs[14];
                if ((caller == 0x40c69bac || caller == 0x40d19d2c) && regs[2] && regs[3] &&
                    HasFilteredVehicleTilt(host, regs[0])) {
                    for (uint32_t offset : {0u, 4u, 8u}) host.MemoryWrite32(regs[1] + offset, 0);
                    host.MemoryWrite32(regs[1] + 12, 0x3f800000);
                    regs[15] = caller;
                } else {
                    // Original push {r4,r5,r6,r7,r8,lr}; nested target queries
                    // continue through the guest's original bank calculation.
                    regs[13] -= 24;
                    unsigned offset = 0;
                    for (unsigned reg : {4u, 5u, 6u, 7u, 8u, 14u}) {
                        host.MemoryWrite32(regs[13] + offset, regs[reg]);
                        offset += 4;
                    }
                }
            })) return false;
    return thunks.RegisterThunk("a7_vehicle_visual_target",
            [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
                auto& fp = jit.ExtRegs();
                const uint32_t car = jit.Regs()[4];
                if (HasFilteredVehicleTilt(host, car)) {
                    // Reuse one scratch packet per rendering thread. The existing
                    // main quaternion is the filter history; no second filter state.
                    static thread_local uint32_t packet = 0;
                    if (!packet) packet = host.GuestAlloc(80, 16);
                    if (!packet) { host.Fail("Vehicle quaternion scratch allocation failed"); return; }
                    const uint32_t fpscr = jit.Fpscr();
                    unsigned offset = 0;
                    for (unsigned reg : {21u, 22u, 19u, 16u}) {
                        host.MemoryWrite32(packet + offset, fp[reg]);
                        offset += 4;
                    }
                    host.CallGuestNested(0x40c58744, {car, packet + 16, 1, 1});
                    host.CallGuestNested(0x40a8a8f8, {packet + 32, packet, packet + 16});
                    float reference = std::bit_cast<float>(fp[29]);
                    const uint32_t milliseconds = host.MemoryRead32(car + 0x3b4);
                    if (!host.HasFailed() && reference == .9f) {
                        const std::array<float, 4> previous = {
                            std::bit_cast<float>(fp[26]), std::bit_cast<float>(fp[27]),
                            std::bit_cast<float>(fp[25]), std::bit_cast<float>(fp[28])};
                        std::array<float, 4> target{}, previous_swing{}, previous_twist{},
                                             target_swing{}, target_twist{};
                        for (unsigned i=0; i<4; ++i)
                            target[i] = std::bit_cast<float>(host.MemoryRead32(packet+32+i*4));
                        if (SplitVehicleTilt(previous, previous_swing, previous_twist) &&
                            SplitVehicleTilt(target, target_swing, target_twist)) {
                            const auto blend = [&](uint32_t output, const auto& a, const auto& b, float weight) {
                                host.CallGuestNested(0x40694f2c, {output,
                                    std::bit_cast<uint32_t>(a[0]), std::bit_cast<uint32_t>(a[1]),
                                    std::bit_cast<uint32_t>(a[2]), std::bit_cast<uint32_t>(a[3]),
                                    std::bit_cast<uint32_t>(b[0]), std::bit_cast<uint32_t>(b[1]),
                                    std::bit_cast<uint32_t>(b[2]), std::bit_cast<uint32_t>(b[3]),
                                    std::bit_cast<uint32_t>(weight)});
                            };
                            // Collision contact needs fast heading response, but normal
                            // suspension tilt. Reuse the original guest interpolator.
                            blend(packet+48, previous_swing, target_swing, VehicleTiltAlpha(.25f, milliseconds));
                            blend(packet+64, previous_twist, target_twist, VehicleTiltAlpha(reference, milliseconds));
                            host.CallGuestNested(0x40a8a8f8, {packet+32, packet+48, packet+64});
                            reference = 1; // Existing final normalization publishes this result.
                        }
                    }
                    jit.SetFpscr(fpscr);
                    if (host.HasFailed()) return;
                    offset = 0;
                    for (unsigned reg : {21u, 22u, 19u, 16u}) {
                        fp[reg] = host.MemoryRead32(packet + 32 + offset);
                        offset += 4;
                    }
                    fp[29] = std::bit_cast<uint32_t>(VehicleTiltAlpha(reference, milliseconds));
                    // Rebuild target dot previous after folding the bank. Guest
                    // shortest-arc selection, nlerp/slerp and normalization follow.
                    float dot = 0;
                    for (auto pair : {std::pair{21u,26u}, std::pair{22u,27u},
                                      std::pair{19u,25u}, std::pair{16u,28u}}) {
                        volatile float product = std::bit_cast<float>(fp[pair.first]) *
                                                 std::bit_cast<float>(fp[pair.second]);
                        dot += product;
                    }
                    fp[15] = std::bit_cast<uint32_t>(dot);
                } else {
                    // Displaced vmla.f32 s15,s16,s28, with separate FP32 multiply.
                    volatile float product = std::bit_cast<float>(fp[16]) * std::bit_cast<float>(fp[28]);
                    fp[15] = std::bit_cast<uint32_t>(std::bit_cast<float>(fp[15]) + product);
                }
            }) != 0;
}

bool PatchVehicleVisualTilt() {
    if (!g_host || g_host->HasFailed()) return false;
    struct Patch { uint32_t address, expected; const char* thunk; };
    constexpr Patch patches[] = {
        {0x40c58744, 0xe92d41f0, "a7_vehicle_bank_output"},
        {0x40c58848, 0xee777a67, "a7_vehicle_bank_pitch"},
        {0x40c58ce0, 0xee487a0e, "a7_vehicle_visual_target"},
    };
    if (g_host->MemoryRead32(0x40a8a8f8) != 0xed923a01 ||
        g_host->MemoryRead32(0x40694f2c) != 0xe24dd010 ||
        g_host->MemoryRead32(0x40c69ba8) != 0xebffbae5 ||
        g_host->MemoryRead32(0x40d19d28) != 0xebfcfa85) {
        LOGE("vehicle visual quaternion helper signature mismatch");
        return false;
    }
    for (const auto& patch : patches) {
        const uint32_t thunk = g_host->GetThunkManager().FindRegisteredThunkId(patch.thunk);
        if (!thunk || !g_host->IsExecutableAddress(patch.address) ||
            g_host->MemoryRead32(patch.address) != patch.expected) {
            LOGE("vehicle visual tilt signature mismatch");
            return false;
        }
    }
    for (const auto& patch : patches) {
        g_host->MemoryWrite32(patch.address, 0xef000000u |
            g_host->GetThunkManager().FindRegisteredThunkId(patch.thunk));
        g_host->InvalidateGuestCode(patch.address, sizeof(uint32_t));
    }
    return !g_host->HasFailed();
}


bool PatchRaceFloorContactDetail() {
    if (!g_host || g_host->HasFailed()) return false;
    constexpr uint32_t kDetailArgument = 0x40a60a9c;
    if (!g_host->IsExecutableAddress(kDetailArgument) ||
        g_host->MemoryRead32(kDetailArgument) != 0xe1a02006 ||
        g_host->MemoryRead32(kDetailArgument+4) != 0xeb004a04) {
        LOGE("race floor contact detail signature mismatch");
        return false;
    }
    // AI culling used one ray in place of four different wheel heights.
    // Switching those representations creates a false vertical velocity on
    // slopes. Use the player's four-contact path; retain the traffic shortcut.
    g_host->MemoryWrite32(kDetailArgument, 0xe3a02001); // mov r2,#1
    g_host->InvalidateGuestCode(kDetailArgument, sizeof(uint32_t));
    return !g_host->HasFailed();
}

bool GuestOnLoad(JNIEnv* env, const char* library) {
    if (!g_host || std::string(library) != "libAndroid.so") {
        LOGE("unexpected guest JNI library: %s", library ? library : "<null>");
        return false;
    }
    if (!g_host->RunLibraryConstructors(library) || g_host->HasFailed()) return false;

    const uint32_t entry = g_host->FindLibrarySymbol(library, "JNI_OnLoad");
    if (!entry) {
        LOGE("missing JNI_OnLoad in %s", library);
        return false;
    }

    NativeFrame frame(env);
    if (!frame.active) return false;
    auto& jni = FakeJniEnv::Instance();
    const uint32_t version = g_host->RunFunction(entry, {jni.VmTableGuestAddr(), 0});
    LOGI("guest JNI_OnLoad: %s -> %08x", library, version);
    return (version == JNI_VERSION_1_2 || version == JNI_VERSION_1_4 ||
            version == JNI_VERSION_1_6) &&
           !env->ExceptionCheck() && !jni.HasFailed() && !g_host->HasFailed();
}

bool Bootstrap(JNIEnv* env, jobject seed) {
    if (!env || !seed || env->PushLocalFrame(32) != JNI_OK) return false;
    struct Pop {
        JNIEnv* env;
        ~Pop() { env->PopLocalFrame(nullptr); }
    } pop{env};

    AAssetManager* manager = nullptr;
    std::string external_files_dir;
    std::string external_obb_dir;
    if (!ResolveAssetManager(env, seed, &manager, &external_files_dir, &external_obb_dir)) {
        LOGE("unable to resolve Context/AssetManager for Asphalt guest");
        return false;
    }
    if (!InitializeGraphicsSettings(env)) return false;
    if (!AssetVfs::Prepare(manager, external_files_dir, external_obb_dir)) return false;

    g_host = new DynarmicHost;
    if (!g_host->Initialize()) return false;

    g_offline_store_callback_thunk = g_host->GetThunkManager().RegisterThunk(
        "a7_offline_freemium_store",
        [](Dynarmic::A32::Jit&, DynarmicHost&) { OpenOfflinePurchaseCatalog(); });
    if (!g_offline_store_callback_thunk) return false;
    if (!RegisterOfflineAcademy(*g_host, external_files_dir)) return false;
    if (!RegisterGraphicsSettings(*g_host)) return false;
    if (!RegisterVehicleVisualTilt(*g_host)) return false;

    auto& jni = FakeJniEnv::Instance();
    if (!jni.Init(*g_host)) return false;
    if (!g_host->LoadGuestLibraries(manager)) return false;
    if (!PatchGameplayCameraAspectSetter()) return false;
    if (!PatchHudMovieVariant()) return false;
    if (!PatchHudVehicleMotion()) return false;
    if (!PatchOfflineGuestNetwork()) return false;
    if (!PatchOfflineAcademy(*g_host)) return false;
    if (!PatchOfflineFreemiumStoreHandler()) return false;
    if (!PatchObsoleteMenuPrompts()) return false;
    if (!PatchAudioPlaybackStatusPoll()) return false;
    if (!PatchSkyboxMeshDrawCall()) return false;
    if (!PatchVehicleVisualTilt()) return false;
    if (!PatchRaceFloorContactDetail()) return false;
    if (!PatchGraphicsSettings(*g_host)) return false;
    if (!g_host->FinalizeReadOnlyMemory()) return false;
    if (!GuestOnLoad(env, "libAndroid.so")) return false;
    if (jni.HasFailed() || g_host->HasFailed()) return false;

    // OpenSL ES buffer-queue callbacks arrive from Android's real-time audio
    // thread.  The guest expects those callbacks to refill the next PCM
    // buffer; without a dedicated pump the first queue can play and then
    // silently starve.  Start it only after JNI/bootstrap is complete so the
    // callback can use the fully initialized guest and thunk tables.
    StartAudioThread(g_host);

    LOGI("Asphalt 7 bridge bootstrap OK: arm64 host, stored ARM32 guest");
    return true;
}

bool EnsureLoaded(JNIEnv* env, jobject seed) {
    {
        std::unique_lock lock(g_load_mutex);
        while (g_load_state.load(std::memory_order_acquire) == LoadState::Loading) {
            if (g_loading_thread == std::this_thread::get_id()) {
                lock.unlock();
                ThrowBridgeError(env, "recursive Asphalt bridge bootstrap");
                return false;
            }
            g_load_changed.wait(lock);
        }
        if (g_load_state.load(std::memory_order_acquire) == LoadState::Ready) return true;
        if (g_load_state.load(std::memory_order_acquire) == LoadState::Failed) {
            lock.unlock();
            ThrowBridgeError(env, "Asphalt bridge bootstrap previously failed; restart is required");
            return false;
        }
        g_loading_thread = std::this_thread::get_id();
        g_load_state.store(LoadState::Loading, std::memory_order_release);
    }

    bool ok = false;
    try {
        ok = Bootstrap(env, seed);
    } catch (const std::exception& error) {
        LOGE("Asphalt bootstrap exception: %s", error.what());
    } catch (...) {
        LOGE("unknown Asphalt bootstrap exception");
    }

    {
        std::lock_guard lock(g_load_mutex);
        g_load_state.store(ok ? LoadState::Ready : LoadState::Failed,
                           std::memory_order_release);
        g_loading_thread = {};
    }
    g_load_changed.notify_all();
    if (!ok) ThrowBridgeError(env, "Asphalt bridge bootstrap failed; see logcat");
    return ok;
}

std::string JniMangle(const char* value, bool signature = false) {
    std::string result;
    if (!value) return result;
    for (const unsigned char* cursor = reinterpret_cast<const unsigned char*>(value); *cursor; ++cursor) {
        const unsigned char character = *cursor;
        if (signature && (character == '(' || character == ')')) continue;
        if ((character >= 'A' && character <= 'Z') ||
            (character >= 'a' && character <= 'z') ||
            (character >= '0' && character <= '9')) {
            result.push_back(static_cast<char>(character));
        } else if (character == '_') {
            result += "_1";
        } else if (character == ';') {
            result += "_2";
        } else if (character == '[') {
            result += "_3";
        } else if (character == '/') {
            result.push_back('_');
        } else {
            constexpr char digits[] = "0123456789abcdef";
            result += "_0";
            result.push_back(digits[(character >> 12) & 0xF]);
            result.push_back(digits[(character >> 8) & 0xF]);
            result.push_back(digits[(character >> 4) & 0xF]);
            result.push_back(digits[character & 0xF]);
        }
    }
    return result;
}

uint32_t FindGuestJniExport(ClassId class_id, const char* name, const char* signature) {
    if (!g_host || !name) return 0;
    const size_t index = static_cast<size_t>(class_id);
    if (index >= kClassCount) return 0;
    const std::string base = "Java_" + JniMangle(kClassNames[index]) + "_" + JniMangle(name);
    if (uint32_t entry = g_host->FindLibrarySymbol("libAndroid.so", base)) return entry;
    if (signature) {
        const std::string long_name = base + "__" + JniMangle(signature, true);
        if (uint32_t entry = g_host->FindLibrarySymbol("libAndroid.so", long_name)) return entry;
    }
    return 0;
}

uint64_t InvokeGuest(JNIEnv* env, jobject receiver, ClassId class_id,
                     const char* name, const char* signature,
                     const std::vector<uint32_t>& arguments,
                     jobject* object_result = nullptr) {
    if (object_result) *object_result = nullptr;
    try {
        if (!EnsureLoaded(env, receiver)) return 0;
        if (!g_host || g_host->HasFailed() || FakeJniEnv::Instance().HasFailed()) {
            ThrowBridgeError(env, "Asphalt bridge has an unresolved runtime failure");
            return 0;
        }

        NativeFrame frame(env);
        if (!frame.active) {
            ThrowBridgeError(env, "Asphalt guest JNI frame failed");
            return 0;
        }

        auto& jni = FakeJniEnv::Instance();
        const jclass owner = g_classes[static_cast<size_t>(class_id)];
        uint32_t entry = jni.FindNative(env, owner, name, signature);
        if (!entry) {
            entry = FindGuestJniExport(class_id, name, signature);
            if (entry) JNI_LOGI("guest static JNI export: %s.%s%s -> %08x",
                            kClassNames[static_cast<size_t>(class_id)], name, signature, entry);
        }
        if (!entry) {
            ThrowBridgeError(env, "Asphalt guest native is not registered");
            return 0;
        }

        std::vector<uint32_t> words;
        words.reserve(arguments.size() + 2);
        words.push_back(jni.EnvTableGuestAddr());
        words.push_back(jni.AddObjectRef(receiver));
        words.insert(words.end(), arguments.begin(), arguments.end());
        if (!words[0] || !words[1] || jni.HasFailed() || env->ExceptionCheck()) return 0;

        const uint32_t low = g_host->RunFunction(entry, words);
        const uint32_t high = g_host->CurrentJit().Regs()[1];
        if (g_host->HasFailed() || jni.HasFailed()) {
            if (!env->ExceptionCheck())
                ThrowBridgeError(env, "Asphalt guest JNI execution failed");
            return 0;
        }
        if (object_result && low && !env->ExceptionCheck())
            *object_result = jni.ResolveObject(low);
        return uint64_t(low) | (uint64_t(high) << 32);
    } catch (const std::exception& error) {
        ThrowBridgeError(env, error.what());
        return 0;
    } catch (...) {
        ThrowBridgeError(env, "unknown exception at Asphalt JNI boundary");
        return 0;
    }
}

uint32_t Ref(jobject object) {
    return FakeJniEnv::Instance().AddObjectRef(object);
}

uint32_t FloatBits(jfloat value) {
    return std::bit_cast<uint32_t>(value);
}

uint32_t Low(jlong value) {
    return static_cast<uint32_t>(static_cast<uint64_t>(value));
}

uint32_t High(jlong value) {
    return static_cast<uint32_t>(static_cast<uint64_t>(value) >> 32);
}

// pauseGame/resumeGame can flush a large amount of guest state after a race
// (especially after a wreck).  The legacy Java activity calls them from the
// Android UI thread, where a synchronous Dynarmic call can trip Android's
// five-second input-dispatch watchdog.  Queue the guest transition for the GL
// thread, which already owns the frame-level guest execution.  The Java call
// remains non-blocking while the ordering relative to stateChanged is kept by
// consuming this queue before the renderer lifecycle callback.
enum class PendingGuestLifecycle : uint8_t {
    None = 0,
    Pause = 1,
    Resume = 2,
};

std::atomic<PendingGuestLifecycle> g_pending_guest_lifecycle{
    PendingGuestLifecycle::None};
std::atomic<int32_t> g_pending_guest_focus{-1};
std::atomic<bool> g_guest_window_focused{true};
std::atomic<int32_t> g_pending_guest_orientation{-1};

static void QueueGuestLifecycle(PendingGuestLifecycle command) {
    g_pending_guest_lifecycle.store(command, std::memory_order_release);
}

static void QueueGuestFocus(bool focused) {
    g_guest_window_focused.store(focused, std::memory_order_release);
    g_pending_guest_focus.store(focused ? 1 : 0, std::memory_order_release);
}

static void QueueGuestOrientation(int32_t orientation) {
    if (orientation < 0) return;
    g_pending_guest_orientation.store(orientation, std::memory_order_release);
}

static void ConsumeGuestLifecycle(JNIEnv* env, jobject receiver) {
    const PendingGuestLifecycle command =
        g_pending_guest_lifecycle.exchange(PendingGuestLifecycle::None,
                                            std::memory_order_acq_rel);
    const int32_t focus =
        g_pending_guest_focus.exchange(-1, std::memory_order_acq_rel);
    const int32_t orientation =
        g_pending_guest_orientation.exchange(-1, std::memory_order_acq_rel);
    if (focus >= 0) {
        (void)InvokeGuest(env, receiver, ClassId::GLGame, "isWindowFocus", "(Z)V",
                          {focus ? 1u : 0u});
    }
    if (orientation >= 0) {
        (void)InvokeGuest(env, receiver, ClassId::GLGame,
                          "nativeChangedOrientation", "(I)V",
                          {static_cast<uint32_t>(orientation)});
    }
    if (command == PendingGuestLifecycle::Pause) {
        (void)InvokeGuest(env, receiver, ClassId::GLGame, "pauseGame", "()V", {});
        return;
    }
    if (command == PendingGuestLifecycle::Resume) {
        (void)InvokeGuest(env, receiver, ClassId::GLGame, "resumeGame", "()V", {});
        ResumeAudioPlayback();
    }
}

#define WRAP_V0(FN, CID, NAME, SIG) \
    static void FN(JNIEnv* env, jobject receiver) { \
        (void)InvokeGuest(env, receiver, CID, NAME, SIG, {}); \
    }
#define WRAP_I0(FN, CID, NAME, SIG) \
    static jint FN(JNIEnv* env, jobject receiver) { \
        return static_cast<jint>(InvokeGuest(env, receiver, CID, NAME, SIG, {})); \
    }
#define WRAP_B0(FN, CID, NAME, SIG) \
    static jboolean FN(JNIEnv* env, jobject receiver) { \
        return InvokeGuest(env, receiver, CID, NAME, SIG, {}) ? JNI_TRUE : JNI_FALSE; \
    }
#define WRAP_V1I(FN, CID, NAME, SIG) \
    static void FN(JNIEnv* env, jobject receiver, jint a) { \
        (void)InvokeGuest(env, receiver, CID, NAME, SIG, {static_cast<uint32_t>(a)}); \
    }
#define WRAP_I1J(FN, CID, NAME, SIG) \
    static jint FN(JNIEnv* env, jobject receiver, jlong a) { \
        return static_cast<jint>(InvokeGuest(env, receiver, CID, NAME, SIG, {Low(a), High(a)})); \
    }
#define WRAP_B1J(FN, CID, NAME, SIG) \
    static jboolean FN(JNIEnv* env, jobject receiver, jlong a) { \
        return InvokeGuest(env, receiver, CID, NAME, SIG, {Low(a), High(a)}) ? JNI_TRUE : JNI_FALSE; \
    }
#define WRAP_V1J(FN, CID, NAME, SIG) \
    static void FN(JNIEnv* env, jobject receiver, jlong a) { \
        (void)InvokeGuest(env, receiver, CID, NAME, SIG, {Low(a), High(a)}); \
    }
#define WRAP_V2I(FN, CID, NAME, SIG) \
    static void FN(JNIEnv* env, jobject receiver, jint a, jint b) { \
        (void)InvokeGuest(env, receiver, CID, NAME, SIG, \
                          {static_cast<uint32_t>(a), static_cast<uint32_t>(b)}); \
    }
#define WRAP_V3I(FN, CID, NAME, SIG) \
    static void FN(JNIEnv* env, jobject receiver, jint a, jint b, jint c) { \
        (void)InvokeGuest(env, receiver, CID, NAME, SIG, \
                          {static_cast<uint32_t>(a), static_cast<uint32_t>(b), static_cast<uint32_t>(c)}); \
    }
#define WRAP_V4I(FN, CID, NAME, SIG) \
    static void FN(JNIEnv* env, jobject receiver, jint a, jint b, jint c, jint d) { \
        (void)InvokeGuest(env, receiver, CID, NAME, SIG, \
                          {static_cast<uint32_t>(a), static_cast<uint32_t>(b), \
                           static_cast<uint32_t>(c), static_cast<uint32_t>(d)}); \
    }
#define WRAP_V1B(FN, CID, NAME, SIG) \
    static void FN(JNIEnv* env, jobject receiver, jboolean a) { \
        (void)InvokeGuest(env, receiver, CID, NAME, SIG, {a ? 1u : 0u}); \
    }
#define WRAP_V1I1B(FN, CID, NAME, SIG) \
    static void FN(JNIEnv* env, jobject receiver, jint a, jboolean b) { \
        (void)InvokeGuest(env, receiver, CID, NAME, SIG, \
                          {static_cast<uint32_t>(a), b ? 1u : 0u}); \
    }
#define WRAP_V3F(FN, CID, NAME, SIG) \
    static void FN(JNIEnv* env, jobject receiver, jfloat a, jfloat b, jfloat c) { \
        (void)InvokeGuest(env, receiver, CID, NAME, SIG, \
                          {FloatBits(a), FloatBits(b), FloatBits(c)}); \
    }
#define WRAP_V1S(FN, CID, NAME, SIG) \
    static void FN(JNIEnv* env, jobject receiver, jstring a) { \
        (void)InvokeGuest(env, receiver, CID, NAME, SIG, {Ref(a)}); \
    }
#define WRAP_V2S(FN, CID, NAME, SIG) \
    static void FN(JNIEnv* env, jobject receiver, jstring a, jstring b) { \
        (void)InvokeGuest(env, receiver, CID, NAME, SIG, {Ref(a), Ref(b)}); \
    }
#define WRAP_V3S(FN, CID, NAME, SIG) \
    static void FN(JNIEnv* env, jobject receiver, jstring a, jstring b, jstring c) { \
        (void)InvokeGuest(env, receiver, CID, NAME, SIG, {Ref(a), Ref(b), Ref(c)}); \
    }
#define WRAP_V4S(FN, CID, NAME, SIG) \
    static void FN(JNIEnv* env, jobject receiver, jstring a, jstring b, jstring c, jstring d) { \
        (void)InvokeGuest(env, receiver, CID, NAME, SIG, \
                          {Ref(a), Ref(b), Ref(c), Ref(d)}); \
    }
#define WRAP_V1O(FN, CID, NAME, SIG) \
    static void FN(JNIEnv* env, jobject receiver, jobject a) { \
        (void)InvokeGuest(env, receiver, CID, NAME, SIG, {Ref(a)}); \
    }
#define WRAP_V2I1S(FN, CID, NAME, SIG) \
    static void FN(JNIEnv* env, jobject receiver, jint a, jint b, jstring c) { \
        (void)InvokeGuest(env, receiver, CID, NAME, SIG, \
                          {static_cast<uint32_t>(a), static_cast<uint32_t>(b), Ref(c)}); \
    }
#define WRAP_V1I2S(FN, CID, NAME, SIG) \
    static void FN(JNIEnv* env, jobject receiver, jint a, jstring b, jstring c) { \
        (void)InvokeGuest(env, receiver, CID, NAME, SIG, \
                          {static_cast<uint32_t>(a), Ref(b), Ref(c)}); \
    }
#define WRAP_V3I1S(FN, CID, NAME, SIG) \
    static void FN(JNIEnv* env, jobject receiver, jint a, jint b, jint c, jstring d) { \
        (void)InvokeGuest(env, receiver, CID, NAME, SIG, \
                          {static_cast<uint32_t>(a), static_cast<uint32_t>(b), \
                           static_cast<uint32_t>(c), Ref(d)}); \
    }
#define WRAP_V2I1O(FN, CID, NAME, SIG) \
    static void FN(JNIEnv* env, jobject receiver, jint a, jint b, jobject c) { \
        (void)InvokeGuest(env, receiver, CID, NAME, SIG, \
                          {static_cast<uint32_t>(a), static_cast<uint32_t>(b), Ref(c)}); \
    }
#define WRAP_V1I1J(FN, CID, NAME, SIG) \
    static void FN(JNIEnv* env, jobject receiver, jint a, jlong b) { \
        (void)InvokeGuest(env, receiver, CID, NAME, SIG, \
                          {static_cast<uint32_t>(a), 0u, Low(b), High(b)}); \
    }
#define WRAP_V1I1O1B(FN, CID, NAME, SIG) \
    static void FN(JNIEnv* env, jobject receiver, jint a, jobject b, jboolean c) { \
        (void)InvokeGuest(env, receiver, CID, NAME, SIG, \
                          {static_cast<uint32_t>(a), Ref(b), c ? 1u : 0u}); \
    }
#define WRAP_I3O(FN, CID, NAME, SIG) \
    static jint FN(JNIEnv* env, jobject receiver, jobject a, jobject b, jobject c) { \
        return static_cast<jint>(InvokeGuest(env, receiver, CID, NAME, SIG, \
                                              {Ref(a), Ref(b), Ref(c)})); \
    }
#define WRAP_O1S(FN, CID, NAME, SIG) \
    static jobject FN(JNIEnv* env, jobject receiver, jstring a) { \
        jobject result = nullptr; \
        (void)InvokeGuest(env, receiver, CID, NAME, SIG, {Ref(a)}, &result); \
        return result; \
    }
#define WRAP_O1I(FN, CID, NAME, SIG) \
    static jobject FN(JNIEnv* env, jobject receiver, jint a) { \
        jobject result = nullptr; \
        (void)InvokeGuest(env, receiver, CID, NAME, SIG, \
                          {static_cast<uint32_t>(a)}, &result); \
        return result; \
    }
#define WRAP_O1O(FN, CID, NAME, SIG) \
    static jobject FN(JNIEnv* env, jobject receiver, jobject a) { \
        jobject result = nullptr; \
        (void)InvokeGuest(env, receiver, CID, NAME, SIG, {Ref(a)}, &result); \
        return result; \
    }
#define WRAP_J0(FN, CID, NAME, SIG) \
    static jlong FN(JNIEnv* env, jobject receiver) { \
        return static_cast<jlong>(InvokeGuest(env, receiver, CID, NAME, SIG, {})); \
    }
#define WRAP_O0(FN, CID, NAME, SIG) \
    static jobject FN(JNIEnv* env, jobject receiver) { \
        jobject result = nullptr; \
        (void)InvokeGuest(env, receiver, CID, NAME, SIG, {}, &result); \
        return result; \
    }
#define WRAP_B1IO1(FN, CID, NAME, SIG) \
    static jboolean FN(JNIEnv* env, jobject receiver, jint a, jobject b, jboolean c) { \
        return InvokeGuest(env, receiver, CID, NAME, SIG, \
                           {static_cast<uint32_t>(a), Ref(b), c ? 1u : 0u}) ? JNI_TRUE : JNI_FALSE; \
    }

WRAP_V3F(Native_Game_nativeAccelerator, ClassId::Game, "nativeAccelerator", "(FFF)V")
WRAP_I0(Native_Game_nativeCanInterrupt, ClassId::Game, "nativeCanInterrupt", "()I")
WRAP_V4S(Native_Game_nativeGetInfo, ClassId::Game, "nativeGetInfo",
         "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V")
WRAP_V0(Native_Game_nativeInit, ClassId::Game, "nativeInit", "()V")
WRAP_V1I(Native_Game_nativeOnKeyDown, ClassId::Game, "nativeOnKeyDown", "(I)V")
WRAP_V1I(Native_Game_nativeOnKeyUp, ClassId::Game, "nativeOnKeyUp", "(I)V")
WRAP_V3F(Native_Game_nativeOrientation, ClassId::Game, "nativeOrientation", "(FFF)V")

WRAP_V0(Native_GLGame_Init, ClassId::GLGame, "Init", "()V")
WRAP_V0(Native_GLGame_backFromGLLive, ClassId::GLGame, "backFromGLLive", "()V")
WRAP_B0(Native_GLGame_isLoading, ClassId::GLGame, "isLoading", "()Z")
static void Native_GLGame_isWindowFocus(JNIEnv* env, jobject receiver, jboolean focused) {
    (void)env;
    (void)receiver;
    QueueGuestFocus(focused != JNI_FALSE);
}
static void Native_GLGame_nativeChangedOrientation(JNIEnv* env, jobject receiver,
                                                   jint orientation) {
    (void)env;
    (void)receiver;
    QueueGuestOrientation(static_cast<int32_t>(orientation));
}
WRAP_V1I1B(Native_GLGame_nativeHandleKey, ClassId::GLGame, "nativeHandleKey", "(IZ)V")
WRAP_V1O(Native_GLGame_nativeHandleMessage, ClassId::GLGame, "nativeHandleMessage",
         "(Landroid/os/Message;)V")
WRAP_V0(Native_GLGame_nativeHideKeyboard, ClassId::GLGame, "nativeHideKeyboard", "()V")
WRAP_V0(Native_GLGame_nativeLaunchIGPAfterInterrupt, ClassId::GLGame,
        "nativeLaunchIGPAfterInterrupt", "()V")
WRAP_V0(Native_GLGame_nativeLaunchWSAfterInterrupt, ClassId::GLGame,
        "nativeLaunchWSAfterInterrupt", "()V")
WRAP_V0(Native_GLGame_nativeOnLowMemory, ClassId::GLGame, "nativeOnLowMemory", "()V")
WRAP_V1S(Native_GLGame_nativeSplashScreenFunction, ClassId::GLGame,
         "nativeSplashScreenFunction", "(Ljava/lang/String;)V")
WRAP_V1S(Native_GLGame_nativeonEditorAction, ClassId::GLGame, "nativeonEditorAction",
         "(Ljava/lang/String;)V")
WRAP_V3I(Native_GLGame_onIGPClose, ClassId::GLGame, "onIGPClose", "(III)V")

static void Native_GLGame_pauseGame(JNIEnv* env, jobject receiver) {
    (void)env;
    (void)receiver;
    QueueGuestLifecycle(PendingGuestLifecycle::Pause);
    PauseAudioPlayback();
}

WRAP_V0(Native_GLGame_requestIGM, ClassId::GLGame, "requestIGM", "()V")

static void Native_GLGame_resumeGame(JNIEnv* env, jobject receiver) {
    (void)env;
    (void)receiver;
    QueueGuestLifecycle(PendingGuestLifecycle::Resume);
}

WRAP_V1S(Native_GLGame_saveIGPMessage, ClassId::GLGame, "saveIGPMessage",
         "(Ljava/lang/String;)V")
WRAP_V1I2S(Native_GLGame_updateCashWithAmount, ClassId::GLGame,
          "updateCashWithAmount", "(ILjava/lang/String;Ljava/lang/String;)V")
WRAP_V2I1S(Native_GLGame_updateIGPReward, ClassId::GLGame, "updateIGPReward",
           "(IILjava/lang/String;)V")

// The original ARM32 runtime initializes its push JNI method table here.
// The Java side is an offline no-op shim; this call only preserves that ABI
// setup so Game.nativeInit can use the shared JNI environment safely.
WRAP_V0(Native_C2DMAndroidUtils_nativeInit, ClassId::C2DMAndroidUtils,
        "nativeInit", "()V")

WRAP_V0(Native_GLUtils_Device_nativeInit, ClassId::GLUtilsDevice, "nativeInit", "()V")
WRAP_V1I(Native_GLUtils_NetworkStateReceiver_setNetworkState,
         ClassId::NetworkStateReceiver, "setNetworkState", "(I)V")
WRAP_V0(Native_GLUtils_SUtils_nativeInit, ClassId::SUtils, "nativeInit", "()V")

WRAP_V1O(Native_InAppBilling_nativeInit, ClassId::InAppBilling, "nativeInit",
         "(Landroid/content/Context;)V")
WRAP_O1O(Native_InAppBilling_nativeSendData, ClassId::InAppBilling, "nativeSendData",
         "(Landroid/os/Bundle;)Landroid/os/Bundle;")
WRAP_I3O(Native_IabS_bq, ClassId::IabS, "bq",
         "(Ljava/security/PublicKey;Ljava/lang/String;Ljava/lang/String;)I")
WRAP_O1S(Native_IabS_gk, ClassId::IabS, "gk", "(Ljava/lang/String;)Ljava/security/PublicKey;")
WRAP_J0(Native_IabS_gn, ClassId::IabS, "gn", "()J")
WRAP_B1J(Native_IabS_in, ClassId::IabS, "in", "(J)Z")
WRAP_V1J(Native_IabS_rn, ClassId::IabS, "rn", "(J)V")
WRAP_V0(Native_IabDevice_nativeInit, ClassId::IabDevice, "nativeInit", "()V")
WRAP_V0(Native_IGPFreemiumActivity_nativeInit, ClassId::IGPFreemiumActivity,
        "nativeInit", "()V")

WRAP_V0(Native_GameInstaller_initNative, ClassId::GameInstaller, "initNative", "()V")
WRAP_V0(Native_GameInstaller_nativeStart, ClassId::GameInstaller, "nativeStart", "()V")
WRAP_V0(Native_GameInstaller_getPublicKey, ClassId::GameInstaller, "getPublicKey", "()V")
WRAP_V3I(Native_GDRMPolicy_initNativeAP, ClassId::GDRMPolicy, "initNativeAP", "(III)V")
WRAP_O1I(Native_GDRMPolicy_getConstString, ClassId::GDRMPolicy, "getConstString",
         "(I)Ljava/lang/String;")
WRAP_O0(Native_GDRMPolicy_getPrefFile, ClassId::GDRMPolicy, "getPrefFile",
        "()Ljava/lang/String;")
WRAP_I1J(Native_GDRMPolicy_nativeAllow, ClassId::GDRMPolicy, "nativeAllow", "(J)I")
WRAP_V2I(Native_GDRMPolicy_processServer, ClassId::GDRMPolicy, "processServer", "(II)V")
WRAP_V2I(Native_GDRMPolicy_setConst, ClassId::GDRMPolicy, "setConst", "(II)V")
WRAP_V1I1J(Native_GDRMPolicy_setLongConst, ClassId::GDRMPolicy, "setLongConst", "(IJ)V")
WRAP_V1J(Native_GDRMPolicy_setTime, ClassId::GDRMPolicy, "setTime", "(J)V")

WRAP_V0(Native_Misc_nativeDestroy, ClassId::Misc, "nativeDestroy", "()V")
WRAP_V3I1S(Native_Misc_nativeInit, ClassId::Misc, "nativeInit",
           "(IIILjava/lang/String;)V")
WRAP_V0(Native_Misc_nativeRender, ClassId::Misc, "nativeRender", "()V")
WRAP_V2I(Native_Misc_nativeResize, ClassId::Misc, "nativeResize", "(II)V")
WRAP_V0(Native_SendInfo_initMethods, ClassId::SendInfo, "initMethods", "()V")
// Sensor callbacks are delivered by Android's sensor looper, which is the
// Activity/UI thread on this title.  Calling the retained guest synchronously
// from that callback can keep the UI thread inside Dynarmic long enough for
// Android 16 to report an input ANR (most visibly after the car is wrecked).
// Keep only the latest sample here and consume it from the GL thread in
// Native_GL2_step, where the rest of the guest frame already runs.
struct PendingSensorSamples {
    bool accelerometer = false;
    bool gyroscope = false;
    float accelerometer_x = 0.0f;
    float accelerometer_y = 0.0f;
    float accelerometer_z = 0.0f;
    float gyroscope_x = 0.0f;
    float gyroscope_y = 0.0f;
    float gyroscope_z = 0.0f;
};

std::mutex g_sensor_mutex;
PendingSensorSamples g_pending_sensor_samples;

static void QueueAccelerometerSample(jfloat x, jfloat y, jfloat z) {
    std::lock_guard lock(g_sensor_mutex);
    g_pending_sensor_samples.accelerometer_x = x;
    g_pending_sensor_samples.accelerometer_y = y;
    g_pending_sensor_samples.accelerometer_z = z;
    g_pending_sensor_samples.accelerometer = true;
}

static void QueueGyroscopeSample(jfloat x, jfloat y, jfloat z) {
    std::lock_guard lock(g_sensor_mutex);
    g_pending_sensor_samples.gyroscope_x = x;
    g_pending_sensor_samples.gyroscope_y = y;
    g_pending_sensor_samples.gyroscope_z = z;
    g_pending_sensor_samples.gyroscope = true;
}

static PendingSensorSamples TakePendingSensorSamples() {
    std::lock_guard lock(g_sensor_mutex);
    PendingSensorSamples samples = g_pending_sensor_samples;
    g_pending_sensor_samples.accelerometer = false;
    g_pending_sensor_samples.gyroscope = false;
    return samples;
}

static void Native_GL2_accelerometerEvent(JNIEnv*, jobject, jfloat x, jfloat y,
                                          jfloat z) {
    QueueAccelerometerSample(x, y, z);
}

WRAP_V0(Native_GL2_destroy, ClassId::GL2JNILib, "destroy", "()V")
WRAP_I0(Native_GL2_getNumExtraContext, ClassId::GL2JNILib, "getNumExtraContext", "()I")
WRAP_V0(Native_GL2_getViewSettings, ClassId::GL2JNILib, "getViewSettings", "()V")
static void Native_GL2_gyroscopeEvent(JNIEnv*, jobject, jfloat x, jfloat y,
                                      jfloat z) {
    QueueGyroscopeSample(x, y, z);
}
WRAP_V0(Native_GL2_init, ClassId::GL2JNILib, "init", "()V")
WRAP_V0(Native_GL2_initGL, ClassId::GL2JNILib, "initGL", "()V")
WRAP_V1I(Native_GL2_orientationChanged, ClassId::GL2JNILib, "orientationChanged", "(I)V")
WRAP_B1IO1(Native_GL2_processTouchpadAsPointer, ClassId::GL2JNILib,
           "processTouchpadAsPointer", "(ILandroid/view/ViewParent;Z)Z")
// Kept as a real wrapper instead of the generic macro so the projection
// adapter can use the same logical dimensions that the renderer gives the
// retained ARM32 guest.  The Java renderer still owns the physical GL
// viewport; this only records the guest-visible surface size and forwards
// the original resize ABI unchanged.
static void Native_GL2_resize(JNIEnv* env, jobject receiver, jint width, jint height);
WRAP_V1B(Native_GL2_setGyrosEnabled, ClassId::GL2JNILib, "setGyrosEnabled", "(Z)V")
WRAP_V1I(Native_GL2_setNumExtraContext, ClassId::GL2JNILib, "setNumExtraContext", "(I)V")
WRAP_V3S(Native_GL2_setPaths, ClassId::GL2JNILib, "setPaths",
         "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V")

static void Native_GL2_stateChanged(JNIEnv* env, jobject receiver, jboolean active) {
    ConsumeGuestLifecycle(env, receiver);
    (void)InvokeGuest(env, receiver, ClassId::GL2JNILib, "stateChanged", "(Z)V",
                      {active ? 1u : 0u});
    // Renderer.b() is the surface-created/resume edge; the EGL teardown path
    // calls the same native method with false.  Keep the host player in the
    // same lifecycle state so pause/background and surface recreation do not
    // leave a stale queue running or strand a held callback.
    if (active) ResumeAudioPlayback();
    else PauseAudioPlayback();
}

static jboolean Native_GLGame_grantOfflinePurchase(JNIEnv* env, jobject receiver,
                                                   jint currency, jint amount) {
    if (currency < 0 || currency > 1 || amount <= 0) return JNI_FALSE;
    if (!EnsureLoaded(env, receiver) || !g_host || g_host->HasFailed()) return JNI_FALSE;

    NativeFrame frame(env);
    if (!frame.active) {
        ThrowBridgeError(env, "Asphalt guest JNI frame failed");
        return JNI_FALSE;
    }

    // These guest addresses are from the retained ARM32 libAndroid.so ELF.
    // Application::updateIGPRewards performs the real profile mutation,
    // persistence and freemium-bar refresh for currency 0 (Stars) and 1
    // (Cash).  No billing receipt or server response is fabricated here.
    constexpr uint32_t kGameGetApp = 0x40932064;
    constexpr uint32_t kApplicationUpdateIGPRewards = 0x40897118;

    const uint32_t app = g_host->RunFunction(kGameGetApp, {});
    if (!app || g_host->HasFailed()) return JNI_FALSE;

    g_host->RunFunction(kApplicationUpdateIGPRewards,
                        {app, static_cast<uint32_t>(amount),
                         static_cast<uint32_t>(currency)});
    if (g_host->HasFailed()) return JNI_FALSE;

    LOGI("OfflinePurchase grant currency=%d amount=%d", static_cast<int>(currency),
         static_cast<int>(amount));
    return JNI_TRUE;
}

namespace currency_reset {
constexpr uint32_t kGetProfileManager = 0x4093694c;
constexpr uint32_t kGetPlayerProfile = 0x40a00cdc;
constexpr uint32_t kGetCareerManager = 0x40936bcc;
constexpr uint32_t kGetLanguage = 0x40b23e04;
constexpr uint32_t kGetCash = 0x40b24338;
constexpr uint32_t kGetAdditionalStars = 0x40b24330;
constexpr uint32_t kGetDisplayedStars = 0x4097dd6c;
constexpr uint32_t kSetCash = 0x40b24398;
constexpr uint32_t kSetAdditionalStars = 0x40b24390;
constexpr uint32_t kCanWeSave = 0x40a02a44;
constexpr uint32_t kSaveCurrentProfile = 0x40a0b6a8;
constexpr uint32_t kRefreshFreemiumBar = 0x40b728a4;
constexpr uint32_t kCurrentProfileIdOffset = 0x4e4b8;

struct Signature { uint32_t address, first, second; };
constexpr Signature kSignatures[] = {
    {kGetProfileManager, 0xe92d41f0, 0xe59f4070},
    {kGetPlayerProfile, 0xe3003fa8, 0xe0030193},
    {kGetCareerManager, 0xe92d41f0, 0xe59f406c},
    {kGetLanguage, 0xe5900120, 0xe12fff1e},
    {kGetCash, 0xe28000e4, 0xeaffffe8},
    {kGetAdditionalStars, 0xe28000ec, 0xeaffffea},
    {kGetDisplayedStars, 0xe92d47f0, 0xe5903008},
    {kSetCash, 0xe28000e4, 0xeaffffe7},
    {kSetAdditionalStars, 0xe28000ec, 0xeaffffe9},
    {kCanWeSave, 0xe59f3028, 0xe92d4010},
    {kSaveCurrentProfile, 0xe92d4ff0, 0xe30e64b0},
    {kRefreshFreemiumBar, 0xe92d45f0, 0xe59f412c},
};

// 0 idle; 1 requested; 2 executing. The UI thread only changes this atomic.
std::atomic<uint8_t> pending{0};

static bool Validate() {
    if (!g_host || g_host->HasFailed()) return false;
    for (const auto& s : kSignatures) {
        if (!g_host->IsExecutableAddress(s.address) ||
            g_host->MemoryRead32(s.address) != s.first ||
            g_host->MemoryRead32(s.address + 4) != s.second) {
            LOGE("CurrencyReset signature mismatch at 0x%08x", s.address);
            return false;
        }
    }
    return !g_host->HasFailed();
}

static uint32_t GetCurrentProfile(uint32_t manager) {
    if (!manager || g_host->HasFailed()) return 0;
    const uint32_t id = g_host->MemoryRead32(manager + kCurrentProfileIdOffset);
    if (id > 4 || g_host->HasFailed()) return 0;
    return g_host->RunFunction(kGetPlayerProfile, {manager, id});
}

struct Result {
    bool verified_zero = false;
    bool mutation_started = false;
};

// Only the render thread calls this, between retained guest frames.
static Result Execute(JNIEnv* env) {
    Result result;
    if (!Validate()) return result;
    NativeFrame frame(env);
    if (!frame.active) return result;

    const uint32_t manager = g_host->RunFunction(kGetProfileManager, {});
    const uint32_t profile = GetCurrentProfile(manager);
    const uint32_t career = g_host->RunFunction(kGetCareerManager, {});
    if (!manager || !profile || !career || g_host->HasFailed()) return result;

    const int32_t old_cash = static_cast<int32_t>(g_host->RunFunction(kGetCash, {profile}));
    const int32_t old_additional = static_cast<int32_t>(g_host->RunFunction(kGetAdditionalStars, {profile}));
    const int32_t old_total = static_cast<int32_t>(g_host->RunFunction(kGetDisplayedStars, {career}));
    if (g_host->HasFailed()) return result;
    const int64_t next = int64_t(old_additional) - int64_t(old_total);
    if (next < std::numeric_limits<int32_t>::min() ||
        next > std::numeric_limits<int32_t>::max()) {
        LOGE("CurrencyReset star subtraction overflow: additional=%d total=%d", old_additional, old_total);
        return result;
    }
    // CanWeSave is a preflight, not a promise about a later I/O operation.
    if (!g_host->RunFunction(kCanWeSave, {manager}) || g_host->HasFailed()) return result;

    result.mutation_started = true;
    g_host->RunFunction(kSetCash, {profile, 0});
    if (g_host->HasFailed()) return result;
    g_host->RunFunction(kSetAdditionalStars, {profile, static_cast<uint32_t>(static_cast<int32_t>(next))});
    if (g_host->HasFailed()) return result;

    // Stock cheat and local reward paths use these exact save arguments.
    // The retained function is void: its r0 is deliberately ignored.
    g_host->RunFunction(kSaveCurrentProfile, {manager, 1, 0, 1});
    if (g_host->HasFailed()) return result;
    g_host->RunFunction(kRefreshFreemiumBar, {});
    if (g_host->HasFailed()) return result;

    const int32_t cash = static_cast<int32_t>(g_host->RunFunction(kGetCash, {profile}));
    const int32_t total = static_cast<int32_t>(g_host->RunFunction(kGetDisplayedStars, {career}));
    result.verified_zero = !g_host->HasFailed() && cash == 0 && total == 0;
    LOGI("CurrencyReset cash=%d->%d stars=%d->%d additional=%d->%d verified=%d save_requested=1 persistence_unconfirmed=1",
         old_cash, cash, old_total, total, old_additional, static_cast<int32_t>(next), result.verified_zero);
    return result;
}

static void Finish(JNIEnv* env, Result result) {
    if (!env || env->ExceptionCheck()) return;
    jclass type = env->FindClass("com/gameloft/android/ANMP/GloftA7HM/CurrencyReset");
    if (!type) return; // JNI lookup exception remains visible, as usual.
    const jmethodID finish = env->GetStaticMethodID(type, "finish", "(ZZ)V");
    if (finish) env->CallStaticVoidMethod(type, finish,
                                        result.verified_zero ? JNI_TRUE : JNI_FALSE,
                                        result.mutation_started ? JNI_TRUE : JNI_FALSE);
    env->DeleteLocalRef(type);
}
} // namespace currency_reset

static jint Native_GLGame_getCurrencyResetLanguage(JNIEnv* env, jclass) {
    // Game.openBrowser -> CurrencyReset.open runs inside the guest GL callback.
    // This prevents a future accidental UI-thread call from running guest code.
    if (!g_host || !g_host->IsJitRunning() || !currency_reset::Validate()) return 1;
    NativeFrame frame(env);
    if (!frame.active) return 1;
    const uint32_t manager = g_host->RunFunction(currency_reset::kGetProfileManager, {});
    const uint32_t profile = currency_reset::GetCurrentProfile(manager);
    if (!profile || g_host->HasFailed()) return 1;
    const uint32_t language = g_host->RunFunction(currency_reset::kGetLanguage, {profile});
    return !g_host->HasFailed() && language >= 1 && language <= 11 ? language : 1;
}

static jboolean Native_GLGame_requestCurrencyReset(JNIEnv*, jclass) {
    uint8_t idle = 0;
    return currency_reset::pending.compare_exchange_strong(idle, 1)
        ? JNI_TRUE : JNI_FALSE;
}

static void ProcessPendingCurrencyReset(JNIEnv* env) {
    uint8_t requested = 1;
    if (!currency_reset::pending.compare_exchange_strong(requested, 2)) return;
    const auto result = currency_reset::Execute(env);
    currency_reset::pending.store(0);
    currency_reset::Finish(env, result);
}


static uint32_t g_auto_splash_handler = 0;
static uint8_t g_auto_splash_handler_frames = 0;
static bool g_auto_splash_continue_sent = false;
struct PendingTouchEvent {
    jint event;
    jint x;
    jint y;
    jint pointer_id;
};
static constexpr size_t kMaxPendingTouchEvents = 128;
static std::mutex g_touch_events_mutex;
static std::deque<PendingTouchEvent> g_pending_touch_events;

static void QueueTouchEvent(jint event, jint x, jint y, jint pointer_id) {
    std::lock_guard lock(g_touch_events_mutex);
    const PendingTouchEvent pending{event, x, y, pointer_id};
    if (event == 2 && !g_pending_touch_events.empty()) {
        PendingTouchEvent& last = g_pending_touch_events.back();
        if (last.event == 2 && last.pointer_id == pointer_id) {
            last = pending;
            return;
        }
    }
    if (g_pending_touch_events.size() >= kMaxPendingTouchEvents) {
        for (auto it = g_pending_touch_events.begin();
             it != g_pending_touch_events.end(); ++it) {
            if (it->event == 2) {
                g_pending_touch_events.erase(it);
                break;
            }
        }
        if (g_pending_touch_events.size() >= kMaxPendingTouchEvents) {
            if (event == 2) return;
            g_pending_touch_events.pop_front();
        }
    }
    g_pending_touch_events.push_back(pending);
}

static void DispatchQueuedTouchEvents(JNIEnv* env, jobject receiver) {
    if (!g_host || g_host->HasFailed()) return;

    std::vector<PendingTouchEvent> events;
    {
        std::lock_guard lock(g_touch_events_mutex);
        const size_t count = std::min<size_t>(g_pending_touch_events.size(), 32);
        events.reserve(count);
        for (size_t i = 0; i < count; ++i) {
            const PendingTouchEvent& next = g_pending_touch_events.front();
            // The game polls button state during step(). If a short tap's
            // press and release are both drained before that step, it sees
            // only the released state. Preserve at least one guest frame
            // between edges for each pointer while retaining queue order.
            const bool edge = next.event == 0 || next.event == 1;
            if (edge && std::any_of(events.begin(), events.end(),
                    [&](const PendingTouchEvent& dispatched) {
                        return dispatched.pointer_id == next.pointer_id &&
                               (dispatched.event == 0 || dispatched.event == 1);
                    })) {
                break;
            }
            events.push_back(next);
            g_pending_touch_events.pop_front();
        }
    }

    for (const PendingTouchEvent& pending : events) {
        // The obsolete splash prompt is advanced by the ready-handler path
        // below. Every real touch must reach the guest as soon as it arrives;
        // the former five-second startup guard also blocked the live menu.
        INPUT_LOGI("dispatch queued touch event=%d x=%d y=%d pointer=%d",
                   pending.event, pending.x, pending.y, pending.pointer_id);
        if (g_host->HasFailed()) continue;
        (void)InvokeGuest(env, receiver, ClassId::GL2JNILib, "touchEvent",
                          "(IIII)V",
                          {static_cast<uint32_t>(pending.event),
                           static_cast<uint32_t>(pending.x),
                           static_cast<uint32_t>(pending.y),
                           static_cast<uint32_t>(pending.pointer_id)});
    }
}

// Presentation is deliberately invariant. The race-state query below may
// update only the active 3D camera projection and audio routing; it must never
// change the framebuffer rectangle or the Java surface geometry.
static std::atomic<int8_t> g_last_race_wide_mode{-1};
static std::atomic<uint8_t> g_guest_audio_init_state{0};
static bool g_guest_audio_queue_tuned = false;
static uint32_t g_guest_menu_music_name = 0;
static uint16_t g_guest_menu_music_retry = 0;
static bool g_guest_menu_music_active = false;
static uint32_t g_guest_menu_music_last_id = 0xffffffffu;
static int8_t g_guest_menu_music_last_playing = -1;
static int8_t g_guest_menu_music_last_actual_playing = -1;
static uint8_t g_guest_menu_music_probe_logs = 0;
static std::atomic<int32_t> g_surface_width{0};
static std::atomic<int32_t> g_surface_height{0};
static std::atomic<bool> g_renderer_wide_viewport_ready{false};
static uint32_t g_cached_race_camera = 0;
static uint32_t g_cached_race_camera_node_ref = 0;
static uint32_t g_cached_race_camera_node = 0;
static uint32_t g_last_projection_camera = 0;
static uint32_t g_last_projection_node = 0;
static uint32_t g_last_projection_aspect_bits = 0;
static int8_t g_last_projection_wide = -1;
#if defined(ASPHALT7_GL_TELEMETRY)
static uint32_t g_last_trace_camera = 0xffffffffu;
static uint32_t g_last_trace_camera_mode = 0xffffffffu;
static uint32_t g_last_trace_race_camera_state = 0xffffffffu;
static uint32_t g_last_trace_camera_target = 0xffffffffu;
static uint32_t g_last_trace_camera_node = 0xffffffffu;
#endif

static void Native_GL2_resize(JNIEnv* env, jobject receiver, jint width, jint height) {
    // Java reports the physical EGL surface only when that surface is created
    // or genuinely resized. Keep it invariant across menu/race transitions.
    // The guest's native Flash aspect adapter and hit-tests need that same
    // physical size; hiding it behind a 16:9 canvas stretches the UI twice.
    PublishHostDefaultFramebufferSurfaceSize(width, height);
    g_surface_width.store(width, std::memory_order_release);
    g_surface_height.store(height, std::memory_order_release);
    const bool wide_viewport = width > 0 && height > 0 &&
                               static_cast<int64_t>(width) * 9 >
                                   static_cast<int64_t>(height) * 16;
    g_renderer_wide_viewport_ready.store(wide_viewport,
                                         std::memory_order_release);
    PublishHostGameplayAspectRatio(0, 0);

    // Keep one full-surface presentation on every screen. In particular, do
    // not turn the physical surface into a second geometry at the race
    // boundary: that was the source of alternating frames on wide devices.
    SetHostDefaultFramebufferWideMode(false);
    (void)InvokeGuest(env, receiver, ClassId::GL2JNILib, "resize", "(II)V",
                      {static_cast<uint32_t>(width),
                       static_cast<uint32_t>(height)});
    RestoreHostDefaultFramebufferState();
}

static bool GetActiveGameplayCamera(uint32_t* out_camera,
                                    uint32_t* out_node_ref) {
    if (!out_camera || !out_node_ref || !g_host || g_host->HasFailed())
        return false;

    // These are the retained guest's validated Camera accessors. Query them
    // only after GS_Race exists; menu and splash states can expose a transient
    // null camera graph during their first GL ticks.
    constexpr uint32_t kGameGetCamera = 0x40937040;
    constexpr uint32_t kCameraGetCameraNode = 0x40c3f5a4;
    const uint32_t camera = g_host->RunFunction(kGameGetCamera, {0xffffffffu});
    if (!camera || g_host->HasFailed()) return false;
    const uint32_t camera_node_ref =
        g_host->RunFunction(kCameraGetCameraNode, {camera});
    if (!camera_node_ref || g_host->HasFailed()) return false;
    const uint32_t camera_node = g_host->MemoryRead32(camera_node_ref);
    if (!camera_node || g_host->HasFailed()) return false;

    *out_camera = camera;
    // Camera::GetCameraNode() returns the address of Camera's node-pointer
    // field (Camera + 0x6c), not a node that is immutable for the whole race.
    // Keep the field address so GS_Race camera-node swaps remain observable.
    *out_node_ref = camera_node_ref;
    return true;
}

static bool ApplyGameplayProjection(uint32_t camera, uint32_t camera_node,
                                    bool force_refresh = false) {
    if (!g_host || g_host->HasFailed() || !camera || !camera_node) return false;
    if (!g_renderer_wide_viewport_ready.load(std::memory_order_acquire)) return false;

    const int32_t width = g_surface_width.load(std::memory_order_acquire);
    const int32_t height = g_surface_height.load(std::memory_order_acquire);
    if (width <= 0 || height <= 0) return false;

    // Keep the authored vertical FOV and widen only the race camera. The
    // framebuffer remains full-surface, so the HUD/menu still fills the
    // display while 3D track geometry is not non-uniformly stretched.
    const float physical_aspect = static_cast<float>(width) /
                                  static_cast<float>(height);
    const uint32_t aspect_bits = FloatBits(physical_aspect);
    PublishHostGameplayAspectRatio(aspect_bits, camera_node);

    constexpr uint32_t kCameraSceneNodeSetAspectRatio = 0x405f9af8;
    if (!force_refresh && camera == g_last_projection_camera &&
        camera_node == g_last_projection_node &&
        aspect_bits == g_last_projection_aspect_bits &&
        g_last_projection_wide == 1) {
        return true;
    }

    g_host->RunFunction(kCameraSceneNodeSetAspectRatio,
                        {camera_node, aspect_bits});
    if (g_host->HasFailed()) return false;

    g_last_projection_camera = camera;
    g_last_projection_node = camera_node;
    g_last_projection_aspect_bits = aspect_bits;
    g_last_projection_wide = 1;
    LOGI("GameplayProjection wide=1 camera=0x%08x node=0x%08x aspect=%.6f surface=%dx%d",
         camera, camera_node, physical_aspect,
         static_cast<int>(width), static_cast<int>(height));
    return true;
}

void EnsureGuestAudioInitialized(JNIEnv* env) {
    if (!g_host || g_host->HasFailed() || g_guest_audio_init_state.load(std::memory_order_acquire) == 2)
        return;

    NativeFrame frame(env);
    if (!frame.active) return;

    // SoundManager owns the VoxEngine used by the original Android audio
    // driver.  The retained ARM32 build exposes a real Initialize() method,
    // but the old Java bootstrap path can skip its call on modern Android.
    // Calling it only after the guest frame is alive restores the original
    // DriverAndroid/AudioTrack path without synthesising or replacing game
    // audio.
    constexpr uint32_t kGameGetSoundManager = 0x4093672c;
    constexpr uint32_t kVoxEngineInitialize = 0x40ec1d44;
    const uint32_t sound_manager = g_host->RunFunction(kGameGetSoundManager, {});
    if (!sound_manager || g_host->HasFailed()) return;

    const uint32_t vox_engine = g_host->MemoryRead32(sound_manager + 0x80);
    if (!vox_engine || g_host->HasFailed()) return;

    if (g_host->MemoryRead8(vox_engine + 0x1c) != 0) {
        g_guest_audio_init_state.store(2, std::memory_order_release);
        LOGI("GuestAudio already initialized: sound_manager=0x%08x vox_engine=0x%08x",
             sound_manager, vox_engine);
        return;
    }

    uint8_t expected = 0;
    if (!g_guest_audio_init_state.compare_exchange_strong(
            expected, 1, std::memory_order_acq_rel, std::memory_order_acquire))
        return;

    g_host->RunFunction(kVoxEngineInitialize, {vox_engine});
    if (g_host->HasFailed()) {
        g_guest_audio_init_state.store(0, std::memory_order_release);
        return;
    }

    const bool initialized = g_host->MemoryRead8(vox_engine + 0x1c) != 0;
    g_guest_audio_init_state.store(initialized ? 2 : 0, std::memory_order_release);
    LOGI("GuestAudio Initialize result=%d sound_manager=0x%08x vox_engine=0x%08x",
         initialized ? 1 : 0, sound_manager, vox_engine);
}

void TuneGuestAudioQueue(JNIEnv* env) {
    if (g_guest_audio_queue_tuned || !g_host || g_host->HasFailed()) return;

    NativeFrame frame(env);
    if (!frame.active) return;

    constexpr uint32_t kVoxEngineInternal = 0x40ecbd68;
    constexpr uint32_t kDataThreshold = 0x4143a078;
    const uint32_t internal = g_host->RunFunction(kVoxEngineInternal, {});
    const uint32_t driver = internal ? g_host->MemoryRead32(internal + 0x5ac) : 0;
    if (!driver || g_host->HasFailed() || g_host->MemoryRead32(driver + 160) != 1)
        return;

    // DriverAndroid::DoCallbackAT sleeps whenever queued PCM exceeds this
    // lead time. The original nonpositive threshold keeps the tiny FIFO near
    // empty on a translated device. Fill roughly 60 ms ahead of playback.
    g_host->MemoryWrite64(kDataThreshold, std::bit_cast<uint64_t>(0.06));
    g_guest_audio_queue_tuned = !g_host->HasFailed();
}

void PumpGuestAudioDriver(JNIEnv* env) {
    if (!g_host || g_host->HasFailed()) return;

    // The guest's original pthread feeds AudioTrack through DoCallbackAT.
    // This GL-thread update services DriverCallbackInterface/MiniBusManager;
    // DriverAndroid::_UpdateAT itself is empty. Keep the menu-only call below
    // because the race step already advances the Vox graph.
    constexpr uint32_t kGameGetSoundManager = 0x4093672c;
    constexpr uint32_t kVoxEngineInternal = 0x40ecbd68;
    constexpr uint32_t kDriverAndroidUpdate = 0x40efdbe8;
    constexpr uint32_t kFrameDelta = 0x3c888889; // 1.0f / 60.0f

    NativeFrame frame(env);
    if (!frame.active) return;

    const uint32_t sound_manager = g_host->RunFunction(kGameGetSoundManager, {});
    if (!sound_manager || g_host->HasFailed()) return;
    const uint32_t vox_engine = g_host->MemoryRead32(sound_manager + 0x80);
    if (!vox_engine || g_host->HasFailed()) return;
    // The internal singleton owns the DriverAndroid pointer at +0x5ac.
    const uint32_t internal = g_host->RunFunction(kVoxEngineInternal, {});
    const uint32_t driver = internal ? g_host->MemoryRead32(internal + 0x5ac) : 0;
    if (!driver || g_host->HasFailed()) return;

    // GL2JNILib::step and SoundManager::Update already advance Vox. Running
    // UpdateThreaded again here can race a pending music-source replacement
    // during splash and spin inside the guest's UpdateSources loop.
    g_host->RunFunction(kDriverAndroidUpdate, {driver, kFrameDelta});
    if (g_host->HasFailed()) {
        LOGE("GuestAudioDriver Update failed object=0x%08x", driver);
        return;
    }
}

void SetRaceWideMode(JNIEnv* env, bool enabled) {
    if (!env) return;

    jclass activity = env->FindClass("com/gameloft/glf/GL2JNIActivity");
    if (!activity || env->ExceptionCheck()) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        return;
    }

    jmethodID setter = env->GetStaticMethodID(activity, "setRaceWideMode", "(Z)V");
    if (!setter || env->ExceptionCheck()) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        env->DeleteLocalRef(activity);
        return;
    }

    env->CallStaticVoidMethod(activity, setter, enabled ? JNI_TRUE : JNI_FALSE);
    if (env->ExceptionCheck()) env->ExceptionClear();
    env->DeleteLocalRef(activity);
}

bool IsRaceWideSupported(JNIEnv* env) {
    if (!env) return false;

    jclass activity = env->FindClass("com/gameloft/glf/GL2JNIActivity");
    if (!activity || env->ExceptionCheck()) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        return false;
    }

    jmethodID checker =
        env->GetStaticMethodID(activity, "isRaceWideSupported", "()Z");
    if (!checker || env->ExceptionCheck()) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        env->DeleteLocalRef(activity);
        return false;
    }

    const jboolean supported = env->CallStaticBooleanMethod(activity, checker);
    const bool result = supported == JNI_TRUE && !env->ExceptionCheck();
    if (env->ExceptionCheck()) env->ExceptionClear();
    env->DeleteLocalRef(activity);
    return result;
}

int UpdateRaceWideMode(JNIEnv* /*env*/) {
    if (!g_host || g_host->HasFailed()) return -1;

    // These guest addresses are from the retained ARM32 libAndroid.so ELF:
    // Game::GetCurrentState() and the GS_Race vtable.  The bridge maps the
    // guest image at 0x40000000, as do the existing menu/splash probes below.
    constexpr uint32_t kGameGetCurrentState = 0x409387e0;
    constexpr uint32_t kGsRaceVtable = 0x41395d40;

    const uint32_t state = g_host->RunFunction(kGameGetCurrentState, {});
    const uint32_t vtable = state ? g_host->MemoryRead32(state) : 0;
    const bool in_race = state != 0 && vtable == kGsRaceVtable;
    if (g_host->HasFailed()) return -1;
    TraceHostGlRaceState(in_race);

    // The physical framebuffer is full-width for every state, so there is no
    // viewport/layout transition to race. Only the active 3D camera changes:
    // the menu/HUD remain stretched to the physical surface, while the race
    // camera keeps its authored vertical FOV and exposes real side content.
    const int8_t target_mode = in_race ? 1 : 0;
    if (!in_race) {
        PublishHostGameplayAspectRatio(0, 0);
        g_last_race_wide_mode.store(0, std::memory_order_release);
        g_cached_race_camera = 0;
        g_cached_race_camera_node_ref = 0;
        g_cached_race_camera_node = 0;
        // Force the next race entry to reapply the aspect even if the guest
        // reuses the same camera object after returning to the menu.
        g_last_projection_camera = 0;
        g_last_projection_node = 0;
        g_last_projection_aspect_bits = 0;
        g_last_projection_wide = -1;
#if defined(ASPHALT7_GL_TELEMETRY)
        g_last_trace_camera = 0xffffffffu;
        g_last_trace_camera_mode = 0xffffffffu;
        g_last_trace_race_camera_state = 0xffffffffu;
        g_last_trace_camera_target = 0xffffffffu;
        g_last_trace_camera_node = 0xffffffffu;
#endif
        return 0;
    }

    // GetCamera() can re-enter guest state while the race camera is being
    // created, so acquire that object only once. GetCameraNode() returns the
    // address of the node field inside this stable Camera object. Poll that
    // field directly: the guest replaces its node during race entry/recovery,
    // and each new node needs its own wide projection.
    if (!g_cached_race_camera || !g_cached_race_camera_node_ref) {
        uint32_t camera = 0;
        uint32_t camera_node_ref = 0;
        if (!GetActiveGameplayCamera(&camera, &camera_node_ref)) return 1;
        g_cached_race_camera = camera;
        g_cached_race_camera_node_ref = camera_node_ref;
        g_cached_race_camera_node = 0;
        LOGI("RaceCamera cache established camera=0x%08x node_ref=0x%08x",
             camera, camera_node_ref);
    }

    const uint32_t camera_node =
        g_host->MemoryRead32(g_cached_race_camera_node_ref);
    if (!camera_node || g_host->HasFailed()) return 1;
    if (camera_node != g_cached_race_camera_node) {
        LOGI("RaceCamera active node changed camera=0x%08x node=0x%08x previous=0x%08x",
             g_cached_race_camera, camera_node, g_cached_race_camera_node);
        g_cached_race_camera_node = camera_node;
    }

#if defined(ASPHALT7_GL_TELEMETRY)
    const uint32_t camera_mode =
        g_host->MemoryRead32(g_cached_race_camera + 0x68);
    const uint32_t race_camera_state =
        g_host->MemoryRead32(g_cached_race_camera + 0x5c);
    const uint32_t camera_target =
        g_host->MemoryRead32(g_cached_race_camera + 0x98);
    const uint32_t node_aspect = g_host->MemoryRead32(camera_node + 0x12c);
    if (g_host->HasFailed()) return 1;
    if (g_last_trace_camera != g_cached_race_camera ||
        g_last_trace_camera_mode != camera_mode ||
        g_last_trace_race_camera_state != race_camera_state ||
        g_last_trace_camera_target != camera_target ||
        g_last_trace_camera_node != camera_node) {
        uint32_t rigid_body = 0;
        int dynamic_body = -1;
        if (camera_target) {
            constexpr uint32_t kPhysicCarGetRigidBody = 0x40a5a124;
            constexpr uint32_t kPhysicRigidBodyIsDynamic = 0x40a738bc;
            rigid_body = g_host->RunFunction(kPhysicCarGetRigidBody,
                                             {camera_target});
            if (rigid_body && !g_host->HasFailed()) {
                dynamic_body = g_host->RunFunction(
                                   kPhysicRigidBodyIsDynamic, {rigid_body})
                                   ? 1
                                   : 0;
            }
        }
        LOGI("RaceCamera state camera=0x%08x mode=%u race_state=%u target=0x%08x body=0x%08x dynamic=%d node=0x%08x aspect=0x%08x",
             g_cached_race_camera, camera_mode, race_camera_state,
             camera_target, rigid_body, dynamic_body, camera_node,
             node_aspect);
        g_last_trace_camera = g_cached_race_camera;
        g_last_trace_camera_mode = camera_mode;
        g_last_trace_race_camera_state = race_camera_state;
        g_last_trace_camera_target = camera_target;
        g_last_trace_camera_node = camera_node;
    }
#endif

    // This stays cheap on steady frames: ApplyGameplayProjection skips the
    // guest setter unless the active node or physical aspect actually changed.
    if (ApplyGameplayProjection(g_cached_race_camera,
                                camera_node)) {
        g_last_race_wide_mode.store(target_mode, std::memory_order_release);
    }
    return 1;
}

void EnsureGuestMenuMusic(JNIEnv* env, bool in_race) {
    if (!g_host || g_host->HasFailed()) return;

    // The original title music is a real Vox sound named m_title.  On the
    // modern host the guest creates AudioTrack before the menu state has
    // selected a track, leaving the write buffer permanently silent.  Select
    // the retained title track once per menu visit and let the guest Vox
    // mixer/Play2D path decode the embedded asset.  No PCM is synthesized.
    if (in_race) {
        g_guest_menu_music_active = false;
        g_guest_menu_music_retry = 0;
        return;
    }

    constexpr uint32_t kGameGetSoundManager = 0x4093672c;
    constexpr uint32_t kSoundManagerSetMusicTrack = 0x40a9f6f0;
    constexpr uint32_t kSoundManagerSetMusicPlaying = 0x40a9f568;
    constexpr uint32_t kSoundManagerUpdate = 0x40a9fff0;
    constexpr uint32_t kSoundManagerIsSoundPlaying = 0x40a9c1b8;

    NativeFrame frame(env);
    if (!frame.active) return;

    const uint32_t sound_manager = g_host->RunFunction(kGameGetSoundManager, {});
    if (!sound_manager || g_host->HasFailed()) return;

    // GS_Init::UpdateLoading owns SoundManager::Init (guest ELF 0x00d1f0a8).
    // The SoundManager exists before that loading stage, so an empty table is
    // not a skipped initialization. Init is not idempotent: it replaces the
    // source/handle arrays. Calling it here lets music use the first arrays
    // while the native loader later replaces them under the Vox workers.
    // Wait for the native stage to publish its tables before selecting music.
    const uint32_t sound_count = g_host->MemoryRead32(sound_manager + 0xec);
    const uint32_t sound_slots = g_host->MemoryRead32(sound_manager + 0xe4);
    if (sound_count == 0 || sound_slots == 0 || g_host->HasFailed()) return;
    if (g_guest_menu_music_probe_logs == 0) {
        LOGI("GuestMenuMusic native tables ready sm=0x%08x sounds=%u slots=0x%08x",
             sound_manager, sound_count, sound_slots);
    }

    const uint32_t current_id = g_host->MemoryRead32(sound_manager + 0x60);
    const bool currently_playing = g_host->MemoryRead8(sound_manager + 0x68) != 0;
    if (g_guest_menu_music_probe_logs < 8 ||
        current_id != g_guest_menu_music_last_id ||
        static_cast<int8_t>(currently_playing) != g_guest_menu_music_last_playing) {
        LOGI("GuestMenuMusic probe sm=0x%08x sounds=%u id=0x%08x playing=%d retry=%u",
             sound_manager, sound_count, current_id, currently_playing ? 1 : 0,
             static_cast<unsigned>(g_guest_menu_music_retry));
        g_guest_menu_music_last_id = current_id;
        g_guest_menu_music_last_playing = static_cast<int8_t>(currently_playing);
        ++g_guest_menu_music_probe_logs;
    }
    if (currently_playing && current_id != 0xffffffffu) {
        // SetMusicPlaying marks the slot active even when Play2D has only
        // queued an asynchronous datasource load.  Ask the game's own
        // emitter table whether an actual emitter exists; otherwise the
        // original one-shot call can leave the menu permanently silent.
        const bool emitter_playing = g_host->RunFunction(
            kSoundManagerIsSoundPlaying,
            {sound_manager, current_id, 0xffffffffu}) != 0;
        if (g_host->HasFailed()) return;
        if (g_guest_menu_music_probe_logs < 8 &&
            static_cast<int8_t>(emitter_playing) != g_guest_menu_music_last_actual_playing) {
            LOGI("GuestMenuMusic emitter id=%u playing=%d",
                 current_id, emitter_playing ? 1 : 0);
            g_guest_menu_music_last_actual_playing =
                static_cast<int8_t>(emitter_playing);
        }
        if (!emitter_playing) {
            if (g_guest_menu_music_retry != 0) {
                --g_guest_menu_music_retry;
                return;
            }
            // Re-arm through the original SoundManager path.  This is safe
            // while a datasource is loading: false clears the stale music
            // flag, and true retries Play2D once IsReady becomes true.
            g_host->RunFunction(kSoundManagerSetMusicPlaying,
                                {sound_manager, 0});
            if (g_host->HasFailed()) return;
            g_host->RunFunction(kSoundManagerSetMusicPlaying,
                                {sound_manager, 1});
            if (g_host->HasFailed()) return;
            g_host->RunFunction(kSoundManagerUpdate, {sound_manager});
            if (g_host->HasFailed()) return;
            g_guest_menu_music_retry = 30;
            LOGI("GuestMenuMusic rearm id=%u", current_id);
            return;
        }
        g_guest_menu_music_retry = 0;
        g_guest_menu_music_active = true;
        // SoundManager::SetMusicPlaying only queues the Vox stream.  The
        // original Java/GL loop normally services this from its audio tick,
        // but that callback is absent on the retained ARM32 path.  Pump the
        // game's own mixer once per menu frame so the AudioTrack buffer is
        // actually filled after the title bank has been selected.
        g_host->RunFunction(kSoundManagerUpdate, {sound_manager});
        if (g_host->HasFailed()) g_guest_menu_music_active = false;
        return;
    }
    if (g_guest_menu_music_retry != 0) {
        --g_guest_menu_music_retry;
        return;
    }

    if (!g_guest_menu_music_name) {
        static constexpr char kTitleTrack[] = "m_title";
        g_guest_menu_music_name = g_host->GuestAlloc(sizeof(kTitleTrack), 1);
        if (!g_guest_menu_music_name) return;
        std::memcpy(g_host->GetGuestMemoryBase() + g_guest_menu_music_name,
                    kTitleTrack, sizeof(kTitleTrack));
    }

    const uint32_t track_result = g_host->RunFunction(kSoundManagerSetMusicTrack,
                                                      {sound_manager, g_guest_menu_music_name});
    if (g_host->HasFailed()) return;

    const uint32_t selected_id = g_host->MemoryRead32(sound_manager + 0x60);
    LOGI("GuestMenuMusic select result=0x%08x id=0x%08x", track_result, selected_id);
    if (selected_id != 0xffffffffu) {
        g_host->RunFunction(kSoundManagerSetMusicPlaying, {sound_manager, 1});
        // Keep the normal guest update path alive on the first menu frame;
        // this also services queued music transitions when the menu was
        // reached from a paused race.
        g_host->RunFunction(kSoundManagerUpdate, {sound_manager});
        if (g_host->HasFailed()) return;
        const bool emitter_playing = g_host->RunFunction(
            kSoundManagerIsSoundPlaying,
            {sound_manager, selected_id, 0xffffffffu}) != 0;
        if (g_host->HasFailed()) return;
        g_guest_menu_music_active = emitter_playing;
        g_guest_menu_music_retry = emitter_playing ? 0 : 30;
        g_guest_menu_music_last_actual_playing =
            static_cast<int8_t>(emitter_playing);
        LOGI("GuestMenuMusic track=m_title id=%u playing=%d emitter=%d",
             selected_id, g_guest_menu_music_active ? 1 : 0,
             emitter_playing ? 1 : 0);
    } else {
        // Loading can expose the SoundManager before its sound-pack XML is
        // ready. Retry without spamming the guest or logcat.
        g_guest_menu_music_retry = 60;
    }
}

static void Native_GL2_prepareSwapBuffer(JNIEnv*, jobject) {
    // The guest calls Java SwapBuffer/SwapBufferLoading from inside step().
    // Filter the completed back buffer at its actual presentation boundary.
    if (!FinalizeHostDefaultFramebufferPresentation()) return;
    if (GraphicsAntialiasingEnabled() && g_guest_window_focused.load(std::memory_order_acquire) &&
        g_host && !g_host->HasFailed())
        (void)ApplyPostprocessAA();
}

static void Native_GL2_step(JNIEnv* env, jobject receiver) {
    ConsumeGuestLifecycle(env, receiver);
    DispatchQueuedTouchEvents(env, receiver);

    // Resolve the debounced game state first, then publish viewport, scissor,
    // and camera mode as one render-thread transaction before guest drawing.
    // Publish the rectangle before the guest begins its frame. Its Java swap
    // callback prepares the actual presented buffer before eglSwapBuffers.
    (void)UpdateRaceWideMode(env);
    // One presentation rectangle for menu, loading, pause and active race.
    // The host GL thunk also enforces this invariant if an older call site
    // accidentally asks for wide mode.
    SetHostDefaultFramebufferWideMode(false);
    RestoreHostDefaultFramebufferState();
    TraceHostDefaultFramebufferState("step-pre");

    (void)InvokeGuest(env, receiver, ClassId::GL2JNILib, "step", "()V", {});
    ProcessPendingCurrencyReset(env);
    TraceHostDefaultFramebufferState("step-post");
    const PendingSensorSamples sensor_samples = TakePendingSensorSamples();
    if (sensor_samples.accelerometer) {
        (void)InvokeGuest(env, receiver, ClassId::GL2JNILib, "accelerometerEvent",
                          "(FFF)V",
                          {FloatBits(sensor_samples.accelerometer_x),
                           FloatBits(sensor_samples.accelerometer_y),
                           FloatBits(sensor_samples.accelerometer_z)});
    }
    if (sensor_samples.gyroscope) {
        (void)InvokeGuest(env, receiver, ClassId::GL2JNILib, "gyroscopeEvent",
                          "(FFF)V",
                          {FloatBits(sensor_samples.gyroscope_x),
                           FloatBits(sensor_samples.gyroscope_y),
                           FloatBits(sensor_samples.gyroscope_z)});
    }
    EnsureGuestAudioInitialized(env);
    TuneGuestAudioQueue(env);
    const int race_mode = UpdateRaceWideMode(env);
    if (race_mode >= 0) EnsureGuestMenuMusic(env, race_mode == 1);
    // SoundManager::Update already advances the Vox graph from the guest
    // GL2JNILib::step path. A second MiniBusManager update during a race can
    // free a stale source and stick inside VoxEngineInternal::UpdateSources().
    if (race_mode != 1) PumpGuestAudioDriver(env);
    if (g_host && !g_host->HasFailed()) {
        constexpr uint32_t kGameInstance = 0x413f99d4;
        constexpr uint32_t kGameGetCurrentMenu = 0x40930048;
        constexpr uint32_t kGameGetSwfMgr = 0x409327c4;
        constexpr uint32_t kMenuSplashFile = 0x41415ce0;
        constexpr uint32_t kMenuSplashCBContinue = 0x40be9ea8;

        const uint32_t game_instance = g_host->MemoryRead32(kGameInstance);
        const uint32_t current_menu =
            game_instance ? g_host->RunFunction(kGameGetCurrentMenu, {game_instance}) : 0;
        if (current_menu != 4) {
            g_auto_splash_handler = 0;
            g_auto_splash_handler_frames = 0;
            g_auto_splash_continue_sent = false;
        } else if (game_instance && !g_auto_splash_continue_sent &&
                   !g_host->HasFailed()) {
            const uint32_t swf_manager =
                g_host->RunFunction(kGameGetSwfMgr, {game_instance});
            const uint32_t splash_file = g_host->MemoryRead32(kMenuSplashFile);
            if (swf_manager && splash_file < 21) {
                const uint32_t splash_handler =
                    g_host->MemoryRead32(swf_manager + 4 * splash_file + 4);
                if (splash_handler && !g_host->HasFailed()) {
                    // Wait one complete guest frame after the SWF publishes its
                    // handler, then pass the obsolete touch gate automatically.
                    // This is tied to actual splash readiness, not a wall-clock
                    // delay or an early tap that the guest might miss.
                    if (splash_handler != g_auto_splash_handler) {
                        g_auto_splash_handler = splash_handler;
                        g_auto_splash_handler_frames = 1;
                    } else if (g_auto_splash_handler_frames < 2) {
                        ++g_auto_splash_handler_frames;
                    }
                }
                if (splash_handler && g_auto_splash_handler_frames >= 2 &&
                    !g_host->HasFailed()) {
                    g_host->RunFunction(kMenuSplashCBContinue, {splash_handler});
                    if (!g_host->HasFailed()) {
                        g_auto_splash_continue_sent = true;
                    }
                }
            }
        }
    }

    // Leave the window presentation rectangle authoritative for subsequent
    // callbacks. FXAA belongs before Java's swap, not on this new back buffer.
    FinalizeHostDefaultFramebufferPresentation();
}

static void Native_GL2_touchEvent(JNIEnv*, jobject, jint event,
                                  jint x, jint y, jint pointer_id) {
    INPUT_LOGI("touch event=%d x=%d y=%d pointer=%d", event, x, y, pointer_id);
    QueueTouchEvent(event, x, y, pointer_id);
}

WRAP_V0(Native_Facebook_nativeInit, ClassId::FacebookAndroidGLSocialLib, "nativeInit", "()V")
WRAP_V1S(Native_Facebook_nativeOnFBDataLoad, ClassId::FacebookAndroidGLSocialLib,
         "nativeOnFBDataLoad", "(Ljava/lang/String;)V")
WRAP_V0(Native_Facebook_nativeOnFBDialogDidComplete, ClassId::FacebookAndroidGLSocialLib,
        "nativeOnFBDialogDidComplete", "()V")
WRAP_V0(Native_Facebook_nativeOnFBDialogDidNotComplete,
        ClassId::FacebookAndroidGLSocialLib, "nativeOnFBDialogDidNotComplete", "()V")
WRAP_V1S(Native_Facebook_nativeOnFBFailWithError, ClassId::FacebookAndroidGLSocialLib,
         "nativeOnFBFailWithError", "(Ljava/lang/String;)V")
WRAP_V0(Native_Platform_nativeInit, ClassId::PlatformAndroid, "nativeInit", "()V")

#undef WRAP_V0
#undef WRAP_I0
#undef WRAP_B0
#undef WRAP_V1I
#undef WRAP_I1J
#undef WRAP_B1J
#undef WRAP_V1J
#undef WRAP_V2I
#undef WRAP_V3I
#undef WRAP_V4I
#undef WRAP_V1B
#undef WRAP_V1I1B
#undef WRAP_V3F
#undef WRAP_V1S
#undef WRAP_V2S
#undef WRAP_V3S
#undef WRAP_V4S
#undef WRAP_V1O
#undef WRAP_V2I1S
#undef WRAP_V1I2S
#undef WRAP_V3I1S
#undef WRAP_V2I1O
#undef WRAP_V1I1J
#undef WRAP_V1I1O1B
#undef WRAP_I3O
#undef WRAP_O1S
#undef WRAP_O1O
#undef WRAP_J0
#undef WRAP_O0
#undef WRAP_B1IO1

#define NATIVE(NAME, SIGNATURE, FUNCTION) \
    {const_cast<char*>(NAME), const_cast<char*>(SIGNATURE), reinterpret_cast<void*>(FUNCTION)}

const JNINativeMethod kGameMethods[] = {
    NATIVE("nativeAccelerator", "(FFF)V", Native_Game_nativeAccelerator),
    NATIVE("nativeCanInterrupt", "()I", Native_Game_nativeCanInterrupt),
    NATIVE("nativeGetInfo", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
           Native_Game_nativeGetInfo),
    NATIVE("nativeInit", "()V", Native_Game_nativeInit),
    NATIVE("nativeOnKeyDown", "(I)V", Native_Game_nativeOnKeyDown),
    NATIVE("nativeOnKeyUp", "(I)V", Native_Game_nativeOnKeyUp),
    NATIVE("nativeOrientation", "(FFF)V", Native_Game_nativeOrientation),
};

const JNINativeMethod kGLGameMethods[] = {
    NATIVE("Init", "()V", Native_GLGame_Init),
    NATIVE("backFromGLLive", "()V", Native_GLGame_backFromGLLive),
    NATIVE("isLoading", "()Z", Native_GLGame_isLoading),
    NATIVE("isWindowFocus", "(Z)V", Native_GLGame_isWindowFocus),
    NATIVE("nativeChangedOrientation", "(I)V", Native_GLGame_nativeChangedOrientation),
    NATIVE("nativeHandleKey", "(IZ)V", Native_GLGame_nativeHandleKey),
    NATIVE("nativeHandleMessage", "(Landroid/os/Message;)V", Native_GLGame_nativeHandleMessage),
    NATIVE("nativeHideKeyboard", "()V", Native_GLGame_nativeHideKeyboard),
    NATIVE("nativeLaunchIGPAfterInterrupt", "()V", Native_GLGame_nativeLaunchIGPAfterInterrupt),
    NATIVE("nativeLaunchWSAfterInterrupt", "()V", Native_GLGame_nativeLaunchWSAfterInterrupt),
    NATIVE("nativeOnLowMemory", "()V", Native_GLGame_nativeOnLowMemory),
    NATIVE("nativeSplashScreenFunction", "(Ljava/lang/String;)V", Native_GLGame_nativeSplashScreenFunction),
    NATIVE("nativeonEditorAction", "(Ljava/lang/String;)V", Native_GLGame_nativeonEditorAction),
    NATIVE("onIGPClose", "(III)V", Native_GLGame_onIGPClose),
    NATIVE("pauseGame", "()V", Native_GLGame_pauseGame),
    NATIVE("requestIGM", "()V", Native_GLGame_requestIGM),
    NATIVE("resumeGame", "()V", Native_GLGame_resumeGame),
    NATIVE("saveIGPMessage", "(Ljava/lang/String;)V", Native_GLGame_saveIGPMessage),
    NATIVE("updateCashWithAmount", "(ILjava/lang/String;Ljava/lang/String;)V", Native_GLGame_updateCashWithAmount),
    NATIVE("updateIGPReward", "(IILjava/lang/String;)V", Native_GLGame_updateIGPReward),
    NATIVE("grantOfflinePurchase", "(II)Z", Native_GLGame_grantOfflinePurchase),
    NATIVE("getCurrencyResetLanguage", "()I", Native_GLGame_getCurrencyResetLanguage),
    NATIVE("requestCurrencyReset", "()Z", Native_GLGame_requestCurrencyReset),
};

const JNINativeMethod kC2DMAndroidUtilsMethods[] = {
    NATIVE("nativeInit", "()V", Native_C2DMAndroidUtils_nativeInit),
};

const JNINativeMethod kGLUtilsDeviceMethods[] = {
    NATIVE("nativeInit", "()V", Native_GLUtils_Device_nativeInit),
};
const JNINativeMethod kNetworkStateReceiverMethods[] = {
    NATIVE("setNetworkState", "(I)V", Native_GLUtils_NetworkStateReceiver_setNetworkState),
};
const JNINativeMethod kSUtilsMethods[] = {
    NATIVE("nativeInit", "()V", Native_GLUtils_SUtils_nativeInit),
};
const JNINativeMethod kInAppBillingMethods[] = {
    NATIVE("nativeInit", "(Landroid/content/Context;)V", Native_InAppBilling_nativeInit),
    NATIVE("nativeSendData", "(Landroid/os/Bundle;)Landroid/os/Bundle;", Native_InAppBilling_nativeSendData),
};
const JNINativeMethod kIabSMethods[] = {
    NATIVE("bq", "(Ljava/security/PublicKey;Ljava/lang/String;Ljava/lang/String;)I", Native_IabS_bq),
    NATIVE("gk", "(Ljava/lang/String;)Ljava/security/PublicKey;", Native_IabS_gk),
    NATIVE("gn", "()J", Native_IabS_gn),
    NATIVE("in", "(J)Z", Native_IabS_in),
    NATIVE("rn", "(J)V", Native_IabS_rn),
};
const JNINativeMethod kIabDeviceMethods[] = {
    NATIVE("nativeInit", "()V", Native_IabDevice_nativeInit),
};
const JNINativeMethod kIGPFreemiumActivityMethods[] = {
    NATIVE("nativeInit", "()V", Native_IGPFreemiumActivity_nativeInit),
};
const JNINativeMethod kGameInstallerMethods[] = {
    NATIVE("initNative", "()V", Native_GameInstaller_initNative),
    NATIVE("nativeStart", "()V", Native_GameInstaller_nativeStart),
    NATIVE("getPublicKey", "()V", Native_GameInstaller_getPublicKey),
};
const JNINativeMethod kGDRMPolicyMethods[] = {
    NATIVE("initNativeAP", "(III)V", Native_GDRMPolicy_initNativeAP),
    NATIVE("getConstString", "(I)Ljava/lang/String;", Native_GDRMPolicy_getConstString),
    NATIVE("getPrefFile", "()Ljava/lang/String;", Native_GDRMPolicy_getPrefFile),
    NATIVE("nativeAllow", "(J)I", Native_GDRMPolicy_nativeAllow),
    NATIVE("processServer", "(II)V", Native_GDRMPolicy_processServer),
    NATIVE("setConst", "(II)V", Native_GDRMPolicy_setConst),
    NATIVE("setLongConst", "(IJ)V", Native_GDRMPolicy_setLongConst),
    NATIVE("setTime", "(J)V", Native_GDRMPolicy_setTime),
};
const JNINativeMethod kMiscMethods[] = {
    NATIVE("nativeDestroy", "()V", Native_Misc_nativeDestroy),
    NATIVE("nativeInit", "(IIILjava/lang/String;)V", Native_Misc_nativeInit),
    NATIVE("nativeRender", "()V", Native_Misc_nativeRender),
    NATIVE("nativeResize", "(II)V", Native_Misc_nativeResize),
};
const JNINativeMethod kSendInfoMethods[] = {
    NATIVE("initMethods", "()V", Native_SendInfo_initMethods),
};
const JNINativeMethod kGL2Methods[] = {
    NATIVE("accelerometerEvent", "(FFF)V", Native_GL2_accelerometerEvent),
    NATIVE("destroy", "()V", Native_GL2_destroy),
    NATIVE("getNumExtraContext", "()I", Native_GL2_getNumExtraContext),
    NATIVE("getViewSettings", "()V", Native_GL2_getViewSettings),
    NATIVE("gyroscopeEvent", "(FFF)V", Native_GL2_gyroscopeEvent),
    NATIVE("init", "()V", Native_GL2_init),
    NATIVE("initGL", "()V", Native_GL2_initGL),
    NATIVE("orientationChanged", "(I)V", Native_GL2_orientationChanged),
    NATIVE("prepareSwapBuffer", "()V", Native_GL2_prepareSwapBuffer),
    NATIVE("processTouchpadAsPointer", "(ILandroid/view/ViewParent;Z)Z", Native_GL2_processTouchpadAsPointer),
    NATIVE("resize", "(II)V", Native_GL2_resize),
    NATIVE("setGyrosEnabled", "(Z)V", Native_GL2_setGyrosEnabled),
    NATIVE("setNumExtraContext", "(I)V", Native_GL2_setNumExtraContext),
    NATIVE("setPaths", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V", Native_GL2_setPaths),
    NATIVE("stateChanged", "(Z)V", Native_GL2_stateChanged),
    NATIVE("step", "()V", Native_GL2_step),
    NATIVE("touchEvent", "(IIII)V", Native_GL2_touchEvent),
};
const JNINativeMethod kFacebookMethods[] = {
    NATIVE("nativeInit", "()V", Native_Facebook_nativeInit),
    NATIVE("nativeOnFBDataLoad", "(Ljava/lang/String;)V", Native_Facebook_nativeOnFBDataLoad),
    NATIVE("nativeOnFBDialogDidComplete", "()V", Native_Facebook_nativeOnFBDialogDidComplete),
    NATIVE("nativeOnFBDialogDidNotComplete", "()V", Native_Facebook_nativeOnFBDialogDidNotComplete),
    NATIVE("nativeOnFBFailWithError", "(Ljava/lang/String;)V", Native_Facebook_nativeOnFBFailWithError),
};
const JNINativeMethod kPlatformMethods[] = {
    NATIVE("nativeInit", "()V", Native_Platform_nativeInit),
};

#undef NATIVE

struct ClassSpec {
    const JNINativeMethod* methods;
    size_t count;
};

constexpr ClassSpec kClassSpecs[kClassCount] = {
    {kGameMethods, sizeof(kGameMethods) / sizeof(kGameMethods[0])},
    {kGLGameMethods, sizeof(kGLGameMethods) / sizeof(kGLGameMethods[0])},
    {kC2DMAndroidUtilsMethods, sizeof(kC2DMAndroidUtilsMethods) / sizeof(kC2DMAndroidUtilsMethods[0])},
    {kGLUtilsDeviceMethods, sizeof(kGLUtilsDeviceMethods) / sizeof(kGLUtilsDeviceMethods[0])},
    {kNetworkStateReceiverMethods, sizeof(kNetworkStateReceiverMethods) / sizeof(kNetworkStateReceiverMethods[0])},
    {kSUtilsMethods, sizeof(kSUtilsMethods) / sizeof(kSUtilsMethods[0])},
    {kInAppBillingMethods, sizeof(kInAppBillingMethods) / sizeof(kInAppBillingMethods[0])},
    {kIabSMethods, sizeof(kIabSMethods) / sizeof(kIabSMethods[0])},
    {kIabDeviceMethods, sizeof(kIabDeviceMethods) / sizeof(kIabDeviceMethods[0])},
    {kIGPFreemiumActivityMethods, sizeof(kIGPFreemiumActivityMethods) / sizeof(kIGPFreemiumActivityMethods[0])},
    {kGameInstallerMethods, sizeof(kGameInstallerMethods) / sizeof(kGameInstallerMethods[0])},
    {kGDRMPolicyMethods, sizeof(kGDRMPolicyMethods) / sizeof(kGDRMPolicyMethods[0])},
    {kMiscMethods, sizeof(kMiscMethods) / sizeof(kMiscMethods[0])},
    {kSendInfoMethods, sizeof(kSendInfoMethods) / sizeof(kSendInfoMethods[0])},
    {kGL2Methods, sizeof(kGL2Methods) / sizeof(kGL2Methods[0])},
    {kFacebookMethods, sizeof(kFacebookMethods) / sizeof(kFacebookMethods[0])},
    {kPlatformMethods, sizeof(kPlatformMethods) / sizeof(kPlatformMethods[0])},
};

size_t NativeMethodCount() {
    size_t total = 0;
    for (const auto& spec : kClassSpecs) total += spec.count;
    return total;
}

} // namespace

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) try {
    JNIEnv* env = nullptr;
    if (!vm || vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK)
        return JNI_ERR;

    g_jvm = vm;
    auto& jni = FakeJniEnv::Instance();
    jni.SetJavaVM(vm);

    for (size_t i = 0; i < kClassCount; ++i) {
        jclass local_class = env->FindClass(kClassNames[i]);
        if (!local_class || env->ExceptionCheck()) return JNI_ERR;
        g_classes[i] = static_cast<jclass>(env->NewGlobalRef(local_class));
        const auto& spec = kClassSpecs[i];
        const jint count = static_cast<jint>(spec.count);
        if (!g_classes[i] || env->RegisterNatives(local_class, spec.methods, count) != JNI_OK ||
            !jni.DeclareNatives(env, local_class, spec.methods, spec.count)) {
            env->DeleteLocalRef(local_class);
            return JNI_ERR;
        }
        env->DeleteLocalRef(local_class);
    }

    if (!jni.CacheClassLoader(env, g_classes[static_cast<size_t>(ClassId::Game)]))
        return JNI_ERR;
    LOGI("host JNI_OnLoad: registered %zu Asphalt native wrappers; guest loading deferred", NativeMethodCount());
    return JNI_VERSION_1_6;
} catch (const std::exception& error) {
    LOGE("JNI_OnLoad exception: %s", error.what());
    return JNI_ERR;
} catch (...) {
    LOGE("unknown JNI_OnLoad exception");
    return JNI_ERR;
}

extern "C" JNIEXPORT void JNICALL JNI_OnUnload(JavaVM*, void*) {
    // The bridge normally lives for the process lifetime, but Android may
    // unload a replaced native library during teardown.  Join the callback
    // pump before its Dynarmic host and thunk state can disappear.
    StopAudioThread();
}
