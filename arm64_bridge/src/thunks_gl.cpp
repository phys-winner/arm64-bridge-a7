// SPDX-License-Identifier: GPL-3.0-or-later
#include "thunk_manager.h"
#include "dynarmic_host.h"
#include "thunks_gl.h"
#include "thunk_types.h"
#include "graphics_settings.h"
#include <GLES2/gl2.h>
#include <GLES2/gl2ext.h>
#include <EGL/egl.h>
#include <android/log.h>
#include <array>
#include <atomic>
#include <vector>
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <map>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>


// Conduit's Java/native surface code owns geometry; the ABI bridge does not rescale it.
#define LOG_TAG "Arm32Bridge_GL"
#if defined(ASPHALT7_FINAL_SILENT)
#define LOGI(...) ((void)0)
#define LOGE(...) ((void)0)
#else
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#endif

// GL/EGL own these strings. Guest copies are interned by value for the host's
// process lifetime, not allocated per query or cached as NULL before a context exists.
static uint32_t DriverString(DynarmicHost& host, const char* value) {
    if (!value) return 0;
    static std::mutex mutex;
    static std::unordered_map<std::string, uint32_t> strings;
    std::lock_guard<std::mutex> lock(mutex);
    auto found = strings.find(value);
    if (found != strings.end()) return found->second;
    const size_t size = strlen(value) + 1;
    const uint32_t address = host.GuestAlloc(size);
    if (!address) return 0;
    memcpy(host.GetGuestMemoryBase() + address, value, size);
    strings.emplace(value, address);
    return address;
}

// EGLDisplay is opaque and host-pointer-sized; only these handles cross the ABI.
static std::mutex g_display_mutex;
static std::vector<EGLDisplay> g_displays;
static thread_local EGLint t_egl_error = EGL_SUCCESS;

namespace {

struct DefaultFramebufferViewportAuthority {
    EGLContext context = EGL_NO_CONTEXT;
    EGLSurface draw_surface = EGL_NO_SURFACE;
    GLint x = 0;
    GLint y = 0;
    GLsizei width = 0;
    GLsizei height = 0;
    bool valid = false;
};

thread_local DefaultFramebufferViewportAuthority t_default_framebuffer_viewport;
std::atomic<std::int32_t> g_default_framebuffer_surface_width{0};
std::atomic<std::int32_t> g_default_framebuffer_surface_height{0};
std::atomic<std::uint32_t> g_host_gameplay_aspect_ratio_bits{0};
std::atomic<std::uint32_t> g_host_gameplay_camera_node{0};
// Resize and touch use physical surface pixels. Keep full-width presentation
// for both menus and races; the retained movies own their internal canvas.
std::atomic<bool> g_default_framebuffer_wide_mode{true};

// Keep the guest's context-wide rectangles separate from the physical
// window override. The engine caches its 1920x1080 viewport and can bind a
// same-sized post-process FBO without issuing glViewport again. Inheriting
// the host's 2340x1080 rectangle there crops the texture every eighth frame.
struct GuestFramebufferRectangles {
    std::array<GLint, 4> viewport{};
    std::array<GLint, 4> scissor{};
    bool viewport_valid = false;
    bool scissor_valid = false;
};

std::mutex g_guest_framebuffer_rectangles_mutex;
std::unordered_map<EGLContext, GuestFramebufferRectangles>
    g_guest_framebuffer_rectangles;

void RememberGuestFramebufferRectangle(bool is_viewport, GLint x, GLint y,
                                       GLsizei width, GLsizei height) {
    const EGLContext context = eglGetCurrentContext();
    if (context == EGL_NO_CONTEXT || width < 0 || height < 0) return;
    std::lock_guard lock(g_guest_framebuffer_rectangles_mutex);
    auto& rectangles = g_guest_framebuffer_rectangles[context];
    if (is_viewport) {
        rectangles.viewport = {x, y, width, height};
        rectangles.viewport_valid = true;
    } else {
        rectangles.scissor = {x, y, width, height};
        rectangles.scissor_valid = true;
    }
}

void RestoreGuestOffscreenFramebufferRectangles() {
    const EGLContext context = eglGetCurrentContext();
    GuestFramebufferRectangles rectangles;
    {
        std::lock_guard lock(g_guest_framebuffer_rectangles_mutex);
        const auto found = g_guest_framebuffer_rectangles.find(context);
        if (found == g_guest_framebuffer_rectangles.end()) return;
        rectangles = found->second;
    }
    if (rectangles.viewport_valid) {
        const auto& r = rectangles.viewport;
        glViewport(r[0], r[1], r[2], r[3]);
    }
    if (rectangles.scissor_valid) {
        const auto& r = rectangles.scissor;
        glScissor(r[0], r[1], r[2], r[3]);
    }
}

bool BuildCurrentHostDefaultFramebufferViewport(
    std::int32_t physical_width, std::int32_t physical_height, bool wide_mode,
    DefaultFramebufferViewportAuthority& viewport) {
    viewport = {};
    viewport.context = eglGetCurrentContext();
    viewport.draw_surface = eglGetCurrentSurface(EGL_DRAW);
    if (physical_width <= 0 || physical_height <= 0 ||
        viewport.context == EGL_NO_CONTEXT ||
        viewport.draw_surface == EGL_NO_SURFACE) {
        return false;
    }

    const EGLDisplay display = eglGetCurrentDisplay();
    EGLint surface_width = 0;
    EGLint surface_height = 0;
    if (display == EGL_NO_DISPLAY ||
        eglQuerySurface(display, viewport.draw_surface, EGL_WIDTH,
                        &surface_width) != EGL_TRUE ||
        eglQuerySurface(display, viewport.draw_surface, EGL_HEIGHT,
                        &surface_height) != EGL_TRUE ||
        surface_width != physical_width || surface_height != physical_height) {
        return false;
    }

    GLsizei presentation_width = surface_width;
    GLsizei presentation_height = surface_height;
    if (!wide_mode) {
        const std::int64_t scaled_width =
            static_cast<std::int64_t>(surface_width) * 9;
        const std::int64_t scaled_height =
            static_cast<std::int64_t>(surface_height) * 16;
        if (scaled_width > scaled_height) {
            presentation_width = static_cast<GLsizei>(
                static_cast<std::int64_t>(surface_height) * 16 / 9);
        } else if (scaled_width < scaled_height) {
            presentation_height = static_cast<GLsizei>(
                static_cast<std::int64_t>(surface_width) * 9 / 16);
        }
    }

    viewport.x = (surface_width - presentation_width) / 2;
    viewport.y = (surface_height - presentation_height) / 2;
    viewport.width = presentation_width;
    viewport.height = presentation_height;
    viewport.valid = true;
    return true;
}

bool GetHostDefaultFramebufferViewport(GLint& x, GLint& y, GLsizei& width,
                                       GLsizei& height) {
    const EGLContext context = eglGetCurrentContext();
    const EGLSurface draw_surface = eglGetCurrentSurface(EGL_DRAW);
    auto& viewport = t_default_framebuffer_viewport;
    if (!viewport.valid || context == EGL_NO_CONTEXT ||
        draw_surface == EGL_NO_SURFACE || viewport.context != context ||
        viewport.draw_surface != draw_surface) {
        // The guest owns several shared EGL contexts and briefly visits 1x1
        // pbuffers. Rebuild the authority when it returns to the window
        // surface instead of tying a layout publication to whichever context
        // happened to be current during the Java resize callback.
        const std::int32_t physical_width =
            g_default_framebuffer_surface_width.load(std::memory_order_acquire);
        const std::int32_t physical_height =
            g_default_framebuffer_surface_height.load(std::memory_order_acquire);
        const bool wide_mode =
            g_default_framebuffer_wide_mode.load(std::memory_order_acquire);
        DefaultFramebufferViewportAuthority refreshed;
        if (!BuildCurrentHostDefaultFramebufferViewport(
                physical_width, physical_height, wide_mode, refreshed)) {
            return false;
        }
        viewport = refreshed;
    }

    x = viewport.x;
    y = viewport.y;
    width = viewport.width;
    height = viewport.height;
    return true;
}

}  // namespace

void PublishHostGameplayAspectRatio(std::uint32_t aspect_ratio_bits,
                                    std::uint32_t camera_node) {
    g_host_gameplay_aspect_ratio_bits.store(aspect_ratio_bits,
                                            std::memory_order_release);
    g_host_gameplay_camera_node.store(camera_node, std::memory_order_release);
}

void PublishHostDefaultFramebufferSurfaceSize(std::int32_t physical_width,
                                              std::int32_t physical_height) {
    g_default_framebuffer_surface_width.store(physical_width,
                                               std::memory_order_release);
    g_default_framebuffer_surface_height.store(physical_height,
                                                std::memory_order_release);
    DefaultFramebufferViewportAuthority viewport;
    (void)BuildCurrentHostDefaultFramebufferViewport(
        physical_width, physical_height,
        g_default_framebuffer_wide_mode.load(std::memory_order_acquire),
        viewport);
    t_default_framebuffer_viewport = viewport;
}

void SetHostDefaultFramebufferWideMode(bool enabled) {
    // The guest and the Java surface use one invariant full-surface
    // presentation for every screen, including active gameplay. Keep this
    // guard here as the last line of defence: a stale caller must not be able
    // to reintroduce a frame-size transition between menu and race.
    (void)enabled;
    constexpr bool kFullSurfacePresentation = true;
    const bool previous = g_default_framebuffer_wide_mode.exchange(
        kFullSurfacePresentation, std::memory_order_acq_rel);
    if (previous == kFullSurfacePresentation) return;

    // The authority is thread-local GL state. Rebuild it immediately on the
    // render thread so viewport and scissor switch together at a frame edge.
    DefaultFramebufferViewportAuthority viewport;
    (void)BuildCurrentHostDefaultFramebufferViewport(
        g_default_framebuffer_surface_width.load(std::memory_order_acquire),
        g_default_framebuffer_surface_height.load(std::memory_order_acquire),
        kFullSurfacePresentation, viewport);
    t_default_framebuffer_viewport = viewport;
}

void RestoreHostDefaultFramebufferState() {
    GLint framebuffer = 0;
    glGetIntegerv(GL_FRAMEBUFFER_BINDING, &framebuffer);
    if (framebuffer != 0) return;

    GLint x = 0;
    GLint y = 0;
    GLsizei width = 0;
    GLsizei height = 0;
    if (!GetHostDefaultFramebufferViewport(x, y, width, height)) return;
    glViewport(x, y, width, height);
    glScissor(x, y, width, height);
}

bool FinalizeHostDefaultFramebufferPresentation() {
    const EGLContext context = eglGetCurrentContext();
    const EGLSurface draw_surface = eglGetCurrentSurface(EGL_DRAW);
    if (context == EGL_NO_CONTEXT || draw_surface == EGL_NO_SURFACE) return false;

    // Only touch the actual window surface. The guest legitimately renders
    // into 1x1/pbuffer surfaces during the same frame; those must not inherit
    // the presentation rectangle or have their FBO forcibly unbound.
    DefaultFramebufferViewportAuthority viewport;
    if (!BuildCurrentHostDefaultFramebufferViewport(
            g_default_framebuffer_surface_width.load(std::memory_order_acquire),
            g_default_framebuffer_surface_height.load(std::memory_order_acquire),
            true, viewport)) {
        return false;
    }

    t_default_framebuffer_viewport = viewport;
    glBindFramebuffer(GL_FRAMEBUFFER, 0);
    glViewport(viewport.x, viewport.y, viewport.width, viewport.height);
    glScissor(viewport.x, viewport.y, viewport.width, viewport.height);
    return true;
}

// Whether pointer arguments are client-memory addresses or buffer offsets is
// determined by these two bindings. Querying them from the driver for every
// draw/attribute call serializes the CPU with the GL command stream. Keep a
// per-thread/per-context mirror instead and resynchronize only when the EGL
// context changes; all guest glBindBuffer/glDeleteBuffers calls pass through
// this translation unit.
struct BufferBindingShadow {
    EGLContext context = EGL_NO_CONTEXT;
    GLuint array_buffer = 0;
    GLuint element_array_buffer = 0;

    bool SynchronizeContext() {
        const EGLContext current = eglGetCurrentContext();
        if (current == EGL_NO_CONTEXT) {
            context = EGL_NO_CONTEXT;
            array_buffer = 0;
            element_array_buffer = 0;
            return false;
        }
        if (current == context) return true;

        GLint array = 0;
        GLint element = 0;
        glGetIntegerv(GL_ARRAY_BUFFER_BINDING, &array);
        glGetIntegerv(GL_ELEMENT_ARRAY_BUFFER_BINDING, &element);
        context = current;
        array_buffer = static_cast<GLuint>(array);
        element_array_buffer = static_cast<GLuint>(element);
        LOGI("GL buffer-binding shadow initialized: context=%p array=%u element=%u",
             current, array_buffer, element_array_buffer);
        return true;
    }

    void Bind(GLenum target, GLuint buffer) {
        if (!SynchronizeContext()) return;
        if (target == GL_ARRAY_BUFFER) array_buffer = buffer;
        else if (target == GL_ELEMENT_ARRAY_BUFFER) element_array_buffer = buffer;
    }

    void Delete(GLsizei count, const GLuint* buffers) {
        if (count <= 0 || !buffers || !SynchronizeContext()) return;
        for (GLsizei index = 0; index < count; ++index) {
            if (buffers[index] == array_buffer) array_buffer = 0;
            if (buffers[index] == element_array_buffer) element_array_buffer = 0;
        }
    }
};

static thread_local BufferBindingShadow t_buffer_bindings;

static thread_local bool t_skybox_draw = false;
void BeginHostSkyboxDraw() { t_skybox_draw = true; }
void EndHostSkyboxDraw() { t_skybox_draw = false; }

struct SkyboxDepthGuard {
    bool active = t_skybox_draw;
    GLboolean depth_test = GL_FALSE;
    GLboolean depth_write = GL_TRUE;
    GLint depth_func = GL_LESS;
    GLfloat depth_range[2] = {0.0f, 1.0f};

    SkyboxDepthGuard() {
        if (!active) return;
        depth_test = glIsEnabled(GL_DEPTH_TEST);
        glGetBooleanv(GL_DEPTH_WRITEMASK, &depth_write);
        glGetIntegerv(GL_DEPTH_FUNC, &depth_func);
        glGetFloatv(GL_DEPTH_RANGE, depth_range);
        glEnable(GL_DEPTH_TEST);
        glDepthFunc(GL_LEQUAL);
        glDepthMask(GL_FALSE);
        glDepthRangef(1.0f, 1.0f);
    }

    ~SkyboxDepthGuard() {
        if (!active) return;
        glDepthRangef(depth_range[0], depth_range[1]);
        glDepthMask(depth_write);
        glDepthFunc(static_cast<GLenum>(depth_func));
        if (!depth_test) glDisable(GL_DEPTH_TEST);
    }
};

#if defined(ASPHALT7_GL_TELEMETRY)
// Diagnostic-only, bounded telemetry. It records the host context and the
// first few geometry/texture calls without changing GL state or issuing any
// extra GL error query beyond the guest's own glGetError call. The release
// bridge compiles this block out.
static std::atomic<uint32_t> g_logged_gl_strings{0};
static std::atomic<uint32_t> g_logged_viewports{0};
static std::atomic<uint32_t> g_logged_compressed_uploads{0};
static std::atomic<uint32_t> g_logged_uncompressed_uploads{0};
static std::atomic<uint32_t> g_logged_gl_errors{0};
static std::atomic<uint32_t> g_logged_framebuffer_status{0};
static std::atomic<uint32_t> g_logged_clears{0};
static std::atomic<uint32_t> g_logged_draw_arrays{0};
static std::atomic<uint32_t> g_logged_draw_elements{0};
static std::atomic<uint32_t> g_logged_use_programs{0};
static std::atomic<uint32_t> g_logged_window_states{0};
static std::atomic<uint32_t> g_logged_bad_window_draws{0};
static std::atomic<uint32_t> g_logged_framebuffer_binds{0};
static std::atomic<uint32_t> g_logged_framebuffer_mutations{0};
static std::atomic<uint32_t> g_logged_large_allocations{0};
static std::atomic<uint64_t> g_render_frame_sequence{0};

struct TraceVertexAttribute {
    bool configured = false;
    bool client_memory = false;
    uint32_t guest_address = 0;
    GLint size = 0;
    GLenum type = 0;
    GLsizei stride = 0;
};

static thread_local std::array<TraceVertexAttribute, 16> t_trace_vertex_attributes{};

uint64_t CurrentRenderFrameSequence() {
    return g_render_frame_sequence.load(std::memory_order_relaxed);
}

void TraceFramebufferBind(GLenum target, GLuint framebuffer) {
    const uint32_t sequence = g_logged_framebuffer_binds.fetch_add(
        1, std::memory_order_relaxed);
    if (sequence >= 8192) return;

    GLint actual_framebuffer = 0;
    GLint viewport[4]{};
    GLint scissor[4]{};
    glGetIntegerv(GL_FRAMEBUFFER_BINDING, &actual_framebuffer);
    glGetIntegerv(GL_VIEWPORT, viewport);
    glGetIntegerv(GL_SCISSOR_BOX, scissor);
    LOGI("fbo_bind #%u frame=%llu target=0x%04X requested=%u actual=%d "
         "viewport=%d,%d,%d,%d scissor=%d,%d,%d,%d context=%p surface=%p",
         sequence, static_cast<unsigned long long>(CurrentRenderFrameSequence()),
         target, framebuffer, actual_framebuffer, viewport[0], viewport[1],
         viewport[2], viewport[3], scissor[0], scissor[1], scissor[2],
         scissor[3], reinterpret_cast<void*>(eglGetCurrentContext()),
         reinterpret_cast<void*>(eglGetCurrentSurface(EGL_DRAW)));
}

void TraceFramebufferMutation(const char* operation, GLenum attachment,
                              GLuint object) {
    const uint32_t sequence = g_logged_framebuffer_mutations.fetch_add(
        1, std::memory_order_relaxed);
    if (sequence >= 4096) return;

    GLint framebuffer = 0;
    glGetIntegerv(GL_FRAMEBUFFER_BINDING, &framebuffer);
    GLint attached_object = 0;
    if (framebuffer != 0) {
        glGetFramebufferAttachmentParameteriv(
            GL_FRAMEBUFFER, attachment, GL_FRAMEBUFFER_ATTACHMENT_OBJECT_NAME,
            &attached_object);
    }
    LOGI("fbo_mutation #%u frame=%llu op=%s fb=%d attachment=0x%04X "
         "object=%u actual=%d status=0x%04X",
         sequence, static_cast<unsigned long long>(CurrentRenderFrameSequence()),
         operation ? operation : "?", framebuffer, attachment, object,
         attached_object, glCheckFramebufferStatus(GL_FRAMEBUFFER));
}

void TraceLargeTextureAllocation(GLenum target, GLint level, GLint internalformat,
                                 GLsizei width, GLsizei height, GLenum format,
                                 GLenum type) {
    if (width < 1000 && height < 1000) return;
    const uint32_t sequence = g_logged_large_allocations.fetch_add(
        1, std::memory_order_relaxed);
    if (sequence >= 4096) return;

    GLint texture = 0;
    GLint framebuffer = 0;
    glGetIntegerv(GL_TEXTURE_BINDING_2D, &texture);
    glGetIntegerv(GL_FRAMEBUFFER_BINDING, &framebuffer);
    LOGI("large_tex_alloc #%u frame=%llu target=0x%04X level=%d internal=0x%04X "
         "size=%dx%d format=0x%04X type=0x%04X texture=%d fb=%d",
         sequence, static_cast<unsigned long long>(CurrentRenderFrameSequence()),
         target, level, internalformat, width, height, format, type, texture,
         framebuffer);
}

void LogLineStripState(DynarmicHost& host, uint32_t sequence, GLenum mode,
                       GLint first, GLsizei count) {
    if (mode != GL_LINE_STRIP || count <= 0 || sequence >= 128) return;

    GLint program = 0;
    GLint active_texture = 0;
    GLint texture = 0;
    GLint viewport[4]{};
    GLboolean color_mask[4]{};
    glGetIntegerv(GL_CURRENT_PROGRAM, &program);
    glGetIntegerv(GL_ACTIVE_TEXTURE, &active_texture);
    glGetIntegerv(GL_TEXTURE_BINDING_2D, &texture);
    glGetIntegerv(GL_VIEWPORT, viewport);
    glGetBooleanv(GL_COLOR_WRITEMASK, color_mask);
    LOGI("line_strip #%u first=%d count=%d program=%d texture=%d active=0x%04X "
         "blend=%d depth=%d scissor=%d viewport=%d,%d,%d,%d mask=%d%d%d%d",
         sequence, first, count, program, texture, active_texture,
         glIsEnabled(GL_BLEND), glIsEnabled(GL_DEPTH_TEST),
         glIsEnabled(GL_SCISSOR_TEST), viewport[0], viewport[1], viewport[2],
         viewport[3], color_mask[0], color_mask[1], color_mask[2], color_mask[3]);

    for (size_t index = 0; index < t_trace_vertex_attributes.size(); ++index) {
        const TraceVertexAttribute& attribute = t_trace_vertex_attributes[index];
        if (!attribute.configured) continue;
        GLint enabled = 0;
        glGetVertexAttribiv(static_cast<GLuint>(index), GL_VERTEX_ATTRIB_ARRAY_ENABLED,
                            &enabled);
        if (!attribute.client_memory || attribute.type != GL_FLOAT ||
            attribute.guest_address == 0 || attribute.stride < 0 || attribute.size <= 0 ||
            attribute.size > 4) {
            LOGI("line_strip_attr #%u index=%zu enabled=%d client=%d guest=0x%08X "
                 "size=%d type=0x%04X stride=%d",
                 sequence, index, enabled, attribute.client_memory, attribute.guest_address,
                 attribute.size, attribute.type, attribute.stride);
            continue;
        }

        const size_t step = attribute.stride ? static_cast<size_t>(attribute.stride)
                                             : static_cast<size_t>(attribute.size) * sizeof(float);
        const uint64_t start = static_cast<uint64_t>(attribute.guest_address) +
                               static_cast<uint64_t>(std::max(first, 0)) * step;
        const size_t sample_bytes = static_cast<size_t>(attribute.size) * sizeof(float);
        if (start > host.GetGuestMemorySize() || sample_bytes > host.GetGuestMemorySize() - start) {
            LOGI("line_strip_attr #%u index=%zu enabled=%d client=1 guest=0x%08X "
                 "size=%d type=0x%04X stride=%d sample=invalid",
                 sequence, index, enabled, attribute.guest_address, attribute.size,
                 attribute.type, attribute.stride);
            continue;
        }
        float values[4]{};
        std::memcpy(values, host.GetGuestMemoryBase() + start, sample_bytes);
        LOGI("line_strip_attr #%u index=%zu enabled=%d guest=0x%08X size=%d stride=%d "
             "v0=%g,%g,%g,%g",
             sequence, index, enabled, attribute.guest_address, attribute.size,
             attribute.stride, values[0], values[1], values[2], values[3]);
    }
}

void LogGlStringOnce(GLenum name, const GLubyte* value) {
    uint32_t bit = 0;
    const char* label = nullptr;
    switch (name) {
        case GL_VENDOR:
            bit = 1u << 0;
            label = "GL_VENDOR";
            break;
        case GL_RENDERER:
            bit = 1u << 1;
            label = "GL_RENDERER";
            break;
        case GL_VERSION:
            bit = 1u << 2;
            label = "GL_VERSION";
            break;
        case GL_EXTENSIONS:
            bit = 1u << 3;
            label = "GL_EXTENSIONS";
            break;
        default:
            return;
    }
    uint32_t observed = g_logged_gl_strings.load(std::memory_order_relaxed);
    while (!(observed & bit) &&
           !g_logged_gl_strings.compare_exchange_weak(
               observed, observed | bit, std::memory_order_relaxed)) {
    }
    if (observed & bit) return;
    LOGI("%s=%s", label, value ? reinterpret_cast<const char*>(value) : "<null>");
}
#endif

void TraceHostGlRaceState(bool in_race) {
#if defined(ASPHALT7_GL_TELEMETRY)
    static bool previous_in_race = false;
    if (in_race == previous_in_race) return;
    previous_in_race = in_race;
    LOGI("render_mode frame=%llu race=%d",
         static_cast<unsigned long long>(CurrentRenderFrameSequence()),
         in_race ? 1 : 0);
    if (!in_race) return;
    g_logged_viewports.store(0, std::memory_order_relaxed);
    g_logged_window_states.store(0, std::memory_order_relaxed);
    g_logged_bad_window_draws.store(0, std::memory_order_relaxed);
    g_logged_framebuffer_binds.store(0, std::memory_order_relaxed);
    g_logged_framebuffer_mutations.store(0, std::memory_order_relaxed);
    g_logged_framebuffer_status.store(0, std::memory_order_relaxed);
    g_logged_clears.store(0, std::memory_order_relaxed);
    g_logged_draw_arrays.store(0, std::memory_order_relaxed);
    g_logged_draw_elements.store(0, std::memory_order_relaxed);
    g_logged_gl_errors.store(0, std::memory_order_relaxed);
#else
    (void)in_race;
#endif
}

void TraceHostDefaultFramebufferState(const char* stage) {
#if defined(ASPHALT7_GL_TELEMETRY)
    if (stage && strcmp(stage, "step-pre") == 0) {
        g_render_frame_sequence.fetch_add(1, std::memory_order_relaxed);
    }
    GLint authority_x = 0;
    GLint authority_y = 0;
    GLsizei authority_width = 0;
    GLsizei authority_height = 0;
    if (!GetHostDefaultFramebufferViewport(
            authority_x, authority_y, authority_width, authority_height) ||
        authority_width <= 1920) {
        return;
    }

    const uint32_t sequence =
        g_logged_window_states.fetch_add(1, std::memory_order_relaxed);
    if (sequence >= 2048) return;

    GLint framebuffer = 0;
    GLint viewport[4]{};
    GLint scissor[4]{};
    glGetIntegerv(GL_FRAMEBUFFER_BINDING, &framebuffer);
    glGetIntegerv(GL_VIEWPORT, viewport);
    glGetIntegerv(GL_SCISSOR_BOX, scissor);
    const GLboolean scissor_enabled = glIsEnabled(GL_SCISSOR_TEST);
    LOGI("window_state #%u frame=%llu stage=%s fb=%d viewport=%d,%d,%d,%d "
         "scissor_enabled=%d scissor=%d,%d,%d,%d authority=%d,%d,%d,%d "
         "context=%p surface=%p",
         sequence, static_cast<unsigned long long>(CurrentRenderFrameSequence()),
         stage ? stage : "?", framebuffer, viewport[0], viewport[1],
         viewport[2], viewport[3], scissor_enabled == GL_TRUE ? 1 : 0,
         scissor[0], scissor[1], scissor[2], scissor[3], authority_x,
         authority_y, authority_width, authority_height,
         reinterpret_cast<void*>(eglGetCurrentContext()),
         reinterpret_cast<void*>(eglGetCurrentSurface(EGL_DRAW)));
#else
    (void)stage;
#endif
}

static void TraceUnexpectedDefaultFramebufferDraw(const char* operation) {
#if defined(ASPHALT7_GL_TELEMETRY)
    GLint authority_x = 0;
    GLint authority_y = 0;
    GLsizei authority_width = 0;
    GLsizei authority_height = 0;
    if (!GetHostDefaultFramebufferViewport(
            authority_x, authority_y, authority_width, authority_height) ||
        authority_width <= 1920) {
        return;
    }

    GLint framebuffer = 0;
    glGetIntegerv(GL_FRAMEBUFFER_BINDING, &framebuffer);
    if (framebuffer != 0) return;

    GLint viewport[4]{};
    GLint scissor[4]{};
    glGetIntegerv(GL_VIEWPORT, viewport);
    glGetIntegerv(GL_SCISSOR_BOX, scissor);
    const bool viewport_wrong =
        viewport[0] != authority_x || viewport[1] != authority_y ||
        viewport[2] != authority_width || viewport[3] != authority_height;
    const GLboolean scissor_enabled = glIsEnabled(GL_SCISSOR_TEST);
    const bool scissor_wrong =
        scissor_enabled == GL_TRUE &&
        (scissor[0] != authority_x || scissor[1] != authority_y ||
         scissor[2] != authority_width || scissor[3] != authority_height);
    if (!viewport_wrong && !scissor_wrong) return;

    const uint32_t sequence =
        g_logged_bad_window_draws.fetch_add(1, std::memory_order_relaxed);
    if (sequence >= 1024) return;
    LOGI("bad_window_draw #%u op=%s viewport=%d,%d,%d,%d "
         "scissor_enabled=%d scissor=%d,%d,%d,%d authority=%d,%d,%d,%d",
         sequence, operation ? operation : "?", viewport[0], viewport[1],
         viewport[2], viewport[3], scissor_enabled == GL_TRUE ? 1 : 0,
         scissor[0], scissor[1], scissor[2], scissor[3], authority_x,
         authority_y, authority_width, authority_height);
#else
    (void)operation;
#endif
}

struct MappedBufferShadow {
    void* host_pointer = nullptr;
    uint32_t guest_address = 0;
    size_t size = 0;
};

using MappedBufferKey = std::pair<uintptr_t, GLuint>;
static std::mutex g_mapped_buffers_mutex;
static std::map<MappedBufferKey, MappedBufferShadow> g_mapped_buffers;

template <typename Function>
Function ExtensionProc(const char* name) {
    return reinterpret_cast<Function>(eglGetProcAddress(name));
}

bool HasGlExtension(const char* extensions, const char* name) {
    if (!extensions) return false;
    const size_t length = strlen(name);
    for (const char* found = strstr(extensions, name); found;
         found = strstr(found + length, name)) {
        if ((found == extensions || found[-1] == ' ') &&
            (found[length] == 0 || found[length] == ' ')) return true;
    }
    return false;
}

PFNGLMAPBUFFERRANGEEXTPROC ReadableBufferMapFunction() {
    // OES_mapbuffer permits only WRITE_ONLY. The bridge must read the old
    // bytes to preserve portions the guest leaves untouched, so use a host
    // mapping that explicitly permits both reads and writes.
    const char* version = reinterpret_cast<const char*>(glGetString(GL_VERSION));
    int major = 0, minor = 0;
    if (version && std::sscanf(version, "OpenGL ES %d.%d", &major, &minor) == 2 && major >= 3)
        return ExtensionProc<PFNGLMAPBUFFERRANGEEXTPROC>("glMapBufferRange");
    const char* extensions = reinterpret_cast<const char*>(glGetString(GL_EXTENSIONS));
    return HasGlExtension(extensions, "GL_EXT_map_buffer_range")
        ? ExtensionProc<PFNGLMAPBUFFERRANGEEXTPROC>("glMapBufferRangeEXT") : nullptr;
}

PFNGLUNMAPBUFFEROESPROC HostBufferUnmapFunction() {
    const char* version = reinterpret_cast<const char*>(glGetString(GL_VERSION));
    int major = 0, minor = 0;
    if (version && std::sscanf(version, "OpenGL ES %d.%d", &major, &minor) == 2 && major >= 3)
        return ExtensionProc<PFNGLUNMAPBUFFEROESPROC>("glUnmapBuffer");
    return ExtensionProc<PFNGLUNMAPBUFFEROESPROC>("glUnmapBufferOES");
}

MappedBufferKey CurrentBufferMappingKey(GLenum target) {
    GLint buffer = 0;
    if (target == GL_ARRAY_BUFFER) glGetIntegerv(GL_ARRAY_BUFFER_BINDING, &buffer);
    else if (target == GL_ELEMENT_ARRAY_BUFFER)
        glGetIntegerv(GL_ELEMENT_ARRAY_BUFFER_BINDING, &buffer);
    return {reinterpret_cast<uintptr_t>(eglGetCurrentContext()), static_cast<GLuint>(buffer)};
}

void DiscardMappedBufferShadow(DynarmicHost& host, const MappedBufferKey& key) {
    uint32_t guest_address = 0;
    {
        std::lock_guard lock(g_mapped_buffers_mutex);
        const auto found = g_mapped_buffers.find(key);
        if (found == g_mapped_buffers.end()) return;
        guest_address = found->second.guest_address;
        g_mapped_buffers.erase(found);
    }
    host.GuestFree(guest_address);
}

// Shared EGL contexts can unmap the same buffer object. A driver map pointer
// identifies that shared store without confusing equal names in unrelated
// contexts; exact context/name lookups remain the common path.
auto FindMappedBufferShadow(const MappedBufferKey& key, void* host_pointer) {
    auto found = g_mapped_buffers.find(key);
    if (found == g_mapped_buffers.end() && host_pointer) {
        found = std::find_if(g_mapped_buffers.begin(), g_mapped_buffers.end(),
            [&](const auto& entry) {
                return entry.first.second == key.second &&
                       entry.second.host_pointer == host_pointer;
            });
    }
    return found;
}

using HostBufferPointerFunction = void (*)(GLenum, GLenum, void**);

HostBufferPointerFunction BufferPointerFunction() {
    const char* version = reinterpret_cast<const char*>(glGetString(GL_VERSION));
    int major = 0, minor = 0;
    if (version && std::sscanf(version, "OpenGL ES %d.%d", &major, &minor) == 2 && major >= 3)
        return ExtensionProc<HostBufferPointerFunction>("glGetBufferPointerv");
    return ExtensionProc<HostBufferPointerFunction>("glGetBufferPointervOES");
}

void* CurrentHostBufferMapPointer(GLenum target) {
    const HostBufferPointerFunction function = BufferPointerFunction();
    void* pointer = nullptr;
    if (function) function(target, GL_BUFFER_MAP_POINTER_OES, &pointer);
    return pointer;
}

std::string GuestGlExtensions(const char* extensions) {
    if (!extensions) return {};
    std::string result(extensions);
    if (ReadableBufferMapFunction() && HostBufferUnmapFunction()) return result;
    constexpr char name[] = "GL_OES_mapbuffer";
    if (HasGlExtension(extensions, name)) {
        const size_t length = sizeof(name) - 1;
        size_t start = result.find(name);
        while (start != std::string::npos) {
            const size_t end = start + length;
            if ((start == 0 || result[start - 1] == ' ') &&
                (end == result.size() || result[end] == ' ')) {
                result.erase(start, length);
                break;
            }
            start = result.find(name, end);
        }
    }
    return result;
}

std::string RewriteGraphicsShaderSource(const std::vector<const GLchar*>& strings,
                                      const GLint* lengths, bool disable_road_reflections) {
    std::string source;
    for (size_t index = 0; index < strings.size(); ++index) {
        const size_t length = lengths && lengths[index] >= 0
            ? static_cast<size_t>(lengths[index]) : strlen(strings[index]);
        if (!length) continue;
        const std::string_view fragment(strings[index], length);
        if (disable_road_reflections &&
            fragment.find("ReflectionTextureJustForMax") != std::string_view::npos) {
            // Guest macro definitions precede this road fragment. Undefine
            // here, while retaining a leading #version as the first directive.
            const size_t first = fragment.find_first_not_of(" \t\r\n");
            size_t prefix = 0;
            if (first != std::string_view::npos && fragment.substr(first).starts_with("#version")) {
                const size_t newline = fragment.find('\n', first);
                prefix = newline == std::string_view::npos ? length : newline + 1;
                source.append(fragment.substr(0, prefix));
            }
            source.append("\n#undef USE_REFLECTION\n");
            source.append(fragment.substr(prefix));
        } else {
            source.append(fragment);
        }
    }
    return source;
}

template <typename T>
T* CheckedGuestArray(DynarmicHost& host, uint32_t address, uint64_t count, const char* function_name) {
    if (!count) return nullptr;
    if (count > std::numeric_limits<size_t>::max() / sizeof(T)) {
        LOGE("%s rejected overflowing guest extent", function_name);
        host.Fail("guest GL extent overflow");
        return nullptr;
    }
    const size_t bytes = static_cast<size_t>(count) * sizeof(T);
    void* value = GuestSpan(host.GetGuestMemoryBase(), host.GetGuestMemorySize(), address, bytes);
    if (!value) {
        LOGE("%s rejected guest range address=0x%08X bytes=%zu", function_name, address, bytes);
        host.Fail("invalid guest GL range");
        return nullptr;
    }
    return static_cast<T*>(value);
}

template <typename T>
T* OptionalGuestArray(DynarmicHost& host, uint32_t address, uint64_t count, const char* function_name) {
    return address ? CheckedGuestArray<T>(host, address, count, function_name) : nullptr;
}

const void* CheckedGuestPointer(DynarmicHost& host, uint32_t address, const char* function_name,
                               bool allow_null = false) {
    if (!address) {
        if (allow_null) return nullptr;
        LOGE("%s rejected null guest pointer", function_name);
        host.Fail("null guest GL pointer");
        return nullptr;
    }
    return CheckedGuestArray<uint8_t>(host, address, 1, function_name);
}

constexpr GLsizei GuestI32(uint32_t value) {
    return static_cast<GLsizei>(static_cast<int32_t>(value));
}

static_assert(static_cast<GLsizeiptr>(static_cast<int32_t>(UINT32_MAX)) == -1,
              "GLsizeiptr must preserve ARM32 signed values");

void RegisterGles2CoreThunks(ThunkManager& manager);

void ThunkManager::RegisterGLThunks() {
    uint8_t* mem = m_host.GetGuestMemoryBase();

    RegisterThunk("a7_CCameraSceneNode_setAspectRatio", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        const std::uint32_t camera_node =
            g_host_gameplay_camera_node.load(std::memory_order_acquire);
        const std::uint32_t aspect_ratio_bits =
            g_host_gameplay_aspect_ratio_bits.load(std::memory_order_acquire);
        const bool override = camera_node != 0 && jit.Regs()[0] == camera_node &&
                              aspect_ratio_bits != 0;
#if defined(ASPHALT7_GL_TELEMETRY)
        static std::atomic<std::uint32_t> logged_camera_aspect_calls{0};
        const std::uint32_t sequence = logged_camera_aspect_calls.fetch_add(
            1, std::memory_order_relaxed);
        if (sequence < 64) {
            LOGI("camera_aspect_override #%u node=0x%08x requested=0x%08x applied=0x%08x",
                 sequence, jit.Regs()[0], jit.Regs()[1],
                 override ? aspect_ratio_bits : jit.Regs()[1]);
        }
#endif
        if (override) jit.Regs()[1] = aspect_ratio_bits;
        // The instruction replaced by this SVC initializes r3 before the
        // original setter body loads and updates the dirty flags at +0x300.
        jit.Regs()[3] = 0x300;
    });

    RegisterThunk("glActiveTexture", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glActiveTexture(static_cast<GLenum>(jit.Regs()[0]));
    });

    RegisterThunk("glAttachShader", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glAttachShader(jit.Regs()[0], jit.Regs()[1]);
    });

    RegisterThunk("glBindBuffer", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const GLenum target = static_cast<GLenum>(jit.Regs()[0]);
        const GLuint buffer = jit.Regs()[1];
        glBindBuffer(target, buffer);
        t_buffer_bindings.Bind(target, buffer);
    });

    RegisterThunk("glBindFramebuffer", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const GLenum target = static_cast<GLenum>(jit.Regs()[0]);
        const GLuint framebuffer = jit.Regs()[1];
        glBindFramebuffer(target, framebuffer);

        // GL rectangles survive framebuffer binds. Apply the window override
        // only to framebuffer 0 and undo it when entering an offscreen pass,
        // even when the guest's state cache suppresses a new viewport call.
        if (target == GL_FRAMEBUFFER) {
            if (framebuffer == 0) RestoreHostDefaultFramebufferState();
            else RestoreGuestOffscreenFramebufferRectangles();
        }
#if defined(ASPHALT7_GL_TELEMETRY)
        TraceFramebufferBind(target, framebuffer);
#endif
    });

    RegisterThunk("glBindRenderbuffer", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glBindRenderbuffer(static_cast<GLenum>(jit.Regs()[0]), jit.Regs()[1]);
    });

    RegisterThunk("glBindTexture", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glBindTexture(static_cast<GLenum>(jit.Regs()[0]), jit.Regs()[1]);
    });

    RegisterThunk("glBlendFunc", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glBlendFunc(static_cast<GLenum>(jit.Regs()[0]), static_cast<GLenum>(jit.Regs()[1]));
    });

    RegisterThunk("glBufferData", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const GLenum target = static_cast<GLenum>(jit.Regs()[0]);
        const GLsizeiptr size = static_cast<GLsizeiptr>(static_cast<int32_t>(jit.Regs()[1]));
        const void* data = nullptr;
        if (size > 0 && jit.Regs()[2])
            data = CheckedGuestArray<uint8_t>(host, jit.Regs()[2], static_cast<uint64_t>(size), "glBufferData");
        const GLenum usage = static_cast<GLenum>(jit.Regs()[3]);
        if (host.HasFailed()) return;
        glBufferData(target, size, data, usage);
        const auto key = CurrentBufferMappingKey(target);
        bool staged = false;
        {
            std::lock_guard lock(g_mapped_buffers_mutex);
            staged = g_mapped_buffers.find(key) != g_mapped_buffers.end();
        }
        if (staged) {
            GLint mapped = GL_TRUE;
            glGetBufferParameteriv(target, GL_BUFFER_MAPPED_OES, &mapped);
            if (!mapped) DiscardMappedBufferShadow(host, key);
        }
    });

    RegisterThunk("glCheckFramebufferStatus", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const GLenum target = static_cast<GLenum>(jit.Regs()[0]);
        const GLenum status = glCheckFramebufferStatus(target);
        jit.Regs()[0] = status;
#if defined(ASPHALT7_GL_TELEMETRY)
        const uint32_t sequence = g_logged_framebuffer_status.fetch_add(
            1, std::memory_order_relaxed);
        if (sequence < 128) {
            LOGI("framebuffer_status #%u target=0x%04X status=0x%04X",
                 sequence, target, status);
        }
#endif
    });

    RegisterThunk("glClear", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const GLbitfield mask = static_cast<GLbitfield>(jit.Regs()[0]);
        TraceUnexpectedDefaultFramebufferDraw("glClear");
        glClear(mask);
#if defined(ASPHALT7_GL_TELEMETRY)
        const uint32_t sequence = g_logged_clears.fetch_add(1, std::memory_order_relaxed);
        if (sequence < 4096) {
            GLint framebuffer = 0;
            GLint viewport[4]{};
            glGetIntegerv(GL_FRAMEBUFFER_BINDING, &framebuffer);
            glGetIntegerv(GL_VIEWPORT, viewport);
            LOGI("clear #%u frame=%llu mask=0x%04X fb=%d viewport=%d,%d,%d,%d",
                 sequence,
                 static_cast<unsigned long long>(CurrentRenderFrameSequence()),
                 mask, framebuffer, viewport[0], viewport[1], viewport[2],
                 viewport[3]);
        }
#endif
    });

    RegisterThunk("glClearColor", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        float r = ReadSF(jit, 0);
        float g = ReadSF(jit, 1);
        float b = ReadSF(jit, 2);
        float a = ReadSF(jit, 3);
        glClearColor(r, g, b, a);
    });

    RegisterThunk("glColorMask", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glColorMask(jit.Regs()[0], jit.Regs()[1], jit.Regs()[2], jit.Regs()[3]);
    });

    RegisterThunk("glCompileShader", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        GLuint shader = jit.Regs()[0];
        glCompileShader(shader);
#ifndef NDEBUG
        GLint compiled = 0;
        glGetShaderiv(shader, GL_COMPILE_STATUS, &compiled);
        if (!compiled) {
            char log[1024];
            glGetShaderInfoLog(shader, sizeof(log), nullptr, log);
            LOGE("Shader %u compile failed: %s", shader, log);
        }
#endif
    });

    RegisterThunk("glCompressedTexImage2D", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const GLenum target = jit.Regs()[0];
        const GLint level = static_cast<GLint>(static_cast<int32_t>(jit.Regs()[1]));
        const GLenum internalformat = jit.Regs()[2];
        const GLsizei width = GuestI32(jit.Regs()[3]);
        const GLsizei height = GuestI32(host.ReadStackWord(jit, 0));
        const GLint border = static_cast<GLint>(static_cast<int32_t>(host.ReadStackWord(jit, 1)));
        const GLsizei image_size = GuestI32(host.ReadStackWord(jit, 2));
        const uint32_t data_address = host.ReadStackWord(jit, 3);
        const void* data = image_size > 0
            ? CheckedGuestArray<uint8_t>(host, data_address, static_cast<uint64_t>(image_size),
                                         "glCompressedTexImage2D")
            : nullptr;
        if (host.HasFailed()) return;
        glCompressedTexImage2D(target, level, internalformat, width, height, border, image_size, data);
#if defined(ASPHALT7_GL_TELEMETRY)
        const uint32_t sequence = g_logged_compressed_uploads.fetch_add(
            1, std::memory_order_relaxed);
        if (sequence < 128) {
            LOGI("compressed_upload #%u target=0x%04X level=%d format=0x%04X "
                 "size=%dx%d bytes=%d", sequence, target, level, internalformat,
                 width, height, image_size);
        }
#endif
    });

    RegisterThunk("glCreateProgram", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = glCreateProgram();
    });

    RegisterThunk("glCreateShader", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = glCreateShader(static_cast<GLenum>(jit.Regs()[0]));
    });

    RegisterThunk("glCullFace", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glCullFace(static_cast<GLenum>(jit.Regs()[0]));
    });

    RegisterThunk("glDeleteBuffers", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const GLsizei count = GuestI32(jit.Regs()[0]);
        const GLuint* buffers = count > 0
            ? CheckedGuestArray<GLuint>(host, jit.Regs()[1], static_cast<uint64_t>(count), "glDeleteBuffers")
            : nullptr;
        if (host.HasFailed()) return;
        const uintptr_t context = reinterpret_cast<uintptr_t>(eglGetCurrentContext());
        for (GLsizei index = 0; index < count; ++index)
            DiscardMappedBufferShadow(host, {context, buffers[index]});
        glDeleteBuffers(count, buffers);
        t_buffer_bindings.Delete(count, buffers);
    });

    RegisterThunk("glDeleteFramebuffers", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const GLsizei count = GuestI32(jit.Regs()[0]);
        const GLuint* framebuffers = count > 0
            ? CheckedGuestArray<GLuint>(host, jit.Regs()[1], static_cast<uint64_t>(count), "glDeleteFramebuffers")
            : nullptr;
        if (host.HasFailed()) return;
        glDeleteFramebuffers(count, framebuffers);
    });

    RegisterThunk("glDeleteProgram", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glDeleteProgram(jit.Regs()[0]);
    });

    RegisterThunk("glDeleteRenderbuffers", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const GLsizei count = GuestI32(jit.Regs()[0]);
        const GLuint* renderbuffers = count > 0
            ? CheckedGuestArray<GLuint>(host, jit.Regs()[1], static_cast<uint64_t>(count), "glDeleteRenderbuffers")
            : nullptr;
        if (host.HasFailed()) return;
        glDeleteRenderbuffers(count, renderbuffers);
    });

    RegisterThunk("glDeleteShader", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glDeleteShader(jit.Regs()[0]);
    });

    RegisterThunk("glDeleteTextures", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const GLsizei count = GuestI32(jit.Regs()[0]);
        const GLuint* textures = count > 0
            ? CheckedGuestArray<GLuint>(host, jit.Regs()[1], static_cast<uint64_t>(count), "glDeleteTextures")
            : nullptr;
        if (host.HasFailed()) return;
        glDeleteTextures(count, textures);
    });

    RegisterThunk("glDepthFunc", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glDepthFunc(static_cast<GLenum>(jit.Regs()[0]));
    });

    RegisterThunk("glDepthMask", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glDepthMask(static_cast<GLboolean>(jit.Regs()[0]));
    });

    RegisterThunk("glDisable", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glDisable(static_cast<GLenum>(jit.Regs()[0]));
    });

    RegisterThunk("glDisableVertexAttribArray", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glDisableVertexAttribArray(jit.Regs()[0]);
    });

    RegisterThunk("glDrawArrays", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const GLenum mode = static_cast<GLenum>(jit.Regs()[0]);
        const GLint first = static_cast<GLint>(jit.Regs()[1]);
        const GLsizei count = static_cast<GLsizei>(jit.Regs()[2]);
        TraceUnexpectedDefaultFramebufferDraw("glDrawArrays");
        {
            SkyboxDepthGuard skybox_depth;
            glDrawArrays(mode, first, count);
        }
#if defined(ASPHALT7_GL_TELEMETRY)
        const uint32_t sequence = g_logged_draw_arrays.fetch_add(1, std::memory_order_relaxed);
        if (sequence < 128) {
            LOGI("draw_arrays #%u mode=0x%04X first=%d count=%d", sequence, mode, first, count);
        }
        LogLineStripState(host, sequence, mode, first, count);
#endif
    });

    RegisterThunk("glDrawElements", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const GLenum mode = static_cast<GLenum>(jit.Regs()[0]);
        const GLsizei count = GuestI32(jit.Regs()[1]);
        const GLenum type = static_cast<GLenum>(jit.Regs()[2]);
        const uint32_t indices_address = jit.Regs()[3];
        t_buffer_bindings.SynchronizeContext();
        const void* indices = t_buffer_bindings.element_array_buffer != 0
            ? reinterpret_cast<const void*>(static_cast<uintptr_t>(indices_address))
            : (count > 0 ? CheckedGuestPointer(host, indices_address, "glDrawElements") : nullptr);
        if (host.HasFailed()) return;
        TraceUnexpectedDefaultFramebufferDraw("glDrawElements");
        {
            SkyboxDepthGuard skybox_depth;
            glDrawElements(mode, count, type, indices);
        }
#if defined(ASPHALT7_GL_TELEMETRY)
        const uint32_t sequence = g_logged_draw_elements.fetch_add(1, std::memory_order_relaxed);
        if (sequence < 128) {
            LOGI("draw_elements #%u mode=0x%04X count=%d type=0x%04X indices=%s", sequence,
                 mode, count, type, indices ? "set" : "null");
        }
#endif
    });

    RegisterThunk("glEnable", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glEnable(static_cast<GLenum>(jit.Regs()[0]));
    });

    RegisterThunk("glEnableVertexAttribArray", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glEnableVertexAttribArray(jit.Regs()[0]);
    });

    RegisterThunk("glFlush", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glFlush();
    });

    RegisterThunk("glFramebufferRenderbuffer", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const GLenum target = static_cast<GLenum>(jit.Regs()[0]);
        const GLenum attachment = static_cast<GLenum>(jit.Regs()[1]);
        const GLenum renderbuffer_target = static_cast<GLenum>(jit.Regs()[2]);
        const GLuint renderbuffer = jit.Regs()[3];
        glFramebufferRenderbuffer(target, attachment, renderbuffer_target,
                                  renderbuffer);
#if defined(ASPHALT7_GL_TELEMETRY)
        TraceFramebufferMutation("renderbuffer", attachment, renderbuffer);
#endif
    });

    RegisterThunk("glFramebufferTexture2D", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const GLenum target = static_cast<GLenum>(jit.Regs()[0]);
        const GLenum attachment = static_cast<GLenum>(jit.Regs()[1]);
        const GLenum textarget = static_cast<GLenum>(jit.Regs()[2]);
        // AAPCS32: the texture name is argument 4 (r3), and the mip level
        // is argument 5 ([sp]). Swapping them rejects every nonzero texture
        // attachment in GLES2, whose framebuffer mip level must be zero.
        const GLuint texture = jit.Regs()[3];
        const GLint level = GuestI32(host.ReadStackWord(jit, 0));
        glFramebufferTexture2D(target, attachment, textarget, texture, level);
#if defined(ASPHALT7_GL_TELEMETRY)
        TraceFramebufferMutation("texture", attachment, texture);
#endif
    });

    RegisterThunk("glFrontFace", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glFrontFace(static_cast<GLenum>(jit.Regs()[0]));
    });

    RegisterThunk("glGenBuffers", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const GLsizei count = GuestI32(jit.Regs()[0]);
        GLuint* buffers = count > 0
            ? CheckedGuestArray<GLuint>(host, jit.Regs()[1], static_cast<uint64_t>(count), "glGenBuffers")
            : nullptr;
        if (host.HasFailed()) return;
        glGenBuffers(count, buffers);
    });

    RegisterThunk("glGenFramebuffers", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const GLsizei count = GuestI32(jit.Regs()[0]);
        GLuint* framebuffers = count > 0
            ? CheckedGuestArray<GLuint>(host, jit.Regs()[1], static_cast<uint64_t>(count), "glGenFramebuffers")
            : nullptr;
        if (host.HasFailed()) return;
        glGenFramebuffers(count, framebuffers);
    });

    RegisterThunk("glGenRenderbuffers", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const GLsizei count = GuestI32(jit.Regs()[0]);
        GLuint* renderbuffers = count > 0
            ? CheckedGuestArray<GLuint>(host, jit.Regs()[1], static_cast<uint64_t>(count), "glGenRenderbuffers")
            : nullptr;
        if (host.HasFailed()) return;
        glGenRenderbuffers(count, renderbuffers);
    });

    RegisterThunk("glGenTextures", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const GLsizei count = GuestI32(jit.Regs()[0]);
        GLuint* textures = count > 0
            ? CheckedGuestArray<GLuint>(host, jit.Regs()[1], static_cast<uint64_t>(count), "glGenTextures")
            : nullptr;
        if (host.HasFailed()) return;
        glGenTextures(count, textures);
    });

    RegisterThunk("glGenerateMipmap", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glGenerateMipmap(static_cast<GLenum>(jit.Regs()[0]));
    });

    RegisterThunk("glGetActiveAttrib", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const GLsizei buf_size = GuestI32(jit.Regs()[2]);
        GLsizei* length = OptionalGuestArray<GLsizei>(host, jit.Regs()[3], 1, "glGetActiveAttrib");
        GLint* size = CheckedGuestArray<GLint>(host, host.ReadStackWord(jit, 0), 1, "glGetActiveAttrib");
        GLenum* type = CheckedGuestArray<GLenum>(host, host.ReadStackWord(jit, 1), 1, "glGetActiveAttrib");
        GLchar* name = buf_size > 0
            ? CheckedGuestArray<GLchar>(host, host.ReadStackWord(jit, 2), static_cast<uint64_t>(buf_size),
                                        "glGetActiveAttrib")
            : nullptr;
        if (host.HasFailed()) return;
        glGetActiveAttrib(jit.Regs()[0], jit.Regs()[1], buf_size, length, size, type, name);
    });

    RegisterThunk("glGetActiveUniform", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const GLsizei buf_size = GuestI32(jit.Regs()[2]);
        GLsizei* length = OptionalGuestArray<GLsizei>(host, jit.Regs()[3], 1, "glGetActiveUniform");
        GLint* size = CheckedGuestArray<GLint>(host, host.ReadStackWord(jit, 0), 1, "glGetActiveUniform");
        GLenum* type = CheckedGuestArray<GLenum>(host, host.ReadStackWord(jit, 1), 1, "glGetActiveUniform");
        GLchar* name = buf_size > 0
            ? CheckedGuestArray<GLchar>(host, host.ReadStackWord(jit, 2), static_cast<uint64_t>(buf_size),
                                        "glGetActiveUniform")
            : nullptr;
        if (host.HasFailed()) return;
        glGetActiveUniform(jit.Regs()[0], jit.Regs()[1], buf_size, length, size, type, name);
    });

    RegisterThunk("glGetAttribLocation", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* name = GuestCString(host.GetGuestMemoryBase(), host.GetGuestMemorySize(), jit.Regs()[1]);
        if (!name) LOGE("glGetAttribLocation rejected guest string");
        jit.Regs()[0] = name ? glGetAttribLocation(jit.Regs()[0], name) : -1;
    });

    RegisterThunk("glGetError", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const GLenum error = glGetError();
        jit.Regs()[0] = error;
#if defined(ASPHALT7_GL_TELEMETRY)
        if (error != GL_NO_ERROR) {
            const uint32_t sequence = g_logged_gl_errors.fetch_add(
                1, std::memory_order_relaxed);
            if (sequence < 128) {
                LOGE("gl_error #%u code=0x%04X", sequence, error);
            }
        }
#endif
    });

    RegisterThunk("glGetIntegerv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        GLint* data = CheckedGuestArray<GLint>(host, jit.Regs()[1], 1, "glGetIntegerv");
        if (host.HasFailed()) return;
        glGetIntegerv(static_cast<GLenum>(jit.Regs()[0]), data);
    });

    RegisterThunk("glGetProgramInfoLog", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const GLsizei buf_size = GuestI32(jit.Regs()[1]);
        GLsizei* length = OptionalGuestArray<GLsizei>(host, jit.Regs()[2], 1, "glGetProgramInfoLog");
        GLchar* info_log = buf_size > 0
            ? CheckedGuestArray<GLchar>(host, jit.Regs()[3], static_cast<uint64_t>(buf_size), "glGetProgramInfoLog")
            : nullptr;
        if (host.HasFailed()) return;
        glGetProgramInfoLog(jit.Regs()[0], buf_size, length, info_log);
    });

    RegisterThunk("glGetProgramiv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        GLint* params = CheckedGuestArray<GLint>(host, jit.Regs()[2], 1, "glGetProgramiv");
        if (host.HasFailed()) return;
        glGetProgramiv(jit.Regs()[0], static_cast<GLenum>(jit.Regs()[1]), params);
    });

    RegisterThunk("glGetRenderbufferParameteriv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        GLint* params = CheckedGuestArray<GLint>(host, jit.Regs()[2], 1, "glGetRenderbufferParameteriv");
        if (host.HasFailed()) return;
        glGetRenderbufferParameteriv(jit.Regs()[0], jit.Regs()[1], params);
    });

    RegisterThunk("glGetShaderInfoLog", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const GLsizei buf_size = GuestI32(jit.Regs()[1]);
        GLsizei* length = OptionalGuestArray<GLsizei>(host, jit.Regs()[2], 1, "glGetShaderInfoLog");
        GLchar* info_log = buf_size > 0
            ? CheckedGuestArray<GLchar>(host, jit.Regs()[3], static_cast<uint64_t>(buf_size), "glGetShaderInfoLog")
            : nullptr;
        if (host.HasFailed()) return;
        glGetShaderInfoLog(jit.Regs()[0], buf_size, length, info_log);
    });

    RegisterThunk("glGetShaderiv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        GLint* params = CheckedGuestArray<GLint>(host, jit.Regs()[2], 1, "glGetShaderiv");
        if (host.HasFailed()) return;
        glGetShaderiv(jit.Regs()[0], static_cast<GLenum>(jit.Regs()[1]), params);
    });

    RegisterThunk("glGetString", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const GLenum name = static_cast<GLenum>(jit.Regs()[0]);
        const GLubyte* value = glGetString(name);
#if defined(ASPHALT7_GL_TELEMETRY)
        LogGlStringOnce(name, value);
#endif
        if (name == GL_EXTENSIONS && value) {
            const std::string extensions = GuestGlExtensions(reinterpret_cast<const char*>(value));
            jit.Regs()[0] = DriverString(host, extensions.c_str());
        } else {
            jit.Regs()[0] = DriverString(host, reinterpret_cast<const char*>(value));
        }
    });

    RegisterThunk("glGetUniformLocation", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* name = GuestCString(host.GetGuestMemoryBase(), host.GetGuestMemorySize(), jit.Regs()[1]);
        if (!name) LOGE("glGetUniformLocation rejected guest string");
        jit.Regs()[0] = name ? glGetUniformLocation(jit.Regs()[0], name) : -1;
    });

    RegisterThunk("glHint", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glHint(static_cast<GLenum>(jit.Regs()[0]), static_cast<GLenum>(jit.Regs()[1]));
    });

    RegisterThunk("glLineWidth", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glLineWidth(ReadSF(jit, 0));
    });

    RegisterThunk("glLinkProgram", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        GLuint prog = jit.Regs()[0];
        glLinkProgram(prog);
#ifndef NDEBUG
        GLint linked = 0;
        glGetProgramiv(prog, GL_LINK_STATUS, &linked);
        if (!linked) {
            char log[1024];
            glGetProgramInfoLog(prog, sizeof(log), nullptr, log);
            LOGE("Program %u link failed: %s", prog, log);
        }
#endif
    });

    RegisterThunk("glPixelStorei", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glPixelStorei(static_cast<GLenum>(jit.Regs()[0]), jit.Regs()[1]);
    });

    RegisterThunk("glPolygonOffset", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glPolygonOffset(ReadSF(jit, 0), ReadSF(jit, 1));
    });

    RegisterThunk("glReadPixels", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const GLenum format = host.ReadStackWord(jit, 0);
        const GLenum type = host.ReadStackWord(jit, 1);
        const uint32_t pixels_address = host.ReadStackWord(jit, 2);
        void* pixels = const_cast<void*>(CheckedGuestPointer(host, pixels_address, "glReadPixels", true));
        if (host.HasFailed()) return;
        glReadPixels(jit.Regs()[0], jit.Regs()[1], jit.Regs()[2], jit.Regs()[3], format, type, pixels);
    });

    RegisterThunk("glRenderbufferStorage", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const GLenum target = static_cast<GLenum>(jit.Regs()[0]);
        const GLenum internalformat = static_cast<GLenum>(jit.Regs()[1]);
        const GLsizei width = GuestI32(jit.Regs()[2]);
        const GLsizei height = GuestI32(jit.Regs()[3]);
        glRenderbufferStorage(target, internalformat, width, height);
#if defined(ASPHALT7_GL_TELEMETRY)
        if (width >= 1000 || height >= 1000) {
            GLint renderbuffer = 0;
            GLint framebuffer = 0;
            glGetIntegerv(GL_RENDERBUFFER_BINDING, &renderbuffer);
            glGetIntegerv(GL_FRAMEBUFFER_BINDING, &framebuffer);
            LOGI("large_rb_alloc frame=%llu target=0x%04X internal=0x%04X "
                 "size=%dx%d renderbuffer=%d fb=%d",
                 static_cast<unsigned long long>(CurrentRenderFrameSequence()),
                 target, internalformat, width, height, renderbuffer,
                 framebuffer);
        }
#endif
    });

    RegisterThunk("glScissor", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const GLint requested_x = jit.Regs()[0];
        const GLint requested_y = jit.Regs()[1];
        const GLsizei requested_w = jit.Regs()[2];
        const GLsizei requested_h = jit.Regs()[3];
        RememberGuestFramebufferRectangle(false, requested_x, requested_y,
                                           requested_w, requested_h);
        GLint x = requested_x, y = requested_y;
        GLsizei w = requested_w, h = requested_h;
        if (x == 0 && y == 0 && w == 1920 && h == 1080) {
            GLint host_x = x;
            GLint host_y = y;
            GLsizei host_w = w;
            GLsizei host_h = h;
            GLint framebuffer = 0;
            glGetIntegerv(GL_FRAMEBUFFER_BINDING, &framebuffer);
            if (GetHostDefaultFramebufferViewport(host_x, host_y, host_w,
                                                  host_h)) {
                // Presentation geometry belongs exclusively to framebuffer 0.
                // Off-screen passes retain the guest's fixed 16:9 rectangle;
                // glBindFramebuffer(0) restores the presentation rectangle.
                if (framebuffer == 0) {
                    x = host_x;
                    y = host_y;
                    w = host_w;
                    h = host_h;
                }
            }
        }
        glScissor(x, y, w, h);
#if defined(ASPHALT7_GL_TELEMETRY)
        const uint32_t sequence = g_logged_viewports.fetch_add(
            1, std::memory_order_relaxed);
        if (sequence < 8192) {
            GLint framebuffer = 0;
            glGetIntegerv(GL_FRAMEBUFFER_BINDING, &framebuffer);
            LOGI("scissor #%u frame=%llu requested=%d,%d,%d,%d applied=%d,%d,%d,%d "
                 "fb=%d",
                 sequence,
                 static_cast<unsigned long long>(CurrentRenderFrameSequence()),
                 requested_x, requested_y, requested_w, requested_h, x, y, w, h,
                 framebuffer);
        }
#endif
        TraceHostDefaultFramebufferState("glScissor");
    });

    RegisterThunk("glShaderSource", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const GLuint shader = jit.Regs()[0];
        const GLsizei count = GuestI32(jit.Regs()[1]);
        if (count < 0) {
            host.Fail("negative glShaderSource count");
            return;
        }
        const uint32_t* addresses = CheckedGuestArray<uint32_t>(
            host, jit.Regs()[2], static_cast<uint64_t>(count), "glShaderSource");
        const GLint* lengths = OptionalGuestArray<GLint>(
            host, jit.Regs()[3], static_cast<uint64_t>(count), "glShaderSource");
        if (host.HasFailed()) return;

        std::vector<const GLchar*> strings(static_cast<size_t>(count));
        for (GLsizei i = 0; i < count; ++i) {
            const uint32_t address = addresses[i];
            if (lengths && lengths[i] >= 0) {
                const size_t length = static_cast<size_t>(lengths[i]);
                if (!address && length) {
                    host.Fail("null glShaderSource string");
                    return;
                }
                const void* value = address
                    ? GuestSpan(host.GetGuestMemoryBase(), host.GetGuestMemorySize(), address, length)
                    : nullptr;
                if (length && !value) {
                    host.Fail("invalid glShaderSource string range");
                    return;
                }
                strings[static_cast<size_t>(i)] = static_cast<const GLchar*>(value);
            } else {
                strings[static_cast<size_t>(i)] = GuestCString(
                    host.GetGuestMemoryBase(), host.GetGuestMemorySize(), address);
                if (!strings[static_cast<size_t>(i)]) {
                    host.Fail("invalid or unterminated glShaderSource string");
                    return;
                }
            }
        }
        const bool disable_road_reflections = !GraphicsRoadReflectionsEnabled();
        if (disable_road_reflections) {
            const std::string rewritten = RewriteGraphicsShaderSource(
                strings, lengths, disable_road_reflections);
            if (rewritten.size() > static_cast<size_t>(std::numeric_limits<GLint>::max())) {
                host.Fail("rewritten glShaderSource exceeds GLint length");
                return;
            }
            const GLchar* pointer = rewritten.c_str();
            const GLint length = static_cast<GLint>(rewritten.size());
            glShaderSource(shader, 1, &pointer, &length);
        } else {
            glShaderSource(shader, count, strings.data(), lengths);
        }
    });

    RegisterThunk("glTexImage2D", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const GLenum target = jit.Regs()[0];
        const GLint level = static_cast<GLint>(static_cast<int32_t>(jit.Regs()[1]));
        const GLint internalformat = static_cast<GLint>(static_cast<int32_t>(jit.Regs()[2]));
        const GLsizei width = GuestI32(jit.Regs()[3]);
        const GLsizei height = GuestI32(host.ReadStackWord(jit, 0));
        const GLint border = static_cast<GLint>(static_cast<int32_t>(host.ReadStackWord(jit, 1)));
        const GLenum format = host.ReadStackWord(jit, 2);
        const GLenum type = host.ReadStackWord(jit, 3);
        const uint32_t pixels_address = host.ReadStackWord(jit, 4);
        const void* pixels = pixels_address < 0x10000
            ? reinterpret_cast<const void*>(static_cast<uintptr_t>(pixels_address))
            : CheckedGuestPointer(host, pixels_address, "glTexImage2D", true);
        if (host.HasFailed()) return;
        glTexImage2D(target, level, internalformat, width, height, border, format, type, pixels);
#if defined(ASPHALT7_GL_TELEMETRY)
        TraceLargeTextureAllocation(target, level, internalformat, width, height,
                                     format, type);
        const uint32_t sequence = g_logged_uncompressed_uploads.fetch_add(
            1, std::memory_order_relaxed);
        if (sequence < 128) {
            LOGI("tex_upload #%u target=0x%04X level=%d internal=0x%04X size=%dx%d "
                 "format=0x%04X type=0x%04X pixels=%s", sequence, target, level,
                 internalformat, width, height, format, type,
                 pixels ? "data" : "null");
        }
#endif
    });

    RegisterThunk("glTexParameterf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glTexParameterf(jit.Regs()[0], jit.Regs()[1], ReadSF(jit, 2));
    });

    RegisterThunk("glTexParameteri", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glTexParameteri(jit.Regs()[0], jit.Regs()[1], jit.Regs()[2]);
    });

    RegisterThunk("glUniform1f", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glUniform1f(jit.Regs()[0], ReadSF(jit, 1));
    });

    RegisterThunk("glUniform1i", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glUniform1i(jit.Regs()[0], jit.Regs()[1]);
    });

    RegisterThunk("glUniform2f", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glUniform2f(jit.Regs()[0], ReadSF(jit, 1), ReadSF(jit, 2));
    });

    RegisterThunk("glUniform3f", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glUniform3f(jit.Regs()[0], ReadSF(jit, 1),
                    ReadSF(jit, 2), ReadSF(jit, 3));
    });

    RegisterThunk("glUniform3fv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const GLint location = static_cast<GLint>(static_cast<int32_t>(jit.Regs()[0]));
        const GLsizei count = GuestI32(jit.Regs()[1]);
        const GLfloat* value = count > 0
            ? CheckedGuestArray<GLfloat>(host, jit.Regs()[2], static_cast<uint64_t>(count) * 3, "glUniform3fv")
            : nullptr;
        if (host.HasFailed()) return;
        glUniform3fv(location, count, value);
    });

    RegisterThunk("glUniform4f", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        Arm32CallArgs args(jit, host);
        const GLint location = args.I32();
        const GLfloat x = args.F32(), y = args.F32(), z = args.F32(), w = args.F32();
        glUniform4f(location, x, y, z, w);
    });

    RegisterThunk("glUniform4fv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const GLint location = static_cast<GLint>(static_cast<int32_t>(jit.Regs()[0]));
        const GLsizei count = GuestI32(jit.Regs()[1]);
        const GLfloat* value = count > 0
            ? CheckedGuestArray<GLfloat>(host, jit.Regs()[2], static_cast<uint64_t>(count) * 4, "glUniform4fv")
            : nullptr;
        if (host.HasFailed()) return;
        glUniform4fv(location, count, value);
    });

    RegisterThunk("glUniformMatrix3fv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const GLint location = static_cast<GLint>(static_cast<int32_t>(jit.Regs()[0]));
        const GLsizei count = GuestI32(jit.Regs()[1]);
        const GLboolean transpose = static_cast<GLboolean>(jit.Regs()[2]);
        const GLfloat* value = count > 0
            ? CheckedGuestArray<GLfloat>(host, jit.Regs()[3], static_cast<uint64_t>(count) * 9, "glUniformMatrix3fv")
            : nullptr;
        if (host.HasFailed()) return;
        glUniformMatrix3fv(location, count, transpose, value);
    });

    RegisterThunk("glUniformMatrix4fv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const GLint location = static_cast<GLint>(static_cast<int32_t>(jit.Regs()[0]));
        const GLsizei count = GuestI32(jit.Regs()[1]);
        const GLboolean transpose = static_cast<GLboolean>(jit.Regs()[2]);
        const GLfloat* value = count > 0
            ? CheckedGuestArray<GLfloat>(host, jit.Regs()[3], static_cast<uint64_t>(count) * 16, "glUniformMatrix4fv")
            : nullptr;
        if (host.HasFailed()) return;
        glUniformMatrix4fv(location, count, transpose, value);
    });

    RegisterThunk("glUseProgram", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const GLuint program = jit.Regs()[0];
        glUseProgram(program);
#if defined(ASPHALT7_GL_TELEMETRY)
        const uint32_t sequence = g_logged_use_programs.fetch_add(1, std::memory_order_relaxed);
        if (sequence < 64) {
            LOGI("use_program #%u id=%u", sequence, program);
        }
#endif
    });

    RegisterThunk("glVertexAttribPointer", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const GLuint index = jit.Regs()[0];
        const GLint size = static_cast<GLint>(static_cast<int32_t>(jit.Regs()[1]));
        const GLenum type = jit.Regs()[2];
        const GLboolean normalized = static_cast<GLboolean>(jit.Regs()[3]);
        const GLsizei stride = GuestI32(host.ReadStackWord(jit, 0));
        const uint32_t pointer_address = host.ReadStackWord(jit, 1);

        t_buffer_bindings.SynchronizeContext();
        const void* pointer = t_buffer_bindings.array_buffer != 0
            ? reinterpret_cast<const void*>(static_cast<uintptr_t>(pointer_address))
            : CheckedGuestPointer(host, pointer_address, "glVertexAttribPointer", true);
        if (host.HasFailed()) return;
        glVertexAttribPointer(index, size, type, normalized, stride, pointer);
#if defined(ASPHALT7_GL_TELEMETRY)
        if (index < t_trace_vertex_attributes.size()) {
            t_trace_vertex_attributes[index] = TraceVertexAttribute{
                true, t_buffer_bindings.array_buffer == 0, pointer_address,
                size, type, stride};
        }
#endif
    });

    RegisterThunk("glViewport", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const GLint requested_x = jit.Regs()[0];
        const GLint requested_y = jit.Regs()[1];
        const GLsizei requested_w = jit.Regs()[2];
        const GLsizei requested_h = jit.Regs()[3];
        RememberGuestFramebufferRectangle(true, requested_x, requested_y,
                                           requested_w, requested_h);
        GLint x = requested_x, y = requested_y;
        GLsizei w = requested_w, h = requested_h;
        // The retained guest submits its canonical 1920x1080 viewport every
        // frame. Java's renderer publishes the authoritative window-system
        // viewport whenever its layout mode changes. Do not infer that value
        // from GL_VIEWPORT: viewport state is shared across framebuffer binds,
        // so an offscreen pass can leave an FBO-sized value behind. Never
        // remap FBO viewports; those belong to the guest's off-screen passes.
        if (x == 0 && y == 0 && w == 1920 && h == 1080) {
            GLint framebuffer = 0;
            glGetIntegerv(GL_FRAMEBUFFER_BINDING, &framebuffer);
            if (framebuffer == 0) {
                (void)GetHostDefaultFramebufferViewport(x, y, w, h);
            }
        }
        glViewport(x, y, w, h);
#if defined(ASPHALT7_GL_TELEMETRY)
        TraceHostDefaultFramebufferState("glViewport");
        const uint32_t sequence = g_logged_viewports.fetch_add(1, std::memory_order_relaxed);
        if (sequence < 8192) {
            GLint framebuffer = 0;
            glGetIntegerv(GL_FRAMEBUFFER_BINDING, &framebuffer);
            LOGI("viewport #%u frame=%llu requested=%d,%d,%d,%d applied=%d,%d,%d,%d "
                 "fb=%d",
                 sequence,
                 static_cast<unsigned long long>(CurrentRenderFrameSequence()),
                 requested_x, requested_y, requested_w, requested_h, x, y, w, h,
                 framebuffer);
        }
#endif
    });

    RegisterThunk("glBufferSubData", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const GLenum target = static_cast<GLenum>(jit.Regs()[0]);
        const GLintptr offset = static_cast<GLintptr>(static_cast<int32_t>(jit.Regs()[1]));
        const GLsizeiptr size = static_cast<GLsizeiptr>(static_cast<int32_t>(jit.Regs()[2]));
        if (size < 0) {
            host.Fail("negative glBufferSubData size");
            return;
        }
        const void* data = size > 0
            ? CheckedGuestArray<uint8_t>(host, jit.Regs()[3], static_cast<uint64_t>(size),
                                         "glBufferSubData")
            : nullptr;
        if (host.HasFailed()) return;
        glBufferSubData(target, offset, size, data);
    });

    RegisterThunk("glTexSubImage2D", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const GLenum target = static_cast<GLenum>(jit.Regs()[0]);
        const GLint level = static_cast<GLint>(static_cast<int32_t>(jit.Regs()[1]));
        const GLint xoffset = static_cast<GLint>(static_cast<int32_t>(jit.Regs()[2]));
        const GLint yoffset = static_cast<GLint>(static_cast<int32_t>(jit.Regs()[3]));
        const GLsizei width = GuestI32(host.ReadStackWord(jit, 0));
        const GLsizei height = GuestI32(host.ReadStackWord(jit, 1));
        const GLenum format = static_cast<GLenum>(host.ReadStackWord(jit, 2));
        const GLenum type = static_cast<GLenum>(host.ReadStackWord(jit, 3));
        const uint32_t pixels_address = host.ReadStackWord(jit, 4);
        const void* pixels = pixels_address
            ? CheckedGuestPointer(host, pixels_address, "glTexSubImage2D", true)
            : nullptr;
        if (host.HasFailed()) return;
        glTexSubImage2D(target, level, xoffset, yoffset, width, height, format, type, pixels);
#if defined(ASPHALT7_GL_TELEMETRY)
        const uint32_t sequence = g_logged_uncompressed_uploads.fetch_add(
            1, std::memory_order_relaxed);
        if (sequence < 128) {
            LOGI("tex_sub_upload #%u target=0x%04X level=%d offset=%d,%d size=%dx%d "
                 "format=0x%04X type=0x%04X pixels=%s", sequence, target, level,
                 xoffset, yoffset, width, height, format, type,
                 pixels ? "data" : "null");
        }
#endif
    });

    RegisterThunk("glTexImage3DOES", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        using Function = void (*)(GLenum, GLint, GLenum, GLsizei, GLsizei, GLsizei, GLint,
                                  GLenum, GLenum, const void*);
        const Function function = ExtensionProc<Function>("glTexImage3DOES");
        if (!function) {
            LOGE("glTexImage3DOES is unavailable on the current GLES implementation");
            return;
        }
        const GLenum target = static_cast<GLenum>(jit.Regs()[0]);
        const GLint level = static_cast<GLint>(static_cast<int32_t>(jit.Regs()[1]));
        const GLenum internalformat = static_cast<GLenum>(jit.Regs()[2]);
        const GLsizei width = GuestI32(jit.Regs()[3]);
        const GLsizei height = GuestI32(host.ReadStackWord(jit, 0));
        const GLsizei depth = GuestI32(host.ReadStackWord(jit, 1));
        const GLint border = static_cast<GLint>(static_cast<int32_t>(host.ReadStackWord(jit, 2)));
        const GLenum format = static_cast<GLenum>(host.ReadStackWord(jit, 3));
        const GLenum type = static_cast<GLenum>(host.ReadStackWord(jit, 4));
        const uint32_t pixels_address = host.ReadStackWord(jit, 5);
        const void* pixels = pixels_address
            ? CheckedGuestPointer(host, pixels_address, "glTexImage3DOES", true)
            : nullptr;
        if (host.HasFailed()) return;
        function(target, level, internalformat, width, height, depth, border, format, type, pixels);
    });

    RegisterThunk("glTexSubImage3DOES", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        using Function = PFNGLTEXSUBIMAGE3DOESPROC;
        const Function function = ExtensionProc<Function>("glTexSubImage3DOES");
        if (!function) {
            LOGE("glTexSubImage3DOES is unavailable on the current GLES implementation");
            return;
        }
        const GLenum target = static_cast<GLenum>(jit.Regs()[0]);
        const GLint level = static_cast<GLint>(static_cast<int32_t>(jit.Regs()[1]));
        const GLint xoffset = static_cast<GLint>(static_cast<int32_t>(jit.Regs()[2]));
        const GLint yoffset = static_cast<GLint>(static_cast<int32_t>(jit.Regs()[3]));
        const GLint zoffset = static_cast<GLint>(static_cast<int32_t>(host.ReadStackWord(jit, 0)));
        const GLsizei width = GuestI32(host.ReadStackWord(jit, 1));
        const GLsizei height = GuestI32(host.ReadStackWord(jit, 2));
        const GLsizei depth = GuestI32(host.ReadStackWord(jit, 3));
        const GLenum format = static_cast<GLenum>(host.ReadStackWord(jit, 4));
        const GLenum type = static_cast<GLenum>(host.ReadStackWord(jit, 5));
        const uint32_t pixels_address = host.ReadStackWord(jit, 6);
        const void* pixels = pixels_address
            ? CheckedGuestPointer(host, pixels_address, "glTexSubImage3DOES", true)
            : nullptr;
        if (host.HasFailed()) return;
        function(target, level, xoffset, yoffset, zoffset, width, height, depth, format, type, pixels);
    });

    RegisterThunk("glCompressedTexImage3DOES", [](Dynarmic::A32::Jit& jit,
                                                     DynarmicHost& host) {
        using Function = PFNGLCOMPRESSEDTEXIMAGE3DOESPROC;
        const Function function = ExtensionProc<Function>("glCompressedTexImage3DOES");
        if (!function) {
            LOGE("glCompressedTexImage3DOES is unavailable on the current GLES implementation");
            return;
        }
        const GLenum target = static_cast<GLenum>(jit.Regs()[0]);
        const GLint level = static_cast<GLint>(static_cast<int32_t>(jit.Regs()[1]));
        const GLenum internalformat = static_cast<GLenum>(jit.Regs()[2]);
        const GLsizei width = GuestI32(jit.Regs()[3]);
        const GLsizei height = GuestI32(host.ReadStackWord(jit, 0));
        const GLsizei depth = GuestI32(host.ReadStackWord(jit, 1));
        const GLint border = static_cast<GLint>(static_cast<int32_t>(host.ReadStackWord(jit, 2)));
        const GLsizei image_size = GuestI32(host.ReadStackWord(jit, 3));
        const uint32_t data_address = host.ReadStackWord(jit, 4);
        if (image_size < 0) {
            host.Fail("negative glCompressedTexImage3DOES image size");
            return;
        }
        const void* data = image_size > 0
            ? CheckedGuestArray<uint8_t>(host, data_address, static_cast<uint64_t>(image_size),
                                         "glCompressedTexImage3DOES")
            : nullptr;
        if (host.HasFailed()) return;
        function(target, level, internalformat, width, height, depth, border, image_size, data);
    });

    RegisterThunk("glCompressedTexSubImage3DOES", [](Dynarmic::A32::Jit& jit,
                                                       DynarmicHost& host) {
        using Function = void (*)(GLenum, GLint, GLint, GLint, GLint, GLsizei, GLsizei, GLsizei,
                                  GLenum, GLsizei, const void*);
        const Function function = ExtensionProc<Function>("glCompressedTexSubImage3DOES");
        if (!function) {
            LOGE("glCompressedTexSubImage3DOES is unavailable on the current GLES implementation");
            return;
        }
        const GLenum target = static_cast<GLenum>(jit.Regs()[0]);
        const GLint level = static_cast<GLint>(static_cast<int32_t>(jit.Regs()[1]));
        const GLint xoffset = static_cast<GLint>(static_cast<int32_t>(jit.Regs()[2]));
        const GLint yoffset = static_cast<GLint>(static_cast<int32_t>(jit.Regs()[3]));
        const GLint zoffset = static_cast<GLint>(static_cast<int32_t>(host.ReadStackWord(jit, 0)));
        const GLsizei width = GuestI32(host.ReadStackWord(jit, 1));
        const GLsizei height = GuestI32(host.ReadStackWord(jit, 2));
        const GLsizei depth = GuestI32(host.ReadStackWord(jit, 3));
        const GLenum format = static_cast<GLenum>(host.ReadStackWord(jit, 4));
        const GLsizei image_size = GuestI32(host.ReadStackWord(jit, 5));
        const uint32_t data_address = host.ReadStackWord(jit, 6);
        if (image_size < 0) {
            host.Fail("negative glCompressedTexSubImage3DOES image size");
            return;
        }
        const void* data = image_size > 0
            ? CheckedGuestArray<uint8_t>(host, data_address, static_cast<uint64_t>(image_size),
                                         "glCompressedTexSubImage3DOES")
            : nullptr;
        if (host.HasFailed()) return;
        function(target, level, xoffset, yoffset, zoffset, width, height, depth, format,
                 image_size, data);
    });

    RegisterThunk("glMapBufferOES", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const GLenum target = static_cast<GLenum>(jit.Regs()[0]);
        const GLenum access = static_cast<GLenum>(jit.Regs()[1]);
        const PFNGLMAPBUFFERRANGEEXTPROC function = ReadableBufferMapFunction();
        const PFNGLUNMAPBUFFEROESPROC unmap = HostBufferUnmapFunction();
        jit.Regs()[0] = 0;
        if (!function || !unmap) {
            LOGE("glMapBufferOES has no readable host mapping on the current GLES implementation");
            return;
        }
        if (access != GL_WRITE_ONLY_OES) {
            // Let the OES entry point report its own INVALID_ENUM for an
            // invalid guest access; no bytes from this mapping are read.
            if (const auto legacy = ExtensionProc<PFNGLMAPBUFFEROESPROC>("glMapBufferOES"))
                (void)legacy(target, access);
            return;
        }
        GLint buffer_size = 0;
        glGetBufferParameteriv(target, GL_BUFFER_SIZE, &buffer_size);
        if (buffer_size <= 0 || static_cast<uint64_t>(buffer_size) > 256u * 1024u * 1024u) {
            LOGE("glMapBufferOES rejected buffer size %d", buffer_size);
            return;
        }
        const auto key = CurrentBufferMappingKey(target);
        void* host_pointer = function(target, 0, buffer_size, GL_MAP_READ_BIT_EXT | GL_MAP_WRITE_BIT_EXT);
        if (!host_pointer) return;
        const size_t size = static_cast<size_t>(buffer_size);
        const uint32_t guest_address = host.GuestAlloc(size, 4);
        if (!guest_address) {
            LOGE("glMapBufferOES could not allocate guest staging memory");
            unmap(target);
            return;
        }
        memcpy(host.GetGuestMemoryBase() + guest_address, host_pointer, size);
        {
            std::lock_guard lock(g_mapped_buffers_mutex);
            g_mapped_buffers.emplace(key, MappedBufferShadow{host_pointer, guest_address, size});
        }
        jit.Regs()[0] = guest_address;
    });

    RegisterThunk("glUnmapBufferOES", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const GLenum target = static_cast<GLenum>(jit.Regs()[0]);
        const PFNGLUNMAPBUFFEROESPROC function = HostBufferUnmapFunction();
        if (!function) { jit.Regs()[0] = GL_FALSE; return; }
        const auto key = CurrentBufferMappingKey(target);
        void* host_pointer = CurrentHostBufferMapPointer(target);
        MappedBufferShadow mapping;
        {
            std::lock_guard lock(g_mapped_buffers_mutex);
            const auto found = FindMappedBufferShadow(key, host_pointer);
            if (found != g_mapped_buffers.end()) {
                mapping = found->second;
                g_mapped_buffers.erase(found);
            }
        }
        if (mapping.guest_address) {
            // A shared context can replace the store while this staging copy
            // survives. Only write back to a mapping the driver still owns.
            if (host_pointer && mapping.host_pointer == host_pointer)
                memcpy(host_pointer, host.GetGuestMemoryBase() + mapping.guest_address, mapping.size);
            host.GuestFree(mapping.guest_address);
        }
        jit.Regs()[0] = static_cast<uint32_t>(function(target));
    });

    RegisterThunk("glGetBufferParameteriv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const GLenum target = static_cast<GLenum>(jit.Regs()[0]);
        const GLenum pname = static_cast<GLenum>(jit.Regs()[1]);
        GLint* params = CheckedGuestArray<GLint>(host, jit.Regs()[2], 1, "glGetBufferParameteriv");
        if (host.HasFailed()) return;
        // The guest's OES API accepts only WRITE_ONLY, even though its host
        // backing uses READ|WRITE to initialize the staging memory safely.
        if (pname == GL_BUFFER_ACCESS_OES && CurrentBufferMappingKey(target).second) {
            *params = GL_WRITE_ONLY_OES;
            return;
        }
        glGetBufferParameteriv(target, pname, params);
    });

    RegisterThunk("glGetBufferPointervOES", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const GLenum target = static_cast<GLenum>(jit.Regs()[0]);
        const GLenum pname = static_cast<GLenum>(jit.Regs()[1]);
        uint32_t* params = CheckedGuestArray<uint32_t>(host, jit.Regs()[2], 1, "glGetBufferPointervOES");
        if (host.HasFailed()) return;
        const HostBufferPointerFunction function = BufferPointerFunction();
        void* pointer = nullptr;
        if (function) function(target, pname, &pointer);
        if (pname != GL_BUFFER_MAP_POINTER_OES) return;
        const auto key = CurrentBufferMappingKey(target);
        std::lock_guard lock(g_mapped_buffers_mutex);
        const auto found = FindMappedBufferShadow(key, pointer);
        *params = pointer && found != g_mapped_buffers.end() &&
                  found->second.host_pointer == pointer ? found->second.guest_address : 0;
    });

    RegisterGles2CoreThunks(*this);

    RegisterThunk("eglGetDisplay", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        if (jit.Regs()[0] != 0) {
            LOGE("eglGetDisplay: unsupported non-default native display");
            t_egl_error = EGL_BAD_PARAMETER;
            jit.Regs()[0] = 0;
            return;
        }
        EGLDisplay display = eglGetDisplay(EGL_DEFAULT_DISPLAY);
        jit.Regs()[0] = 0;
        if (display == EGL_NO_DISPLAY) return;
        std::lock_guard<std::mutex> lock(g_display_mutex);
        auto found = std::find(g_displays.begin(), g_displays.end(), display);
        if (found == g_displays.end()) {
            if (g_displays.size() == UINT32_MAX) {
                t_egl_error = EGL_BAD_ALLOC;
                return;
            }
            g_displays.push_back(display);
            jit.Regs()[0] = static_cast<uint32_t>(g_displays.size());
        } else {
            jit.Regs()[0] = static_cast<uint32_t>(found - g_displays.begin()) + 1;
        }
    });
    RegisterThunk("eglQueryString", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        EGLDisplay display = EGL_NO_DISPLAY;
        const uint32_t handle = jit.Regs()[0];
        if (handle) {
            std::lock_guard<std::mutex> lock(g_display_mutex);
            if (handle > g_displays.size()) {
                t_egl_error = EGL_BAD_DISPLAY;
                jit.Regs()[0] = 0;
                return;
            }
            display = g_displays[handle - 1];
        }
        const char* value = eglQueryString(display, static_cast<EGLint>(jit.Regs()[1]));
        jit.Regs()[0] = DriverString(host, value);
    });
    RegisterThunk("eglGetError", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        if (t_egl_error != EGL_SUCCESS) {
            jit.Regs()[0] = t_egl_error;
            t_egl_error = EGL_SUCCESS;
        } else {
            jit.Regs()[0] = eglGetError();
        }
    });
    // nvGetSystemCapabilities checks both pointers and a nonzero frequency before use.
    RegisterThunk("eglGetSystemTimeFrequencyNV", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static auto function = reinterpret_cast<uint64_t (*)()>(eglGetProcAddress("eglGetSystemTimeFrequencyNV"));
        const uint64_t value = function ? function() : 0;
        jit.Regs()[0] = static_cast<uint32_t>(value);
        jit.Regs()[1] = static_cast<uint32_t>(value >> 32);
    });
    RegisterThunk("eglGetSystemTimeNV", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static auto function = reinterpret_cast<uint64_t (*)()>(eglGetProcAddress("eglGetSystemTimeNV"));
        const uint64_t value = function ? function() : 0;
        jit.Regs()[0] = static_cast<uint32_t>(value);
        jit.Regs()[1] = static_cast<uint32_t>(value >> 32);
    });
    RegisterThunk("eglGetProcAddress", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* name = GuestCString(host.GetGuestMemoryBase(), host.GetGuestMemorySize(), jit.Regs()[0]);
        jit.Regs()[0] = 0;
        if (!name || (strncmp(name, "gl", 2) && strncmp(name, "egl", 3))) return;
        if (!eglGetProcAddress(name)) return;
        jit.Regs()[0] = host.GetThunkManager().FindRegisteredSymbol(name);
        if (!jit.Regs()[0]) LOGE("eglGetProcAddress: no guest provider for %s", name);
    });
}
