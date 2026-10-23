// SPDX-License-Identifier: GPL-3.0-or-later
#include "postprocess_aa.h"

#include <EGL/egl.h>
#include <GLES2/gl2.h>
#include <android/log.h>
#include <array>
#include <cstdint>

namespace {

#if defined(ASPHALT7_FINAL_SILENT)
#define AA_LOG(...) ((void)0)
#else
#define AA_LOG(...) __android_log_print(ANDROID_LOG_ERROR, "Arm32Bridge_AA", __VA_ARGS__)
#endif

constexpr char kVertexShader[] = R"(
attribute highp vec2 a7_aa_position;
varying highp vec2 a7_aa_uv;
void main() {
    a7_aa_uv = a7_aa_position * 0.5 + 0.5;
    gl_Position = vec4(a7_aa_position, 0.0, 1.0);
}
)";

// FXAA quality pass: 3x3 edge orientation, endpoint search and normal shift.
// Subpixel filtering is capped at half a texel to retain thin car details.
// Algorithm: https://developer.download.nvidia.com/assets/gamedev/files/sdk/11/FXAA_WhitePaper.pdf
constexpr char kFragmentShader[] = R"(
precision highp float;
uniform lowp sampler2D a7_aa_source;
uniform highp vec2 a7_aa_inverse_size;
varying highp vec2 a7_aa_uv;

float lumaAt(vec2 uv) {
    return dot(texture2D(a7_aa_source, uv).rgb, vec3(0.299, 0.587, 0.114));
}

float searchDistance(int index) {
    if (index == 0) return 1.0;
    if (index == 1) return 2.5;
    if (index == 2) return 4.5;
    if (index == 3) return 6.5;
    if (index == 4) return 8.5;
    if (index == 5) return 10.5;
    return 14.5;
}

void main() {
    vec2 uv = a7_aa_uv;
    vec2 texel = a7_aa_inverse_size;
    vec4 center = texture2D(a7_aa_source, uv);
    float m = dot(center.rgb, vec3(0.299, 0.587, 0.114));
    float n = lumaAt(uv + vec2(0.0, -texel.y));
    float s = lumaAt(uv + vec2(0.0,  texel.y));
    float w = lumaAt(uv + vec2(-texel.x, 0.0));
    float e = lumaAt(uv + vec2( texel.x, 0.0));
    float low = min(m, min(min(n, s), min(w, e)));
    float high = max(m, max(max(n, s), max(w, e)));
    float range = high - low;
    if (range < max(1.0 / 32.0, high / 8.0)) {
        gl_FragColor = center;
        return;
    }
    float nw = lumaAt(uv + vec2(-texel.x, -texel.y));
    float ne = lumaAt(uv + vec2( texel.x, -texel.y));
    float sw = lumaAt(uv + vec2(-texel.x,  texel.y));
    float se = lumaAt(uv + vec2( texel.x,  texel.y));
    float horizontal = abs(nw + sw - 2.0 * w) + 2.0 * abs(n + s - 2.0 * m) + abs(ne + se - 2.0 * e);
    float vertical = abs(sw + se - 2.0 * s) + 2.0 * abs(w + e - 2.0 * m) + abs(nw + ne - 2.0 * n);
    bool horizontalEdge = horizontal >= vertical;
    float negativeGradient = (horizontalEdge ? n : w) - m;
    float positiveGradient = (horizontalEdge ? s : e) - m;
    float normalSign = abs(positiveGradient) >= abs(negativeGradient) ? 1.0 : -1.0;
    float gradient = normalSign > 0.0 ? positiveGradient : negativeGradient;
    vec2 normal = horizontalEdge ? vec2(0.0, normalSign * texel.y) : vec2(normalSign * texel.x, 0.0);
    vec2 tangent = horizontalEdge ? vec2(texel.x, 0.0) : vec2(0.0, texel.y);
    vec2 boundary = uv + normal * 0.5;
    float boundaryLuma = m + gradient * 0.5;
    float stopContrast = abs(gradient) * 0.25;
    float negativeDistance = 22.5, positiveDistance = 22.5;
    bool foundNegative = false, foundPositive = false;
    bool goodNegative = false, goodPositive = false;
    for (int index = 0; index < 7; ++index) {
        float distance = searchDistance(index);
        if (!foundNegative) {
            float contrast = lumaAt(boundary - tangent * distance) - boundaryLuma;
            if (abs(contrast) >= stopContrast) {
                foundNegative = true;
                negativeDistance = distance;
                goodNegative = contrast * gradient > 0.0;
            }
        }
        if (!foundPositive) {
            float contrast = lumaAt(boundary + tangent * distance) - boundaryLuma;
            if (abs(contrast) >= stopContrast) {
                foundPositive = true;
                positiveDistance = distance;
                goodPositive = contrast * gradient > 0.0;
            }
        }
        if (foundNegative && foundPositive) break;
    }
    float edgeShift = 0.5 - min(negativeDistance, positiveDistance) / (negativeDistance + positiveDistance);
    bool goodSpan = negativeDistance < positiveDistance ? goodNegative : goodPositive;
    if (!goodSpan) edgeShift = 0.0;
    float average = (2.0 * (n + s + w + e) + nw + ne + sw + se) / 12.0;
    float subpixel = clamp(abs(average - m) / range, 0.0, 1.0);
    subpixel = subpixel * subpixel * (3.0 - 2.0 * subpixel);
    subpixel = min(0.5, subpixel * subpixel * 0.75);
    vec3 filtered = texture2D(a7_aa_source, uv + normal * max(edgeShift, subpixel)).rgb;
    gl_FragColor = vec4(filtered, center.a);
}
)";

constexpr std::array<GLenum, 9> kDisabled = {
    GL_BLEND, GL_CULL_FACE, GL_DEPTH_TEST, GL_STENCIL_TEST, GL_SCISSOR_TEST,
    GL_DITHER, GL_POLYGON_OFFSET_FILL, GL_SAMPLE_ALPHA_TO_COVERAGE, GL_SAMPLE_COVERAGE,
};

struct SavedState {
    GLint program = 0, active_texture = 0, texture0 = 0, array_buffer = 0;
    GLint enabled = 0, size = 0, type = 0, normalized = 0, stride = 0, attrib_buffer = 0;
    std::array<GLint, 4> viewport{};
    std::array<GLfloat, 4> current{};
    std::array<GLboolean, 4> color_mask{};
    std::array<GLboolean, kDisabled.size()> capabilities{};
    void* pointer = nullptr;

    SavedState() {
        glGetIntegerv(GL_CURRENT_PROGRAM, &program);
        glGetIntegerv(GL_ACTIVE_TEXTURE, &active_texture);
        glActiveTexture(GL_TEXTURE0);
        glGetIntegerv(GL_TEXTURE_BINDING_2D, &texture0);
        glGetIntegerv(GL_ARRAY_BUFFER_BINDING, &array_buffer);
        glGetIntegerv(GL_VIEWPORT, viewport.data());
        glGetBooleanv(GL_COLOR_WRITEMASK, color_mask.data());
        glGetVertexAttribiv(0, GL_VERTEX_ATTRIB_ARRAY_ENABLED, &enabled);
        glGetVertexAttribiv(0, GL_VERTEX_ATTRIB_ARRAY_SIZE, &size);
        glGetVertexAttribiv(0, GL_VERTEX_ATTRIB_ARRAY_TYPE, &type);
        glGetVertexAttribiv(0, GL_VERTEX_ATTRIB_ARRAY_NORMALIZED, &normalized);
        glGetVertexAttribiv(0, GL_VERTEX_ATTRIB_ARRAY_STRIDE, &stride);
        glGetVertexAttribiv(0, GL_VERTEX_ATTRIB_ARRAY_BUFFER_BINDING, &attrib_buffer);
        glGetVertexAttribPointerv(0, GL_VERTEX_ATTRIB_ARRAY_POINTER, &pointer);
        glGetVertexAttribfv(0, GL_CURRENT_VERTEX_ATTRIB, current.data());
        for (size_t i = 0; i < kDisabled.size(); ++i) capabilities[i] = glIsEnabled(kDisabled[i]);
    }

    ~SavedState() {
        glUseProgram(static_cast<GLuint>(program));
        glBindTexture(GL_TEXTURE_2D, static_cast<GLuint>(texture0));
        glActiveTexture(static_cast<GLenum>(active_texture));
        glBindBuffer(GL_ARRAY_BUFFER, static_cast<GLuint>(attrib_buffer));
        glVertexAttribPointer(0, size, static_cast<GLenum>(type), static_cast<GLboolean>(normalized), stride, pointer);
        if (enabled) glEnableVertexAttribArray(0);
        else glDisableVertexAttribArray(0);
        glVertexAttrib4fv(0, current.data());
        glBindBuffer(GL_ARRAY_BUFFER, static_cast<GLuint>(array_buffer));
        glViewport(viewport[0], viewport[1], viewport[2], viewport[3]);
        glColorMask(color_mask[0], color_mask[1], color_mask[2], color_mask[3]);
        for (size_t i = 0; i < kDisabled.size(); ++i) {
            if (capabilities[i]) glEnable(kDisabled[i]);
            else glDisable(kDisabled[i]);
        }
    }
};

struct Resources {
    EGLContext context = EGL_NO_CONTEXT;
    GLuint program = 0, texture = 0, buffer = 0, framebuffer = 0;
    GLint inverse_size = -1;
    GLsizei width = 0, height = 0;
    GLenum format = GL_NONE;
    GLint max_texture_size = 0;
    bool failed = false;
};

// One render context owns the pass. Destroyed contexts reclaim their objects;
// their old numeric names must never be deleted in a newly created context.
thread_local Resources resources;

GLuint Compile(GLenum type, const char* source) {
    GLuint shader = glCreateShader(type);
    if (!shader) return 0;
    glShaderSource(shader, 1, &source, nullptr);
    glCompileShader(shader);
    GLint compiled = GL_FALSE;
    glGetShaderiv(shader, GL_COMPILE_STATUS, &compiled);
    if (compiled) return shader;
    std::array<char, 512> log{};
    glGetShaderInfoLog(shader, static_cast<GLsizei>(log.size()), nullptr, log.data());
    AA_LOG("FXAA shader compilation failed: %s", log.data());
    glDeleteShader(shader);
    return 0;
}

bool CreateResources() {
    GLuint vertex = Compile(GL_VERTEX_SHADER, kVertexShader);
    GLuint fragment = Compile(GL_FRAGMENT_SHADER, kFragmentShader);
    if (vertex && fragment) {
        resources.program = glCreateProgram();
        if (resources.program) {
            glAttachShader(resources.program, vertex);
            glAttachShader(resources.program, fragment);
            glBindAttribLocation(resources.program, 0, "a7_aa_position");
            glLinkProgram(resources.program);
        }
    }
    if (vertex) glDeleteShader(vertex);
    if (fragment) glDeleteShader(fragment);
    GLint linked = GL_FALSE;
    if (resources.program) glGetProgramiv(resources.program, GL_LINK_STATUS, &linked);
    if (!linked) {
        AA_LOG("FXAA program could not be linked");
        if (resources.program) glDeleteProgram(resources.program);
        resources.program = 0;
        return false;
    }
    resources.inverse_size = glGetUniformLocation(resources.program, "a7_aa_inverse_size");
    glUseProgram(resources.program);
    glUniform1i(glGetUniformLocation(resources.program, "a7_aa_source"), 0);
    constexpr std::array<GLfloat, 6> vertices = {-1.0f, -1.0f, 3.0f, -1.0f, -1.0f, 3.0f};
    glGenBuffers(1, &resources.buffer);
    if (!resources.buffer) return false;
    glBindBuffer(GL_ARRAY_BUFFER, resources.buffer);
    glBufferData(GL_ARRAY_BUFFER, sizeof(vertices), vertices.data(), GL_STATIC_DRAW);
    GLint buffer_size = 0;
    glGetBufferParameteriv(GL_ARRAY_BUFFER, GL_BUFFER_SIZE, &buffer_size);
    glGenFramebuffers(1, &resources.framebuffer);
    glGetIntegerv(GL_MAX_TEXTURE_SIZE, &resources.max_texture_size);
    return resources.inverse_size >= 0 && resources.framebuffer &&
           buffer_size == static_cast<GLint>(sizeof(vertices));
}

bool Resize(GLsizei width, GLsizei height, GLenum format) {
    GLuint texture = 0;
    glGenTextures(1, &texture);
    if (!texture) return false;
    glBindTexture(GL_TEXTURE_2D, texture);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
    // CopyTexSubImage2D cannot add an alpha component to an RGB window buffer.
    glTexImage2D(GL_TEXTURE_2D, 0, format, width, height, 0, format, GL_UNSIGNED_BYTE, nullptr);
    // A fresh texture has no previous image to mask an allocation failure.
    // Checking completeness leaves any allocation GL error in the guest queue.
    glBindFramebuffer(GL_FRAMEBUFFER, resources.framebuffer);
    glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, texture, 0);
    const bool complete = glCheckFramebufferStatus(GL_FRAMEBUFFER) == GL_FRAMEBUFFER_COMPLETE;
    glBindFramebuffer(GL_FRAMEBUFFER, 0);
    if (!complete) {
        glDeleteTextures(1, &texture);
        AA_LOG("FXAA texture allocation failed for %d x %d", width, height);
        return false;
    }
    if (resources.texture) glDeleteTextures(1, &resources.texture);
    resources.texture = texture;
    resources.width = width;
    resources.height = height;
    resources.format = format;
    return true;
}

} // namespace

bool ApplyPostprocessAA() {
    const EGLContext context = eglGetCurrentContext();
    const EGLSurface surface = eglGetCurrentSurface(EGL_DRAW);
    if (context == EGL_NO_CONTEXT || surface == EGL_NO_SURFACE ||
        surface != eglGetCurrentSurface(EGL_READ)) {
        return false;
    }
    GLint framebuffer = 0;
    glGetIntegerv(GL_FRAMEBUFFER_BINDING, &framebuffer);
    if (framebuffer != 0) {
        return false;
    }
    GLint current_program = 0, delete_pending = GL_FALSE;
    glGetIntegerv(GL_CURRENT_PROGRAM, &current_program);
    if (current_program) glGetProgramiv(static_cast<GLuint>(current_program), GL_DELETE_STATUS, &delete_pending);
    // Rebinding a different program would finalize its deferred deletion and
    // make SavedState unable to restore the guest's current program.
    if (delete_pending) {
        return false;
    }
    std::array<GLint, 4> viewport{};
    glGetIntegerv(GL_VIEWPORT, viewport.data());
    EGLint surface_width = 0, surface_height = 0;
    const EGLDisplay display = eglGetCurrentDisplay();
    if (!eglQuerySurface(display, surface, EGL_WIDTH, &surface_width) ||
        !eglQuerySurface(display, surface, EGL_HEIGHT, &surface_height) ||
        viewport[0] < 0 || viewport[1] < 0 || viewport[2] <= 0 || viewport[3] <= 0 ||
        int64_t(viewport[0]) + viewport[2] > surface_width ||
        int64_t(viewport[1]) + viewport[3] > surface_height) {
        return false;
    }

    if (resources.context != context) resources = Resources{.context = context};
    // EGL can reuse a destroyed context's handle. The private uniform identifies
    // our linked program even if a guest object has reused the same GL name.
    if (resources.program) {
        GLint linked = GL_FALSE;
        if (glIsProgram(resources.program)) glGetProgramiv(resources.program, GL_LINK_STATUS, &linked);
        if (!linked || glGetUniformLocation(resources.program, "a7_aa_inverse_size") != resources.inverse_size) {
            resources = Resources{.context = context};
        }
    }
    if (resources.failed) {
        return false;
    }
    SavedState state;
    GLint alpha_bits = 0;
    glGetIntegerv(GL_ALPHA_BITS, &alpha_bits);
    const GLenum format = alpha_bits > 0 ? GL_RGBA : GL_RGB;
    if ((!resources.program && !CreateResources()) ||
        viewport[2] > resources.max_texture_size || viewport[3] > resources.max_texture_size ||
        ((resources.width != viewport[2] || resources.height != viewport[3] || resources.format != format) &&
         !Resize(viewport[2], viewport[3], format))) {
        resources.failed = true;
        return false;
    }
    glBindTexture(GL_TEXTURE_2D, resources.texture);
    glCopyTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, viewport[0], viewport[1], viewport[2], viewport[3]);
    for (GLenum capability : kDisabled) glDisable(capability);
    glColorMask(GL_TRUE, GL_TRUE, GL_TRUE, GL_TRUE);
    glUseProgram(resources.program);
    glUniform2f(resources.inverse_size, 1.0f / resources.width, 1.0f / resources.height);
    glBindBuffer(GL_ARRAY_BUFFER, resources.buffer);
    glVertexAttribPointer(0, 2, GL_FLOAT, GL_FALSE, 0, nullptr);
    glEnableVertexAttribArray(0);
    glDrawArrays(GL_TRIANGLES, 0, 3);
    return true;
}
