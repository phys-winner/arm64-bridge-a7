// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

// Publish the physical window-surface size used by the guest and framebuffer 0.
void PublishHostDefaultFramebufferSurfaceSize(std::int32_t physical_width,
                                              std::int32_t physical_height);

// Keep the retained guest's camera setter from reverting a wide race camera
// to the authored 16:9 aspect in the middle of a frame. Pass IEEE-754 bits.
void PublishHostGameplayAspectRatio(std::uint32_t aspect_ratio_bits,
                                    std::uint32_t camera_node);

// Keep the full-surface presentation invariant. The argument is retained for
// ABI/source compatibility with older callers and is intentionally ignored.
// Call this on the EGL render thread before restoring framebuffer-0 state.
void SetHostDefaultFramebufferWideMode(bool enabled);

// Re-apply the published window viewport after the retained guest changes EGL
// contexts. Returns without touching off-screen framebuffers or pbuffer
// surfaces, whose geometry belongs to the guest.
void RestoreHostDefaultFramebufferState();

// Finalize the render-thread presentation immediately before GLSurfaceView
// swaps. If the guest left an off-screen FBO bound on the window surface,
// return to framebuffer 0 and restore the full physical presentation rectangle.
// Returns false for guest pbuffer surfaces or an unavailable window context.
bool FinalizeHostDefaultFramebufferPresentation();

// Diagnostic-only state snapshot; compiled to a no-op in release builds.
void TraceHostDefaultFramebufferState(const char* stage);

// Restart bounded GL diagnostics at race entry, after the menu has finished.
void TraceHostGlRaceState(bool in_race);

// Skybox mesh render scope, used by the retained guest's render-call hook.
void BeginHostSkyboxDraw();
void EndHostSkyboxDraw();
