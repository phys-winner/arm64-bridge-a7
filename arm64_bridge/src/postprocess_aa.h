// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

// Run immediately before eglSwapBuffers on the current EGL render thread,
// after the full physical presentation viewport is restored. Returns false
// if framebuffer 0 cannot be processed.
// The pass restores every GL state it changes and leaves GL errors observable.
bool ApplyPostprocessAA();
