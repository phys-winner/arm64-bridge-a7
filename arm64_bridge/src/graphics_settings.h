// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <jni.h>
#include <cstdint>
class DynarmicHost;

// Snapshot preferences once, before any guest constructors or render threads.
bool InitializeGraphicsSettings(JNIEnv* env);
bool RegisterGraphicsSettings(DynarmicHost& host);
bool PatchGraphicsSettings(DynarmicHost& host);
bool GraphicsAntialiasingEnabled();
bool GraphicsRoadReflectionsEnabled();
