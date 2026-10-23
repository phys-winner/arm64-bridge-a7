// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

class DynarmicHost;
bool RegisterOfflineAcademy(DynarmicHost& host, const std::string& files_dir);
bool PatchOfflineAcademy(DynarmicHost& host);
