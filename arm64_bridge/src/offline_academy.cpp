// SPDX-License-Identifier: GPL-3.0-or-later
#include "offline_academy.h"
#include "academy_schedule.h"
#include "dynarmic_host.h"
#include "thunk_manager.h"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <unistd.h>

namespace {
constexpr uint32_t base = 0x40000000;
constexpr uint32_t state_addr = base + 0x140f948;
constexpr uint32_t connect_action = base + 0x14153c0;
constexpr uint32_t opening_screen = base + 0x13b3798;
constexpr uint32_t auto_action = base + 0x14153e4;
constexpr uint32_t previous_auto_action = base + 0x14153e8;
constexpr int32_t maximum_score = 86400000;

struct Record {
    uint32_t profile;
    int32_t week, track, car, score;
    char name[64];
};
struct Header {
    uint32_t magic = 0x41433741, version = 2;
    int32_t epoch = AcademySchedule::epoch;
    uint32_t count = 0;
};
static_assert(sizeof(Header) == 16 && sizeof(Record) == 84);
// ponytail: retain the latest 64 scored profile/weeks; grow only when local history needs more.
Header header;
std::array<Record, 64> records{};
DynarmicHost* host = nullptr;
std::string store_path;
uint32_t academy = 0, original_connect = 0, owned_login_name = 0;
bool session = false, race_active = false, prior_online = false;
Record pinned{};

uint32_t Call(uint32_t rva, const std::vector<uint32_t>& args = {}) {
    return host->CallGuestNested(base + rva, args);
}
int32_t State() { return int32_t(host->MemoryRead32(state_addr)); }
bool ValidScore(int32_t score) { return score > 0 && score <= maximum_score; }
int32_t KeepBest(int32_t old, int32_t score) {
    return ValidScore(score) && (!ValidScore(old) || score < old) ? score : old;
}
int32_t LatestWeek() { return AcademySchedule::WeekAt(std::time(nullptr)); }
int32_t Track(int32_t week) { return AcademySchedule::ForWeek(week).track; }
int32_t Car(int32_t week) { return AcademySchedule::ForWeek(week).car; }
bool ValidRecord(const Record& record) {
    return record.week > 0 && record.week <= AcademySchedule::maximum_week &&
           record.track == Track(record.week) && record.car == Car(record.week) && ValidScore(record.score) &&
           record.name[0] && std::memchr(record.name, 0, sizeof(record.name)) &&
           !std::strpbrk(record.name, "|\r\n");
}
void Load() {
    FILE* file = std::fopen(store_path.c_str(), "rb");
    if (!file) return;
    Header read_header{};
    std::array<Record, 64> read_records{};
    bool valid = std::fread(&read_header, sizeof(read_header), 1, file) == 1 &&
                 read_header.magic == header.magic && read_header.version == header.version &&
                 read_header.epoch == AcademySchedule::epoch &&
                 read_header.count <= records.size();
    if (valid) valid = std::fread(read_records.data(), sizeof(Record), read_header.count, file) == read_header.count &&
                       std::fgetc(file) == EOF && !std::ferror(file);
    std::fclose(file);
    if (!valid) return;
    const Header previous = header;
    header = read_header;
    for (uint32_t i = 0; i < header.count; ++i) {
        if (!ValidRecord(read_records[i])) { header = previous; return; }
        for (uint32_t j = 0; j < i; ++j)
            if (read_records[i].profile == read_records[j].profile && read_records[i].week == read_records[j].week &&
                !std::strcmp(read_records[i].name, read_records[j].name)) { header = previous; return; }
    }
    records = read_records;
}
bool Save() {
    const std::string temporary = store_path + ".tmp";
    FILE* file = std::fopen(temporary.c_str(), "wb");
    if (!file) return false;
    bool ok = std::fwrite(&header, sizeof(header), 1, file) == 1 &&
              std::fwrite(records.data(), sizeof(Record), header.count, file) == header.count;
    if (ok) ok = std::fflush(file) == 0 && ::fsync(::fileno(file)) == 0;
    if (std::fclose(file)) ok = false;
    if (ok) ok = std::rename(temporary.c_str(), store_path.c_str()) == 0;
    if (!ok) ::unlink(temporary.c_str());
    return ok;
}
Record Identity(int32_t week) {
    Record result{};
    result.week = week; result.track = Track(week); result.car = Car(week); result.score = -1;
    const uint32_t manager = Call(0x93694c);
    if (!manager) { host->Fail("Academy profile manager is unavailable"); return result; }
    result.profile = host->MemoryRead32(manager + 0x4e4b8);
    const uint32_t profile = Call(0xa00cdc, {manager, result.profile});
    const uint32_t name = profile ? Call(0xb28780, {profile}) : 0;
    if (name && uint64_t(name) + sizeof(result.name) <= host->GetGuestMemorySize()) {
        for (size_t i = 0; i + 1 < sizeof(result.name); ++i) {
            char value = char(host->MemoryRead8(name + uint32_t(i)));
            if (!value) break;
            result.name[i] = value == '|' || value == '\r' || value == '\n' ? '_' : value;
        }
        // Keep a complete final UTF-8 code point at the parser's 63-byte limit.
        size_t length = std::strlen(result.name), lead = length;
        while (lead && (uint8_t(result.name[lead - 1]) & 0xc0) == 0x80) --lead;
        if (lead && uint8_t(result.name[lead - 1]) >= 0xc0) {
            const uint8_t value = uint8_t(result.name[lead - 1]);
            const size_t width = value < 0xe0 ? 2 : value < 0xf0 ? 3 : 4;
            if (length - lead + 1 < width) result.name[lead - 1] = 0;
        }
    }
    if (!result.name[0]) std::strcpy(result.name, "Asphalt7");
    return result;
}
int32_t Best(const Record& identity) {
    for (uint32_t i = 0; i < header.count; ++i)
        if (records[i].profile == identity.profile && records[i].week == identity.week &&
            !std::strcmp(records[i].name, identity.name)) return records[i].score;
    return -1;
}
bool Earlier(const Record& a, const Record& b) {
    if (a.score != b.score) return a.score < b.score;
    if (a.profile != b.profile) return a.profile < b.profile;
    return std::strcmp(a.name, b.name) < 0;
}
uint32_t GuestText(const std::string& text) {
    const uint32_t address = host->GuestAlloc(text.size() + 1);
    if (address) std::memcpy(host->GetGuestMemoryBase() + address, text.c_str(), text.size() + 1);
    return address;
}
uint32_t Instance() {
    if (!academy) {
        academy = Call(0xd1ac38, {0xac});
        if (!academy) { host->Fail("Academy allocation failed"); return 0; }
        Call(0xb30a00, {academy});
    }
    return academy;
}
void Populate(int32_t requested_week) {
    const uint32_t object = Instance();
    if (!object || host->HasFailed()) return;
    const int32_t latest = LatestWeek(), selected = std::clamp(requested_week < 1 ? latest : requested_week, 1, latest);
    Record mine = Identity(selected), newest = Identity(latest);
    if (host->HasFailed()) return;
    if (int32_t(Call(0x982530, {Call(0x93ab40), uint32_t(mine.car)})) < 0 ||
        int32_t(Call(0xa3c6b8, {Call(0x932854), uint32_t(mine.track)})) < 0) {
        host->Fail("Academy assignment is absent from bundled car/track tables"); return;
    }
    const int32_t latest_best = Best(newest);
    newest.score = latest_best;
    int32_t latest_rank = latest_best > 0 ? 1 : -1, leader = -1;
    for (uint32_t i = 0; i < header.count; ++i) if (records[i].week == latest) {
        leader = KeepBest(leader, records[i].score);
        if (latest_best > 0 && Earlier(records[i], newest)) ++latest_rank;
    }
    const auto latest_event = AcademySchedule::ForWeek(latest), selected_event = AcademySchedule::ForWeek(selected);
    const std::array<int32_t, 8> event = {latest, latest_event.start_date,
        latest_event.end_date, newest.track, newest.car, latest_rank, leader, latest_best};
    for (size_t i = 0; i < event.size(); ++i) host->MemoryWrite32(object + 0x68 + uint32_t(i * 4), uint32_t(event[i]));
    const std::array<int32_t, 5> history = {selected, selected_event.start_date,
        selected_event.end_date, mine.track, mine.car};
    for (size_t i = 0; i < history.size(); ++i) host->MemoryWrite32(object + 0x88 + uint32_t(i * 4), uint32_t(history[i]));
    std::vector<Record> table;
    for (uint32_t i = 0; i < header.count; ++i) if (records[i].week == selected) table.push_back(records[i]);
    std::sort(table.begin(), table.end(), Earlier);
    const int32_t best = Best(mine);
    int32_t rank = -1;
    for (size_t i = 0; i < table.size(); ++i)
        if (table[i].profile == mine.profile && !std::strcmp(table[i].name, mine.name)) rank = int32_t(i + 1);
    std::string payload = table.empty() ? "n|" : "y|" + std::to_string(rank) + "|" + mine.name + "|" + std::to_string(best) + "|0|";
    for (size_t i = 0; i < std::min(table.size(), size_t(10)); ++i)
        payload += std::to_string(i + 1) + "|" + table[i].name + "|" + std::to_string(table[i].score) + "|0|";
    host->MemoryWrite32(object + 0x64, 1);
    host->MemoryWrite32(object + 0x50, host->MemoryRead32(object + 0x4c));
    const uint32_t text = GuestText(payload);
    if (!text) { host->Fail("Academy ranking payload allocation failed"); return; }
    Call(0xb3129c, {object, text});
    host->GuestFree(text);
}
void CompleteRequest(int32_t week) {
    Populate(week);
    if (host->HasFailed()) return;
    if (State() == 1) {
        host->MemoryWrite32(state_addr, 0);
        Call(0xbc60b4);
    } else Call(0xbc602c);
}
void LoginName() {
    const uint32_t login = Call(0xe43e4c);
    if (!login) { host->Fail("Academy local display identity is unavailable"); return; }
    const uint32_t previous = host->MemoryRead32(login + 0x74);
    if (previous && previous != owned_login_name) return;
    const uint32_t text = GuestText(Identity(LatestWeek()).name);
    if (!text) { host->Fail("Academy display name allocation failed"); return; }
    const uint32_t name = Call(0xdd1828, {text});
    host->GuestFree(text);
    if (!name) { host->Fail("Academy owned display name allocation failed"); return; }
    if (previous) host->GuestFree(previous);
    owned_login_name = name;
    host->MemoryWrite32(login + 0x74, name);
}
void Upload(Dynarmic::A32::Jit& jit) {
    const int32_t score = int32_t(jit.Regs()[1]);
    if (session && race_active && State() == 2 && jit.Regs()[0] == academy && jit.Regs()[2] == 5 && ValidScore(score)) {
        uint32_t index = header.count;
        for (uint32_t i = 0; i < header.count; ++i)
            if (records[i].profile == pinned.profile && records[i].week == pinned.week && !std::strcmp(records[i].name, pinned.name)) index = i;
        if (index == header.count) {
            if (header.count == records.size()) {
                index = uint32_t(std::min_element(records.begin(), records.end(), [](const Record& a, const Record& b) { return a.week < b.week; }) - records.begin());
            } else ++header.count;
            records[index] = pinned;
        }
        records[index].score = KeepBest(records[index].score, score);
        if (!Save()) host->Fail("Academy local record could not be saved");
        race_active = false;
    }
    jit.Regs()[0] = 0;
}
struct Hook {
    const char* name;
    uint32_t rva, first, second;
    ThunkHandler handler;
    uint32_t thunk = 0;
};
std::array<Hook, 10> hooks = {{
    {"instance", 0xb2f1e4, 0xe92d4010, 0xeb0b91c2, [](auto& jit, auto&) { jit.Regs()[0] = Instance(); }},
    {"week", 0xb2ef20, 0xe59f308c, 0xe3a02a01, [](auto& jit, auto&) { CompleteRequest(-1); jit.Regs()[0] = 0; }},
    {"track", 0xb2f0bc, 0xe92d41f0, 0xe59f40c8, [](auto& jit, auto&) { CompleteRequest(int32_t(jit.Regs()[1])); jit.Regs()[0] = 0; }},
    {"car", 0xb2efd8, 0xe92d41f0, 0xe59f40c8, [](auto& jit, auto&) { CompleteRequest(int32_t(jit.Regs()[1])); jit.Regs()[0] = 0; }},
    {"ranking", 0xb2ee08, 0xe92d47f0, 0xe59f40fc, [](auto& jit, auto& h) {
        if (h.ReadStackWord(jit, 0)) h.MemoryWrite32(Instance() + 0xa8, jit.Regs()[1] ? 1 : 0);
        CompleteRequest(int32_t(jit.Regs()[2])); jit.Regs()[0] = 0;
    }},
    {"upload", 0xb2ed60, 0xe59f3098, 0xe92d41f0, [](auto& jit, auto&) { Upload(jit); }},
    {"connect", 0xbc2ec8, 0xe92d4070, 0xe59f50b8, [](auto& jit, auto& h) {
        if (h.MemoryRead32(connect_action) != 2) { jit.Regs()[0] = h.CallGuestNested(original_connect); return; }
        session = true; race_active = false;
        const uint32_t online = Call(0xe11844);
        prior_online = h.MemoryRead8(online + 5);
        Call(0xe11614, {online, 1});
        LoginName(); Populate(-1);
        if (!Save()) { h.Fail("Academy local schedule could not be saved"); return; }
        h.MemoryWrite32(state_addr, 0); h.MemoryWrite32(connect_action, 3);
        Call(0xbc60b4);
    }},
    {"state", 0xb2ed00, 0xe59f3008, 0xe79f3003, [](auto& jit, auto& h) {
        const uint32_t value = jit.Regs()[0];
        if (session && value == 2) {
            pinned = Identity(int32_t(h.MemoryRead32(Instance() + 0x68)));
            race_active = true;
            Call(0xe11614, {Call(0xe11844), 1});
        }
        h.MemoryWrite32(state_addr, value);
    }},
    {"leave", 0xb2ed14, 0xe3a00000, 0xeafffff8, [](auto& jit, auto& h) {
        if (session) Call(0xe11614, {Call(0xe11844), prior_online ? 1u : 0u});
        session = false; race_active = false;
        h.MemoryWrite32(state_addr, 0); jit.Regs()[0] = 0;
    }},
    {"auto_action", 0xbbed20, 0xe59f301c, 0xe79f2003, [](auto& jit, auto& h) {
        uint32_t action = jit.Regs()[0];
        if (session && action == 3 && State() == 3) {
            Populate(-1); h.MemoryWrite32(state_addr, 0); h.MemoryWrite32(opening_screen, 7); action = 0;
        }
        const uint32_t previous = h.MemoryRead32(auto_action);
        if (action != previous) { h.MemoryWrite32(auto_action, action); h.MemoryWrite32(previous_auto_action, previous); }
        jit.Regs()[0] = action;
    }},
}};
}

bool RegisterOfflineAcademy(DynarmicHost& h, const std::string& files_dir) {
    if (host || files_dir.empty()) return false;
    host = &h; store_path = files_dir + "/academy_local.dat";
    if (KeepBest(-1, 120000) != 120000 || KeepBest(120000, 150000) != 120000 ||
        KeepBest(120000, 110000) != 110000 || KeepBest(120000, 0) != 120000 ||
        ValidScore(-1) || ValidScore(maximum_score + 1)) return false;
    Load();
    for (auto& hook : hooks) hook.thunk = h.GetThunkManager().RegisterThunk(std::string("a7_academy_") + hook.name, hook.handler);
    return !h.HasFailed();
}

bool PatchOfflineAcademy(DynarmicHost& h) {
    if (&h != host || h.MemoryRead32(base + 0xbac760) != 0xebf3b03d) return false;
    for (const auto& hook : hooks)
        if (!hook.thunk || !h.IsExecutableAddress(base + hook.rva) ||
            h.MemoryRead32(base + hook.rva) != hook.first || h.MemoryRead32(base + hook.rva + 4) != hook.second) return false;
    // Relocate only the exact ConnectToGLLive PUSH/LDR-literal prologue; resume at its original third instruction.
    original_connect = h.GuestAlloc(20);
    if (!original_connect) return false;
    const std::array<uint32_t, 5> trampoline = {0xe92d4070, 0xe59f5004, 0xe51ff004,
        base + 0xbc2ed0, h.MemoryRead32(base + 0xbc2f8c)};
    for (size_t i = 0; i < trampoline.size(); ++i) h.MemoryWrite32(original_connect + uint32_t(i * 4), trampoline[i]);
    h.AddExecutableRange(original_connect, 20);
    for (const auto& hook : hooks) {
        h.MemoryWrite32(base + hook.rva, 0xe51ff004); h.MemoryWrite32(base + hook.rva + 4, hook.thunk);
        h.InvalidateGuestCode(base + hook.rva, 8);
    }
    h.MemoryWrite32(base + 0xbac760, 0xe3a00001);
    h.InvalidateGuestCode(base + 0xbac760, 4);
    return !h.HasFailed();
}
