// SPDX-License-Identifier: GPL-3.0-or-later
#include "elf_loader.h"
#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <unordered_set>
#include <android/log.h>

#define LOG_TAG "Arm32Bridge_Elf"
#if defined(ASPHALT7_FINAL_SILENT)
#define LOGI(...) ((void)0)
#define LOGE(...) ((void)0)
#else
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#endif
#define ELF_REQUIRE(test, ...) do { if (!(test)) { LOGE(__VA_ARGS__); return false; } } while (0)

namespace {
bool Fits(uint64_t offset, uint64_t length, uint64_t size) {
    return offset <= size && length <= size - offset;
}
template<class T> T Read(const uint8_t* p) {
    T value;
    memcpy(&value, p, sizeof(value));
    return value;
}
}

ElfLoader::ElfLoader(uint8_t* memory, size_t memory_size, uint32_t base, uint32_t limit)
    : m_guest_mem(memory), m_guest_mem_size(memory_size), m_load_base(base), m_load_limit(limit) {}

bool ElfLoader::Contains(uint32_t address, uint64_t size, bool file_backed) const {
    for (const auto& segment : m_segments) {
        const uint64_t end = uint64_t(segment.vaddr) + (file_backed ? segment.filesz : segment.memsz);
        if (address >= segment.vaddr && Fits(address, size, end)) return true;
    }
    return false;
}

bool ElfLoader::IsExecutable(uint32_t address) const {
    if (address < m_load_base) return false;
    const uint32_t vaddr = (address & ~1u) - m_load_base;
    for (const auto& segment : m_segments) {
        if ((segment.flags & PF_X) && vaddr >= segment.vaddr &&
            Fits(vaddr, 2, uint64_t(segment.vaddr) + segment.filesz)) return true;
    }
    return false;
}

bool ElfLoader::LoadFromMemory(const uint8_t* data, size_t size) {
    ELF_REQUIRE(!m_loaded && m_segments.empty(), "ELF cannot be loaded twice");
    ELF_REQUIRE(data && size >= sizeof(Elf32_Ehdr), "Truncated ELF header");
    const auto header = Read<Elf32_Ehdr>(data);
    ELF_REQUIRE(memcmp(header.e_ident, ELFMAG, SELFMAG) == 0 &&
                header.e_ident[EI_CLASS] == ELFCLASS32 && header.e_ident[EI_DATA] == ELFDATA2LSB &&
                header.e_ident[EI_VERSION] == EV_CURRENT && header.e_version == EV_CURRENT &&
                header.e_machine == EM_ARM && header.e_type == ET_DYN,
                "Expected little-endian ARM ELF32 shared object");
    ELF_REQUIRE(header.e_ehsize == sizeof(Elf32_Ehdr) && header.e_phentsize == sizeof(Elf32_Phdr) &&
                header.e_phnum && Fits(header.e_phoff, uint64_t(header.e_phnum) * sizeof(Elf32_Phdr), size),
                "Invalid program header table");
    ELF_REQUIRE(!header.e_shnum || (header.e_shentsize == sizeof(Elf32_Shdr) &&
                Fits(header.e_shoff, uint64_t(header.e_shnum) * sizeof(Elf32_Shdr), size)),
                "Invalid section header table");
    ELF_REQUIRE(m_guest_mem && m_load_base < m_load_limit && m_load_limit <= m_guest_mem_size,
                "Invalid guest image reservation");

    for (uint32_t i = 0; i < header.e_phnum; ++i) {
        const auto p = Read<Elf32_Phdr>(data + header.e_phoff + i * sizeof(Elf32_Phdr));
        if (p.p_type != PT_LOAD) continue;
        ELF_REQUIRE(p.p_filesz <= p.p_memsz && Fits(p.p_offset, p.p_filesz, size), "Truncated PT_LOAD");
        ELF_REQUIRE(uint64_t(m_load_base) + p.p_vaddr + p.p_memsz <= m_load_limit,
                    "PT_LOAD exceeds reserved image range");
        ELF_REQUIRE(p.p_align <= 1 || ((p.p_align & (p.p_align - 1)) == 0 &&
                    (p.p_offset % p.p_align) == (p.p_vaddr % p.p_align)), "Invalid PT_LOAD alignment");
        for (const auto& existing : m_segments) {
            ELF_REQUIRE(!p.p_memsz || !existing.memsz ||
                        uint64_t(p.p_vaddr) + p.p_memsz <= existing.vaddr ||
                        uint64_t(existing.vaddr) + existing.memsz <= p.p_vaddr, "Overlapping PT_LOAD segments");
        }
        m_segments.push_back({p.p_vaddr, p.p_memsz, p.p_filesz, p.p_flags, p.p_offset});
        m_image_size = std::max(m_image_size, p.p_vaddr + p.p_memsz);
    }
    ELF_REQUIRE(!m_segments.empty() && m_image_size, "ELF has no loadable image");
    // Validate every destination before the first copy; the host gives each guest a disjoint reservation.
    for (const auto& segment : m_segments) {
        auto* destination = m_guest_mem + m_load_base + segment.vaddr;
        memcpy(destination, data + segment.offset, segment.filesz);
        memset(destination + segment.filesz, 0, segment.memsz - segment.filesz);
    }
    ELF_REQUIRE(ParseDynamic(data, size, header), "Invalid dynamic ELF metadata");
    m_loaded = true;
    LOGI("ELF mapped: base=0x%08x end=0x%08x segments=%zu exports=%zu imports=%zu",
         m_load_base, m_load_base + m_image_size, m_segments.size(), m_exported_symbols.size(), m_undefined_symbols.size());
    return true;
}

bool ElfLoader::ReadString(uint32_t offset, std::string& value) const {
    if (offset >= m_strtab_size) return false;
    const char* start = reinterpret_cast<const char*>(m_guest_mem + m_load_base + m_strtab_vaddr + offset);
    const char* end = static_cast<const char*>(memchr(start, 0, m_strtab_size - offset));
    if (!end) return false;
    value.assign(start, end);
    return true;
}

bool ElfLoader::ParseDynamic(const uint8_t* data, size_t size, const Elf32_Ehdr& header) {
    Elf32_Phdr dynamic{};
    for (uint32_t i = 0; i < header.e_phnum; ++i) {
        const auto p = Read<Elf32_Phdr>(data + header.e_phoff + i * sizeof(Elf32_Phdr));
        if (p.p_type != PT_DYNAMIC) continue;
        ELF_REQUIRE(!dynamic.p_filesz, "Multiple PT_DYNAMIC segments");
        dynamic = p;
    }
    ELF_REQUIRE(dynamic.p_filesz && dynamic.p_filesz % sizeof(Elf32_Dyn) == 0 &&
                Fits(dynamic.p_offset, dynamic.p_filesz, size) && Contains(dynamic.p_vaddr, dynamic.p_filesz, true),
                "Missing or truncated PT_DYNAMIC");
    uint32_t symtab = 0, syment = 0, hash = 0, rel = 0, relsz = 0, relent = sizeof(Elf32_Rel);
    uint32_t jmprel = 0, pltrelsz = 0, pltrel = DT_REL;
    std::vector<uint32_t> needed;
    bool terminated = false;
    for (uint32_t offset = 0; offset < dynamic.p_filesz; offset += sizeof(Elf32_Dyn)) {
        const auto d = Read<Elf32_Dyn>(m_guest_mem + m_load_base + dynamic.p_vaddr + offset);
        if (d.d_tag == DT_NULL) { terminated = true; break; }
        switch (d.d_tag) {
        case DT_STRTAB: m_strtab_vaddr = d.d_un.d_ptr; break;
        case DT_STRSZ: m_strtab_size = d.d_un.d_val; break;
        case DT_SYMTAB: symtab = d.d_un.d_ptr; break;
        case DT_SYMENT: syment = d.d_un.d_val; break;
        case DT_HASH: hash = d.d_un.d_ptr; break;
        case DT_REL: rel = d.d_un.d_ptr; break;
        case DT_RELSZ: relsz = d.d_un.d_val; break;
        case DT_RELENT: relent = d.d_un.d_val; break;
        case DT_JMPREL: jmprel = d.d_un.d_ptr; break;
        case DT_PLTRELSZ: pltrelsz = d.d_un.d_val; break;
        case DT_PLTREL: pltrel = d.d_un.d_val; break;
        case DT_INIT: m_init_func = d.d_un.d_ptr; break;
        case DT_INIT_ARRAY: m_init_array_vaddr = d.d_un.d_ptr; break;
        case DT_INIT_ARRAYSZ: m_init_array_size = d.d_un.d_val; break;
        case DT_NEEDED: needed.push_back(d.d_un.d_val); break;
        case DT_RELA: case DT_RELASZ:
            ELF_REQUIRE(!d.d_un.d_val, "DT_RELA is unsupported for these ARM guests");
            break;
        default: break;
        }
    }
    ELF_REQUIRE(terminated, "PT_DYNAMIC is missing DT_NULL");
    ELF_REQUIRE(symtab && syment == sizeof(Elf32_Sym) && m_strtab_size &&
                Contains(m_strtab_vaddr, m_strtab_size, true), "Invalid symbol/string tables");
    ELF_REQUIRE(relent == sizeof(Elf32_Rel) && pltrel == DT_REL, "Unsupported relocation entry format");
    ELF_REQUIRE(m_init_array_size % 4 == 0 && (!m_init_array_size ||
                Contains(m_init_array_vaddr, m_init_array_size, true)), "Truncated init array");
    ELF_REQUIRE(!m_init_func || IsExecutable(m_load_base + m_init_func), "DT_INIT is outside executable segments");

    uint32_t symbol_count = 0;
    if (hash) {
        ELF_REQUIRE(Contains(hash, 8, true), "Truncated DT_HASH header");
        const uint32_t buckets = Read<uint32_t>(m_guest_mem + m_load_base + hash);
        symbol_count = Read<uint32_t>(m_guest_mem + m_load_base + hash + 4);
        ELF_REQUIRE(Contains(hash, 8 + 4ull * (uint64_t(buckets) + symbol_count), true), "Truncated DT_HASH table");
    }
    // GNU-hash-only files may still give the exact dynsym extent through their checked section table.
    for (uint32_t i = 0; i < header.e_shnum; ++i) {
        const auto section = Read<Elf32_Shdr>(data + header.e_shoff + i * sizeof(Elf32_Shdr));
        if (section.sh_type != SHT_DYNSYM || section.sh_addr != symtab) continue;
        ELF_REQUIRE(section.sh_entsize == sizeof(Elf32_Sym) && section.sh_size % sizeof(Elf32_Sym) == 0 &&
                    Fits(section.sh_offset, section.sh_size, size), "Invalid dynsym section");
        const uint32_t count = section.sh_size / sizeof(Elf32_Sym);
        ELF_REQUIRE(!symbol_count || symbol_count == count, "DT_HASH/dynsym count disagreement");
        symbol_count = count;
    }
    ELF_REQUIRE(symbol_count && Contains(symtab, uint64_t(symbol_count) * sizeof(Elf32_Sym), true),
                "No bounded dynamic symbol table");
    for (uint32_t offset : needed) {
        std::string name;
        ELF_REQUIRE(ReadString(offset, name) && !name.empty(), "Invalid DT_NEEDED string");
        m_needed_libs.push_back(std::move(name));
    }
    for (uint32_t i = 0; i < symbol_count; ++i) {
        const auto sym = Read<Elf32_Sym>(m_guest_mem + m_load_base + symtab + i * sizeof(Elf32_Sym));
        ElfSymbol parsed{};
        ELF_REQUIRE(ReadString(sym.st_name, parsed.name), "Unterminated symbol name");
        parsed.type = ELF32_ST_TYPE(sym.st_info);
        parsed.bind = ELF32_ST_BIND(sym.st_info);
        parsed.shndx = sym.st_shndx;
        parsed.size = sym.st_size;
        if (sym.st_shndx != SHN_UNDEF) {
            ELF_REQUIRE(sym.st_shndx != SHN_COMMON && parsed.type != STT_TLS, "Unsupported allocated/TLS symbol");
            if (sym.st_shndx == SHN_ABS) parsed.value = sym.st_value;
            else {
                ELF_REQUIRE(Contains(sym.st_value & (parsed.type == STT_FUNC ? ~1u : ~0u), sym.st_size),
                            "Defined symbol lies outside its PT_LOAD");
                parsed.value = m_load_base + sym.st_value;
            }
            if (!parsed.name.empty() && parsed.bind != STB_LOCAL && (sym.st_other & 3u) != STV_HIDDEN)
                m_exported_symbols.emplace(parsed.name, parsed);
        } else if (!parsed.name.empty()) m_undefined_symbols.push_back(parsed.name);
        m_symbols.push_back(std::move(parsed));
    }
    for (auto [address, bytes] : {std::pair{rel, relsz}, std::pair{jmprel, pltrelsz}}) {
        ELF_REQUIRE(bytes % sizeof(Elf32_Rel) == 0 && (!bytes || Contains(address, bytes, true)),
                    "Truncated relocation table");
        for (uint32_t offset = 0; offset < bytes; offset += sizeof(Elf32_Rel))
            m_relocations.push_back(Read<Elf32_Rel>(m_guest_mem + m_load_base + address + offset));
    }
    return true;
}

bool ElfLoader::Relocate(const SymbolResolver& resolver) {
    ELF_REQUIRE(m_loaded && !m_relocated, "ELF must be loaded and relocated exactly once");
    std::vector<std::pair<uint32_t, uint32_t>> writes;
    std::unordered_set<uint32_t> destinations;
    bool resolved = true;
    for (const auto& relocation : m_relocations) {
        const uint32_t type = ELF32_R_TYPE(relocation.r_info);
        if (type == R_ARM_NONE) continue;
        ELF_REQUIRE(Contains(relocation.r_offset, 4) && !(relocation.r_offset & 3), "Invalid relocation destination");
        ELF_REQUIRE(destinations.insert(relocation.r_offset).second, "Duplicate relocation destination");
        const uint32_t index = ELF32_R_SYM(relocation.r_info);
        ELF_REQUIRE(index < m_symbols.size(), "Relocation symbol index out of bounds");
        uint32_t symbol = 0;
        if (index) {
            const auto& entry = m_symbols[index];
            const uint8_t expected_type = type == R_ARM_JUMP_SLOT ? STT_FUNC : entry.type;
            ELF_REQUIRE(expected_type == STT_NOTYPE || expected_type == STT_FUNC || expected_type == STT_OBJECT,
                        "Unsupported relocation symbol type %u", expected_type);
            if (entry.shndx != SHN_UNDEF) symbol = entry.value;
            else {
                symbol = resolver(entry.name, expected_type);
                if (!symbol && entry.bind != STB_WEAK) {
                    LOGE("Unresolved strong import: %s type=%u relocation=%u", entry.name.c_str(), expected_type, type);
                    resolved = false;
                }
            }
        }
        uint32_t value = Read<uint32_t>(m_guest_mem + m_load_base + relocation.r_offset);
        switch (type) {
        case R_ARM_RELATIVE:
            ELF_REQUIRE(!index, "R_ARM_RELATIVE has a symbol index");
            value += m_load_base; break;
        case R_ARM_GLOB_DAT: case R_ARM_JUMP_SLOT: value = symbol; break;
        case R_ARM_ABS32: value += symbol; break;
        case R_ARM_REL32: value += symbol - (m_load_base + relocation.r_offset); break;
        default: LOGE("Unsupported ARM relocation %u", type); return false;
        }
        writes.emplace_back(m_load_base + relocation.r_offset, value);
    }
    ELF_REQUIRE(resolved, "Strong import closure failed; no relocations applied");
    for (const auto& [address, value] : writes) memcpy(m_guest_mem + address, &value, sizeof(value));
    if (m_init_func) m_init_array.push_back(m_load_base + m_init_func);
    for (uint32_t offset = 0; offset < m_init_array_size; offset += 4) {
        const uint32_t entry = Read<uint32_t>(m_guest_mem + m_load_base + m_init_array_vaddr + offset);
        // Entries are read AFTER relocation; adding load_base a second time corrupts them.
        if (entry && entry != UINT32_MAX) m_init_array.push_back(entry);
    }
    m_relocated = true;
    LOGI("ELF relocated: base=0x%08x relocations=%zu initializers=%zu", m_load_base, writes.size(), m_init_array.size());
    return true;
}

uint32_t ElfLoader::GetSymbolAddress(const std::string& name, uint8_t type) const {
    const auto found = m_exported_symbols.find(name);
    if (found == m_exported_symbols.end()) return 0;
    if (type != STT_NOTYPE && found->second.type != STT_NOTYPE && found->second.type != type) return 0;
    return found->second.value;
}

bool ElfLoader::SelfCheck(uint8_t* memory, size_t memory_size) {
    std::array<uint8_t, sizeof(Elf32_Ehdr) + sizeof(Elf32_Phdr)> bytes{};
    Elf32_Ehdr header{};
    memcpy(header.e_ident, ELFMAG, SELFMAG);
    header.e_ident[EI_CLASS] = ELFCLASS32;
    header.e_ident[EI_DATA] = ELFDATA2LSB;
    header.e_ident[EI_VERSION] = EV_CURRENT;
    header.e_type = ET_DYN; header.e_machine = EM_ARM; header.e_version = EV_CURRENT;
    header.e_ehsize = sizeof(header); header.e_phoff = sizeof(header);
    header.e_phnum = 1; header.e_phentsize = sizeof(Elf32_Phdr);
    auto reject = [&](const Elf32_Ehdr& h, const Elf32_Phdr& p, size_t size) {
        memcpy(bytes.data(), &h, sizeof(h));
        memcpy(bytes.data() + sizeof(h), &p, sizeof(p));
        ElfLoader loader(memory, memory_size, 0x40000000, 0x40800000);
        return !loader.LoadFromMemory(bytes.data(), size);
    };
    Elf32_Phdr segment{}; segment.p_type = PT_LOAD;
    bool ok = reject(header, segment, sizeof(Elf32_Ehdr) - 1);
    auto bad_header = header; bad_header.e_phoff = UINT32_MAX - 3;
    ok &= reject(bad_header, segment, bytes.size());
    segment.p_filesz = 1; segment.p_memsz = 0;
    ok &= reject(header, segment, bytes.size());
    segment.p_memsz = 1; segment.p_offset = UINT32_MAX;
    ok &= reject(header, segment, bytes.size());
    segment.p_offset = 0; segment.p_vaddr = 0x00800000;
    ok &= reject(header, segment, bytes.size());
    LOGI("ElfParserSelfCheck %s (five expected rejections)", ok ? "OK" : "FAILED");
    return ok;
}
