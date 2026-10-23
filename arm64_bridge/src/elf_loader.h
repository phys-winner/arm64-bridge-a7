// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <unordered_map>
#include <functional>
#include <elf.h>

struct ElfSegment {
    uint32_t vaddr;
    uint32_t memsz;
    uint32_t filesz;
    uint32_t flags;
    uint32_t offset;
};

struct ElfSymbol {
    std::string name;
    uint32_t value;
    uint32_t size;
    uint8_t bind;
    uint8_t type;
    uint16_t shndx;
};

using SymbolResolver = std::function<uint32_t(const std::string&, uint8_t)>;

class ElfLoader {
public:
    ElfLoader(uint8_t* guest_memory_base, size_t guest_memory_size,
              uint32_t load_base_addr, uint32_t load_limit);
    bool Relocate(const SymbolResolver& resolver);

    uint32_t GetSymbolAddress(const std::string& name, uint8_t type = STT_NOTYPE) const;
    uint32_t GetBaseAddress() const { return m_load_base; }
    uint32_t GetImageSize() const { return m_image_size; }
    const std::vector<uint32_t>& GetInitArray() const { return m_init_array; }
    const std::vector<ElfSegment>& GetSegments() const { return m_segments; }
    const std::vector<std::string>& GetNeededLibraries() const { return m_needed_libs; }
    const std::vector<std::string>& GetUndefinedSymbols() const { return m_undefined_symbols; }
    bool IsExecutable(uint32_t address) const;
    static bool SelfCheck(uint8_t* guest_memory, size_t guest_memory_size);

private:
    friend class DynarmicHost;
    // Only DynarmicHost may pass the live, direct-APK mmap into this parser.
    bool LoadFromMemory(const uint8_t* data, size_t size);
    bool ParseDynamic(const uint8_t* data, size_t size, const Elf32_Ehdr& header);
    bool Contains(uint32_t vaddr, uint64_t size, bool file_backed = false) const;
    bool ReadString(uint32_t offset, std::string& value) const;

    uint8_t* m_guest_mem;
    size_t m_guest_mem_size;
    uint32_t m_load_base;
    uint32_t m_load_limit;
    uint32_t m_image_size = 0;
    bool m_loaded = false;
    bool m_relocated = false;
    std::vector<ElfSegment> m_segments;
    std::vector<ElfSymbol> m_symbols;
    std::unordered_map<std::string, ElfSymbol> m_exported_symbols;
    std::vector<std::string> m_undefined_symbols;
    std::vector<std::string> m_needed_libs;
    std::vector<Elf32_Rel> m_relocations;
    std::vector<uint32_t> m_init_array;
    uint32_t m_init_func = 0;
    uint32_t m_init_array_vaddr = 0;
    uint32_t m_init_array_size = 0;
    uint32_t m_strtab_vaddr = 0;
    uint32_t m_strtab_size = 0;
};
