#include "gnames.hpp"
#include "../offsets/offsets_manual.hpp"
#include "../../api/proc/process.hpp"

#include <unordered_map>
#include <mutex>

namespace airfn::engine {

    namespace {
        constexpr std::uint32_t FNAME_STRIDE       = 2;   // bytes-per-entry alignment (UE5: 2 bytes)
        constexpr std::uint32_t FNAME_BLOCK_SIZE   = 0x2000; // 8 KiB per block (Fortnite UE5 default)
        constexpr std::uint32_t FNAME_BLOCK_OFFSET_BITS = 16;
        constexpr std::uint32_t FNAME_BLOCK_MASK   = (1u << FNAME_BLOCK_OFFSET_BITS) - 1;

        std::mutex g_cache_mtx;
        std::unordered_map<std::uint32_t, std::string> g_cache;

        std::uintptr_t fname_pool_base() {
            static std::uintptr_t cached = 0;
            if (cached) return cached;
            auto module = process::get_module_base("FortniteClient-Win64-Shipping.exe");
            if (!module || !off::manual::gnames_rva) return 0;
            cached = module + off::manual::gnames_rva;
            return cached;
        }
    }

    std::string fname_to_string_uncached(const ue::FName& name) {
        auto pool = fname_pool_base();
        if (!pool) return {};

        const std::uint32_t idx = name.comparison_index;
        const std::uint32_t block  = idx >> FNAME_BLOCK_OFFSET_BITS;
        const std::uint32_t offset = (idx & FNAME_BLOCK_MASK) * FNAME_STRIDE;

        // FNamePool layout (UE5): pool + 0x10 = Blocks[]  (TArray-like of ptrs)
        auto blocks_ptr = process::read<std::uintptr_t>(pool + 0x10);
        if (!blocks_ptr) return {};

        auto block_addr = process::read<std::uintptr_t>(blocks_ptr + block * sizeof(void*));
        if (!block_addr) return {};

        auto entry_addr = block_addr + offset;

        // FNameEntry header: 2 bytes = (bIsWide:1) | (len:15) (varies per UE version)
        auto header = process::read<std::uint16_t>(entry_addr);
        const bool  wide = (header & 1) != 0;
        const std::size_t len = (header >> 6) & 0x3FF; // conservative mask

        if (!len || len > 512) return {};

        if (wide) {
            std::wstring w(len, L'\0');
            if (!process::read_array(w.data(), entry_addr + 2, len * sizeof(wchar_t))) return {};
            std::string s(w.begin(), w.end()); // ok for ASCII names
            return s;
        } else {
            std::string s(len, '\0');
            if (!process::read_array(s.data(), entry_addr + 2, len)) return {};
            return s;
        }
    }

    std::string fname_to_string(const ue::FName& name) {
        {
            std::lock_guard<std::mutex> lk(g_cache_mtx);
            auto it = g_cache.find(name.comparison_index);
            if (it != g_cache.end()) return it->second;
        }
        auto s = fname_to_string_uncached(name);
        if (!s.empty()) {
            std::lock_guard<std::mutex> lk(g_cache_mtx);
            g_cache.emplace(name.comparison_index, s);
        }
        return s;
    }

}
