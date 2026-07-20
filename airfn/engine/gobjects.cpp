#include "gobjects.hpp"
#include "../offsets/offsets_manual.hpp"
#include "../../api/proc/process.hpp"

namespace airfn::engine {

    namespace {
        constexpr std::int32_t ELEMENTS_PER_CHUNK = 64 * 1024;
        constexpr std::size_t  ITEM_STRIDE        = 24; // FUObjectItem: {ptr, flags, cluster, serial}

        std::uintptr_t g_array = 0;

        std::uintptr_t array_base() {
            if (g_array) return g_array;
            auto mod = process::get_module_base("FortniteClient-Win64-Shipping.exe");
            if (!mod || !off::manual::gobjects_rva) return 0;
            g_array = mod + off::manual::gobjects_rva;
            return g_array;
        }

        // FUObjectArray -> FChunkedFixedUObjectArray at +0x10
        // FChunkedFixedUObjectArray layout:
        //   +0x00 Objects (FUObjectItem**)
        //   +0x08 PreAllocatedObjects
        //   +0x10 MaxElements
        //   +0x14 NumElements
        //   +0x18 MaxChunks
        //   +0x1C NumChunks
        std::uintptr_t chunked() { return array_base() + 0x10; }
    }

    std::int32_t gobjects_num() {
        auto c = chunked();
        if (!c) return 0;
        return process::read<std::int32_t>(c + 0x14);
    }

    UObjectItem gobjects_at(std::int32_t index) {
        UObjectItem out{};
        if (index < 0) return out;

        auto c = chunked();
        if (!c) return out;

        auto objects = process::read<std::uintptr_t>(c + 0x00);
        if (!objects) return out;

        const std::int32_t chunk_index = index / ELEMENTS_PER_CHUNK;
        const std::int32_t within      = index % ELEMENTS_PER_CHUNK;

        auto chunk = process::read<std::uintptr_t>(objects + chunk_index * sizeof(void*));
        if (!chunk) return out;

        auto item_addr = chunk + static_cast<std::uintptr_t>(within) * ITEM_STRIDE;
        if (!process::read_array(&out, item_addr, sizeof(out))) return {};
        return out;
    }

    void gobjects_for_each(const std::function<bool(std::int32_t, const UObjectItem&)>& fn) {
        const auto n = gobjects_num();
        for (std::int32_t i = 0; i < n; ++i) {
            auto it = gobjects_at(i);
            if (!it.object) continue;
            if (!fn(i, it)) return;
        }
    }

}
