// GObjects walker — iterate every live UObject in Fortnite.
// UE5 uses FUObjectArray, chunked by 64 KiB.
// Placeholder addresses in offsets_manual.hpp.

#pragma once
#include <cstdint>
#include <functional>

namespace airfn::engine {

    struct UObjectItem {
        std::uintptr_t object;
        std::int32_t   flags;
        std::int32_t   cluster_root_index;
        std::int32_t   serial_number;
    };

    // Total live object count.
    std::int32_t gobjects_num();

    // Fetch by index. Returns {0,...} on OOB.
    UObjectItem gobjects_at(std::int32_t index);

    // Walk everything, stop when the callback returns false.
    void gobjects_for_each(const std::function<bool(std::int32_t, const UObjectItem&)>& fn);

}
