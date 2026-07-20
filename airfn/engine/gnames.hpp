// GNames walker — resolves FName -> ansi/wide string.
// UE5 uses FNamePool (chunked). Chunk stride + entry alignment come from
// Dumper-7. Placeholders live in offsets_manual.hpp.

#pragma once
#include <cstdint>
#include <string>
#include "ue_types.hpp"

namespace airfn::engine {

    // Returns "" on failure. Caches per-FName resolution in-process.
    std::string fname_to_string(const ue::FName& name);

    // Skip cache — refetch from live memory. Use during dev / offset tuning.
    std::string fname_to_string_uncached(const ue::FName& name);

}
