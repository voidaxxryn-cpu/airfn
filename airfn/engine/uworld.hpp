// UWorld resolution. Two paths:
//   1) Decrypt path: read encrypted GWorld pointer at gworld_rva, run the
//      byte-swap + XOR-subtract from offsets_manual.hpp.
//   2) Fallback chain: GEngine -> GameViewport -> World (raw pointers, no
//      decrypt). Slower first frame but survives EAC pointer-mangling changes.
//
// Owner: viru.

#pragma once
#include <cstdint>

namespace airfn::engine {

    // Resolve UWorld once per session. Caches result. Returns 0 on failure.
    std::uintptr_t resolve_uworld();

    // Force refresh (call on map change or after respawn).
    std::uintptr_t refresh_uworld();

    // Getters — pull from the last resolved UWorld. Zero-safe.
    std::uintptr_t get_persistent_level();
    std::uintptr_t get_owning_game_instance();
    std::uintptr_t get_game_state();

}
