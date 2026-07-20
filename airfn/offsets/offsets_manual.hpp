// Hand-verified offsets — survives autogen regen.
// Owner: viru. Source: https://www.cheatoffsets.com/g/fortnite#decrypt (2026-07-20 dump).

#pragma once
#include <cstdint>
#include <intrin.h>   // _byteswap_uint64

namespace off::manual {

    // ---- Engine globals (module-relative RVAs, hardcoded per build) --------
    inline constexpr std::uintptr_t gworld_rva  = 0x1B2439A0;   // encrypted GWorld ptr
    inline constexpr std::uintptr_t gengine_rva = 0x1B245388;   // plain GEngine ptr

    // ---- UWorld decrypt formula -------------------------------------------
    // byteswap(encrypted ^ 0x012F546C) - 1274101633
    inline constexpr std::uint64_t uworld_xor_key = 0x012F546CULL;
    inline constexpr std::uint64_t uworld_sub_key = 1274101633ULL;

    inline std::uintptr_t decrypt_uworld(std::uint64_t encrypted) {
        if (!encrypted) return 0;
        return static_cast<std::uintptr_t>(
            _byteswap_uint64(encrypted ^ uworld_xor_key) - uworld_sub_key
        );
    }

    // ---- GEngine -> GameViewport -> World fallback path -------------------
    // Only used if the decrypt path returns garbage. Offsets from u_engine
    // (GameViewport is at 0x130-ish depending on class — verify per dump).
    // For 41.20: UGameEngine::GameInstance = 0x288; UGameViewportClient::World = 0x78.
    // Full GEngine -> GameViewport chain: GEngine + 0x1C0 (approx) → GVC → +0x78 → UWorld.
    inline constexpr std::uintptr_t off_uengine_gameviewport = 0x1C0;  // verify vs Dumper-7
    inline constexpr std::uintptr_t off_ugvc_world           = 0x78;   // u_game_viewport_client::World

    // ---- GNames / GObjects raw RVAs (fill from Dumper-7 output) -----------
    // cheatoffsets doesn't publish these — they change every patch. viru
    // resolves via Dumper-7 pattern scan and drops here.
    inline constexpr std::uintptr_t gnames_rva   = 0x0;
    inline constexpr std::uintptr_t gobjects_rva = 0x0;

    // ---- Fortnite head-bone index (UE5 mannequin) -------------------------
    // Usually 66 across recent seasons. Verify on live by walking the
    // skeletal component's ComponentSpaceTransformsArray and looking for
    // the transform ~168 units above pelvis.
    inline constexpr std::int32_t head_bone_index = 66;
    inline constexpr std::int32_t neck_bone_index = 65;
    inline constexpr std::int32_t chest_bone_index = 8;
    inline constexpr std::int32_t pelvis_bone_index = 2;
}
