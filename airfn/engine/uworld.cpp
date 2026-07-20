#include "uworld.hpp"
#include "../offsets/offsets.h"
#include "../offsets/offsets_manual.hpp"
#include "../../api/proc/process.hpp"

namespace airfn::engine {

    namespace {
        std::uintptr_t g_uworld = 0;
        std::uintptr_t g_module_base = 0;

        std::uintptr_t base() {
            if (!g_module_base) {
                g_module_base = process::get_module_base("FortniteClient-Win64-Shipping.exe");
            }
            return g_module_base;
        }

        // Cheap sanity check — decrypted UWorld should sit in user-mode range
        // and be page-aligned-ish.
        bool looks_like_uworld(std::uintptr_t p) {
            if (p < 0x10000ULL || p >= 0x00007FFFFFFFFFFFULL) return false;
            if (p & 0xF) return false;
            return true;
        }

        std::uintptr_t try_decrypt_path() {
            const auto b = base();
            if (!b || !off::manual::gworld_rva) return 0;
            auto encrypted = process::read<std::uint64_t>(b + off::manual::gworld_rva);
            if (!encrypted) return 0;
            auto decrypted = off::manual::decrypt_uworld(encrypted);
            return looks_like_uworld(decrypted) ? decrypted : 0;
        }

        std::uintptr_t try_fallback_chain() {
            const auto b = base();
            if (!b || !off::manual::gengine_rva) return 0;
            auto gengine = process::read<std::uintptr_t>(b + off::manual::gengine_rva);
            if (!gengine) return 0;
            auto gvc = process::read<std::uintptr_t>(gengine + off::manual::off_uengine_gameviewport);
            if (!gvc) return 0;
            auto world = process::read<std::uintptr_t>(gvc + off::manual::off_ugvc_world);
            return looks_like_uworld(world) ? world : 0;
        }
    }

    std::uintptr_t resolve_uworld() {
        if (g_uworld) return g_uworld;
        return refresh_uworld();
    }

    std::uintptr_t refresh_uworld() {
        if (auto p = try_decrypt_path())  { g_uworld = p; return p; }
        if (auto p = try_fallback_chain()){ g_uworld = p; return p; }
        g_uworld = 0;
        return 0;
    }

    std::uintptr_t get_persistent_level() {
        auto w = resolve_uworld();
        if (!w) return 0;
        return process::read<std::uintptr_t>(w + off::u_world::PersistentLevel);
    }

    std::uintptr_t get_owning_game_instance() {
        auto w = resolve_uworld();
        if (!w) return 0;
        // OwningGameInstance not in the auto-generated tree yet — add to
        // offsets_manual.hpp once viru confirms from Dumper-7.
        return 0;
    }

    std::uintptr_t get_game_state() {
        auto w = resolve_uworld();
        if (!w) return 0;
        // GameState offset also lives in u_world once cheatoffsets ships it.
        return 0;
    }

}
