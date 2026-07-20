// airfn — usermode cheat client.
// Attaches to Fortnite via truly's roseware driver, resolves UWorld (viru),
// walks GObjects, prints a sanity dump. Later modules (aim/esp/etc.) plug in
// on top of the same read/write primitives.
//
// Build: MSBuild via physmem.sln (airfn project) or CMake preset "airfn".

#include <cstdio>
#include <chrono>
#include <thread>

#include "../api/proc/process.hpp"
#include "engine/uworld.hpp"
#include "engine/gnames.hpp"
#include "engine/gobjects.hpp"
#include "offsets/offsets.h"
#include "offsets/offsets_manual.hpp"

using namespace airfn;

int main() {
    printf("[airfn] build %s (%s) offsets id=%llu\n",
        off::build_version, off::build_label, (unsigned long long)off::build_id);

    if (!process::attach_to_proc("FortniteClient-Win64-Shipping.exe")) {
        printf("[airfn] attach failed. driver mapped? game running?\n");
        return 1;
    }

    printf("[airfn] attached pid=%llu cr3=%llx\n",
        (unsigned long long)process::target_pid,
        (unsigned long long)process::target_cr3);

    auto module_base = process::get_module_base("FortniteClient-Win64-Shipping.exe");
    auto module_size = process::get_module_size("FortniteClient-Win64-Shipping.exe");
    printf("[airfn] module base=%llx size=%llx\n",
        (unsigned long long)module_base, (unsigned long long)module_size);

    auto uworld = engine::resolve_uworld();
    printf("[airfn] uworld=%llx (%s)\n",
        (unsigned long long)uworld,
        uworld ? "ok" : "not resolved — check offsets_manual.hpp");

    auto n = engine::gobjects_num();
    printf("[airfn] gobjects=%d\n", (int)n);

    // Sanity loop — keeps primitives warm. Real modules land week 2+.
    for (;;) {
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
        if (!uworld) uworld = engine::refresh_uworld();
    }
    return 0;
}
