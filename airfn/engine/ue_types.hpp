// Minimal UE5 struct declarations used by the walkers.
// Kept small on purpose — full SDK output is dumped by Dumper-7 and lives
// outside this repo (too big to commit, too churny to review).

#pragma once
#include <cstdint>

namespace ue {

    struct FVector      { float x, y, z; };
    struct FVector2D    { float x, y; };
    struct FRotator     { float pitch, yaw, roll; };
    struct FQuat        { float x, y, z, w; };
    struct FTransform   { FQuat rot; FVector translation; float pad0; FVector scale; float pad1; };

    struct FString {
        std::uintptr_t data;   // TCHAR*
        std::int32_t   count;
        std::int32_t   max;
    };

    template <typename T>
    struct TArray {
        std::uintptr_t data;   // T*
        std::int32_t   count;
        std::int32_t   max;
    };

    struct FNameEntry {
        std::uint16_t header; // wide flag + length
        char          str[1024];
    };

    struct FName {
        std::uint32_t comparison_index;
        std::uint32_t number;
    };

} // namespace ue
