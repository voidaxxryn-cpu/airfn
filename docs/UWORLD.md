# UWorld resolution notes

Owner: viru.

## Two paths

`airfn/engine/uworld.cpp` tries them in order and caches the result.

### 1. Decrypt path (fast)

Fortnite obfuscates GWorld with a per-build byte-swap + XOR + subtract. cheatoffsets.com publishes the constants in the markdown body — look for the code block titled `Decryption` on https://www.cheatoffsets.com/g/fortnite.

Copy the two constants into `airfn/offsets/offsets_manual.hpp`:

```cpp
inline constexpr std::uint64_t uworld_xor_key = 0x????????????????ULL;
inline constexpr std::uint64_t uworld_sub_key = 0x????????????????ULL;
```

And the RVA:

```cpp
inline constexpr std::uintptr_t gworld_rva = 0x????????;
```

`decrypt_uworld()` does `_byteswap_uint64(enc) ^ xor - sub`. Result should be page-aligned and land in the user-mode canonical range — `looks_like_uworld()` filters obvious garbage.

### 2. Fallback chain (slower, safer)

If EAC changes the decrypt scheme mid-season, fall back to walking:

```
UEngine* GEngine
  └── UGameViewportClient* GameViewport
        └── UWorld* World
```

Needs three offsets in `offsets_manual.hpp`:

```cpp
inline constexpr std::uintptr_t gengine_rva              = 0x????????;
inline constexpr std::uintptr_t off_uengine_gameviewport = 0x????;
inline constexpr std::uintptr_t off_ugvc_world           = 0x????;
```

All three come out of Dumper-7's `Engine_classes.hpp`.

## Testing

Run `airfn.exe` on the lobby (before match). `uworld` should be non-zero within the first second. If not:

- Verify `gworld_rva` matches the running build's `FortniteClient-Win64-Shipping.exe` RVA (use IDA / rebase-aware disassembler).
- Print the raw `encrypted` value from `try_decrypt_path()` — non-zero means we're reading the right slot, decrypt is wrong.
- If encrypted is 0, EAC hasn't handed the pointer out yet — the game isn't past the first tick.
