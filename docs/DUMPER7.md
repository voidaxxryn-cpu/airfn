# Dumper-7 setup

Owner: viru. Everyone else can skim.

## What it is

Public UE4/UE5 SDK dumper: https://github.com/Encryqed/Dumper-7. Injects into the target process, walks GObjects + GNames, spits out a C++ SDK folder with every UClass/UEnum/UStruct offset.

We use it to bootstrap `airfn/offsets/offsets.h` — regex-parsed by `scripts/gen_offsets.mjs` for the fields cheatoffsets.com already publishes, and by hand for anything else.

## Steps

1. Clone Dumper-7. `x64 / Release` in VS 2022.
2. Open `Dumper-7/Generator.cpp`, edit `Settings::GameName` and `Settings::GameVersion` to match the current Fortnite build (e.g. `"Fortnite"` / `"++Fortnite+Release-31.00"`).
3. Adjust `Off::InSDK::ProcessEvent::Index` if EAC has moved it since the last dump — usually stable, watch UnknownCheats for the current index.
4. Build. Get `Dumper-7.dll`.
5. Inject into Fortnite via **any** injector that works on EAC (right now: manual-map through our roseware driver — do NOT LoadLibrary; EAC dumps loaded modules). See `docs/UWORLD.md` for the tiny injector we ship.
6. SDK output lands in `%APPDATA%/Roaming/UEDumper/GameName/`. Keep it OUT of the repo — 400 MB of generated code isn't a review-friendly diff.

## What we consume

From the dumped SDK we copy **only** the offsets we actually reference — not the full SDK. Add them to `airfn/offsets/offsets_manual.hpp` under the relevant `struct`. The autogen header handles anything cheatoffsets.com already tracks (`u_world::PersistentLevel`, `a_actor::RootComponent`, etc.).

## Sanity check

```
airfn.exe
[airfn] uworld=<ptr> ok
[airfn] gobjects=<n>
```

If `n` is 0 or `uworld=0`, either GObjects RVA is stale or the UWorld decrypt keys changed. Both live in `offsets_manual.hpp`.

## Anti-cheat note

Dumper-7 is public and EAC signatures it on sight. **Never inject the vanilla build.** Recompile with a fresh name + strip symbols + change section names before every injection. Or — better — port the relevant walking logic into our own dumper that runs entirely from the mapped driver's PoV (week 3+ stretch).
