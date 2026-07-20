# airfn roadmap — 4 weeks

Live board mirrored at https://airfn-web.vercel.app/roadmap. Anti-cheat: **EAC only** (BattlEye is not on Fortnite).

---

## Week 1 — Foundations   ✅ done (truly)

- [x] Vulnerable driver picked: **iqvw64e** (Intel network diagnostics).
- [x] kdmapper compiling with PDB-resolved offset block.
- [x] Manual-mapped `roseware_driver.sys` — physmem R/W via CR3 decryption.
- [x] IOCTL-less comms via NtUserGetCPD hook (Win10 + Win11 23H2 paths).
- [x] Module base via kernel-side PEB walk (Toolhelp blocked by EAC).
- [x] `rose::` / `process::` usermode wrapper.

---

## Week 2 — Reading the world   🟡 in progress

Goal: enumerate every player. Walk the actor list, read health / position / bones for every enemy. WorldToScreen returns real pixels. Console-only proof — no drawing yet.

**viru** — engine + offsets
- [x] airfn client skeleton (`airfn/main.cpp`, engine/, offsets/).
- [x] cheatoffsets.com poller + autogen `offsets.h` + CI (30-min cron).
- [x] Full verified struct set copied to `offsets_verified.hpp` (Fortnite-specific).
- [x] UWorld decrypt formula wired: `byteswap(enc ^ 0x012F546C) - 1274101633`.
- [ ] Dumper-7 producing a clean SDK for build 41.20.
- [ ] `resolve_uworld()` returning non-zero within 1s of attach.
- [ ] GameState → PlayerArray traversal. Skip local player, filter dead pawns (health <= 0).
- [ ] Find health/shield offsets by pattern (attribute-set component). Log the byte layout.
- [ ] Mesh → BoneArray chain. FTransform stride, world-space extraction (position = last column of matrix).
- [ ] Verify head bone index in UE5 mannequin (usually 66, confirm on-live).

**real** — read-only rendering research
- [ ] Study UnknownCheats external-overlay repos. No code this week.
- [ ] Plan DX11 setup: transparent WS_EX_LAYERED topmost + WDA_EXCLUDEFROMCAPTURE.
- [ ] View matrix source path: LocalPlayer → ViewportClient → view projection. Draft WorldToScreen.
- [ ] Console "HUD": printf every visible player's name / HP / distance every 200ms. Sanity pass.

**truly** — driver ergonomics
- [ ] Batched read helper: one syscall pulls 0x2800 bytes per actor into local buffer. memcpy fields out.
- [ ] Handle stripping helper: OpenProcess dummy → drop PROCESS_QUERY_INFORMATION before EAC sees it.

**icenagger** — mouse driver bring-up (read-only week)
- [ ] Install Interception filter driver on dev boxes. Compile hello-world mouse mover.
- [ ] `KMouseMove(dx, dy)` + `KMouseClick(down)` via Interception. Verify Fortnite reads movement as real HID.

**airproductions** — plumbing
- [ ] Config skeleton (INI). Xorstr utility. Random window class name generator.

---

## Week 3 — Visuals   overlay + ESP

Goal: overlay running. ESP renders on top of Fortnite. Menu opens with R-SHIFT. Feels like a real cheat.

**real** — rendering owner
- [ ] DX11 device + swapchain on transparent WS_EX_LAYERED topmost window. `WDA_EXCLUDEFROMCAPTURE` on for anti-recording.
- [ ] ImGui bring-up. White theme (matches airfn-web). Inter font atlas 17px 4x oversampling.
- [ ] Player ESP: 2D box, health bar, shield bar, name, distance label, snap-line. Distance-fade past 200m.
- [ ] Skeleton ESP: 15 bones connected. Sanity clamp bone-to-origin < 200 units.
- [ ] Loot ESP: rarity-colored dots + labels. Filter by min rarity (blue+, purple+, gold+). Scan cache 750ms.
- [ ] Vehicle ESP: cars / boats / planes. Different icon per class.
- [ ] Radar: circular top-left, directional arrows for enemies, yaw-corrected. Zoom slider.
- [ ] Watermark, spectator counter, nearby-enemy counter.

**airproductions** — config
- [ ] Config save/load working with every module. Ini path next to exe.

---

## Week 4 — Combat + polish + ship

Goal: aim + trigger flawless. No-recoil clean. Config sticky. Obfuscation pass. Internal alpha to the five of us.

**icenagger** — aim owner
- [ ] Aim assist core: sub-pixel accumulator, cubic ease-out blend (30% prev / 70% new), long-range boost past 60m.
- [ ] Bone selector (head / chest / pelvis). Visibility gate. ADS-only toggle. FOV slider 30–600 px.
- [ ] Triggerbot spam mode: 20ms release cycle. Weapon-only gate. Trigger delay slider.
- [ ] No-recoil: read view punch offset, emit counter-delta via kernel mouse. Gaussian jitter for humanization.
- [ ] Silent-aim experiment: write viewangle pre-fire, snap back after. Test whether Fortnite server accepts.
- [ ] Rapid-fire toggle for semi-autos: intercept LMB, re-fire at max cadence per weapon class.

**airproductions** — hardening + release
- [ ] Obfuscation pass: xorstr every literal, delete PDB, optional PE header erase, random module name at map time.
- [ ] HWID spoof helper (separate exe): volume ID, SMBIOS via truly's driver. Test on burner accounts first.

**all**
- [ ] Internal alpha: five of us dogfood two nights back-to-back. Log every crash. Fix. Tag v1.0. Ship to ourselves.

---

## Working agreement

- Every PR reviewed by someone other than the author. No self-merge.
- Weekly sync Sunday 8pm UTC.
- Patch-day playbook: viru re-runs Dumper-7, verifies `offsets_manual.hpp` decrypt keys + `gworld_rva`, everyone else waits.
- EAC only. If an experiment risks a session flag (silent-aim, rapid-fire), test on a burner account first.
