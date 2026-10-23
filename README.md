# DS3 Co-op

Russian-language project workspace for playing **Dark Souls III** in two-player
co-op, built on top of Yui's **Seamless Co-op** mod.

The goal is four behaviours the base mod does not fully provide:

1. **Souls for both players** — souls are awarded to every player regardless of who killed the enemy.
2. **Loot for both players** — an item picked up by one player appears in each player's inventory;
   each can pick up independently.
3. **Independent NPC interaction** — each player can use merchants, the blacksmith and
   level-up NPCs on their own.
4. **Individual spending** — souls and items are deducted only from the player who is
   trading, upgrading or levelling.

Additional goal: a **Russian localization** of the mod.

> Notes, plans and session state are written in Russian because the owner is
> Russian-speaking. Code, commits and this README are in English.

## Status

| Stage | State |
|---|---|
| Research: what the base mod already does | done — see [`notes/01-mod-features.md`](notes/01-mod-features.md) |
| Install the mod + Russian locale | done, locale not yet picked up (game still in English) |
| Verify the four behaviours in a live session | **not started** |
| Patch for the missing behaviours | not started |

Current state of work, blockers and next steps: [`STATE.md`](STATE.md).
Task list: [`TODO.md`](TODO.md). History: [`CHANGELOG.md`](CHANGELOG.md).

## What the base mod does today

Short version — the mod synchronises the world, combat, event flags and sessions,
but **not** the wallet or the inventory. It has no economy, souls or shop subsystem
at all (confirmed by static analysis of `ds3sc.dll`).

| Requirement | Status in the base mod |
|---|---|
| 1. Souls for both | **No** — each player earns souls only for their own kills |
| 2. Loot for both | **Partial** — world pickups are instanced per player; scripted grants are only partly synced |
| 3. Independent NPCs | **Partial** — a guest can use bonfire menus, but merchant stock follows the host's progress |
| 4. Individual spending | **Likely yes** — separate characters and saves, no shared bank |

These are documented findings, not test results. See [`notes/01-mod-features.md`](notes/01-mod-features.md)
for sources and the caveats.

## Layout

```
STATE.md      handoff file — a new session reads this first
TODO.md       task list by stage
CHANGELOG.md  what changed, when, which files
notes/        research notes and evidence
mod/          our own artifacts: the Russian locale source
patches/      patches layered on top of the mod (not started)
backups/      local saves and game snapshots (git-ignored, never published)
local/        private machine state (git-ignored)
```

## Ground rules

- No anti-cheat bypass, no connection to FromSoftware servers.
- Co-op only through the mod, with its separate `.co2` saves — never on retail saves.
- No game files or assets in this repository.
- Patches ship as a separate package; the author's files are not modified.

## Credits

- **Seamless Co-op** by Yui (LukeYui) — [Nexus Mods](https://www.nexusmods.com/darksouls3/mods/1895).
  This project builds on it and does not redistribute it.
- Working method and playbooks: [coop-anything](https://github.com/cranebeaker/coop-anything).
