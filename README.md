# chromium-audit

**One command that finds every program on your PC built on the Chromium engine, checks each one against the four critical vulnerabilities Google fixed in October 2026 — CVE-2026-118306 (CVSS 9.6), CVE-2026-118331, CVE-2026-118348, CVE-2026-118344 — and updates the ones that can be updated.**

한국어: [README.ko.md](README.ko.md)

---

## The short version

**What it targets.** The four Critical Chromium vulnerabilities Google fixed on 2026-10-27. Every Chromium engine older than the fix build **156.0.8078.73** is in the vulnerable range — that includes Chrome builds from before that date, the whole 153 generation and older, the Chromium pinned by Playwright (156.0.8078.4), every fork based on those builds, and every engine embedded inside another app.

**What it finds.** Everything on your computer that runs on the Chromium engine — not just the browsers you know about:

- standalone browsers: Chrome, Edge, Brave, Vivaldi, Opera, NAVER Whale, Arc, Chromium, and lesser-known forks;
- the Edge WebView2 runtime that many Windows apps share;
- Chromium engines *embedded inside other programs* (CEF/Electron) — OBS Studio's browser sources, office suites, chat apps — the copies nobody remembers to update;
- the browser builds pinned by developer tools such as Playwright.

Each copy carries its own version and its own update path, and the embedded ones are exactly the ones that get forgotten.

**What it does.** For every copy it finds, the tool reads the *actual engine version* from disk (not the version the app advertises), tells you plainly which ones are in the vulnerable range, and — with `--update` — updates them through their **official** update channels only. Output language is automatic: Korean on Korean systems, English elsewhere (`--lang` to override).

## Quick start

**Windows** — double-click `run.bat` (it finds or installs Python for you, then runs the audit):

```
run.bat            audit only
run.bat --update   audit + update
```

**Linux / macOS:**

```sh
chmod +x run.sh
./run.sh            # audit only
./run.sh --update   # audit + update
```

**Anywhere, if you already have Python 3.8+:**

```sh
python3 chromium-audit.py            # audit only
python3 chromium-audit.py --update   # audit + update
python3 chromium-audit.py --json     # machine-readable output
python3 chromium-audit.py --lang ko  # output language: auto (default) / ko / en
```

No dependencies: the script uses only the Python standard library.

## What it checks

| Target | Examples | How the engine version is obtained |
|---|---|---|
| Standalone browsers | Chrome, Edge, Brave, Vivaldi, Opera, NAVER Whale, Arc, Chromium, Thorium, forks such as ego lite | File version resources, version-named install folders, package/registry records |
| Embedded Chromium (CEF) | OBS Studio browser sources, Hancom Office, other CEF apps | Version strings embedded in `libcef.dll` / the host executable |
| Edge WebView2 Runtime | The evergreen runtime many Windows apps share | Registry + install folder; judged by milestone (see below) |
| Playwright browsers | `chromium-1243`, `chromium-1248`, headless shells in the Playwright cache | Folder revision + the bundled binary's real version |

Detection is **characteristic-based, not a fixed name list**: install records, `PATH`, Chromium fingerprint files (`chrome.dll`, `chrome_elf.dll`, Chromium frameworks), and version output are all used, so unlisted forks are still found — and unrelated programs that merely have "browser" in their name are filtered out by an evidence gate.

## Reading the results

Each browser is merged into **one line per product** (old version folders and helper binaries are folded in), followed by a merged conclusion.

| Level | Meaning |
|---|---|
| **[DANGER]** | Engine is in a known-vulnerable range. Update now. |
| **[WARN]** | Engine is patched against the critical CVEs but behind the current stable, **or** an Edge/WebView2 on milestone 156, whose exact patch level cannot be read from disk. |
| **[INFO]** | The engine version could not be confirmed, or the item is an *embedded* engine (see "Embedded engines" below). |
| **[OK]** | Up to date. |

Exit codes: `0` = nothing needs action, `1` = something needs an update, `2` = nothing was found.

## Updating: what `--update` does

For each item flagged DANGER or WARN, the tool tries, in order:

1. **The official channel** — Playwright via `pip`; Windows browsers via `winget`, falling back to the vendor's own updater (`GoogleUpdate.exe`, `MicrosoftEdgeUpdate.exe`, …); macOS via Homebrew casks; Linux via flatpak/snap (apt/dnf/pacman systems get the exact command printed instead of silent elevation).
2. **The app's own updater file** — if the install folder contains an updater executable, it is launched (installers and uninstallers are never run).
3. **Launching the app itself** — many apps check for updates at startup.
4. Only if all of that fails, the item is reported as **manual**, with its path.

**What it never does:** it never downloads binaries from unofficial sources, never patches or replaces program files itself, and never touches an item it could not identify. OBS Studio is deliberately *not* updated through winget: that route runs the full installer, which dies at the Windows UAC prompt (observed in practice); OBS is handled by steps 2–3, i.e. its own built-in updater.

## Requirements

- Python 3.8+ (the launchers install it if missing: winget on Windows, Homebrew on macOS, your package manager on Linux).
- Windows 10/11, macOS, or Linux. Administrator rights are only needed if an update channel itself asks for them.

---

## Background: the October 2026 Chromium vulnerabilities

### What actually happened (facts, as of 2026-11-04)

On **2026-10-27**, Google's *Chrome Releases* blog ("Stable Channel Update for Desktop") shipped Chrome **156.0.8078.73/.74** (Windows/Mac) and **156.0.8078.73** (Linux) with 52 security fixes: 4 Critical, 46 High, 2 Medium. The four Criticals — all reported by a single researcher at Anthropic — are:

| CVE | Component | CVSS (CISA/NVD) | Notes |
|---|---|---|---|
| CVE-2026-118306 | FileSystem | **9.6** | Scope-changed vector — sandbox-escape class. Description wording differs between sources ("use after free" vs "memory corruption"). |
| CVE-2026-118331 | FileAPI | 8.8 | Insufficient validation / use-after-free, depending on source. |
| CVE-2026-118348 | Skia | 8.8 | Integer overflow / improper validation, depending on source. |
| CVE-2026-118344 | Layout | 8.8 | Use after free (consistent across sources). |

Google does not publish CVSS scores; the scores above come from CISA's ADP via the NVD.

**Consequence:** any Chromium engine **older than 156.0.8078.73** contains the vulnerable code. That includes:

- Chrome/Chromium builds before 2026-10-27's release, and the whole 153 generation and older.
- The Chromium pinned by **Playwright**: revision **chromium-1248 = 156.0.8078.4**, shipped by Playwright **1.64.0 / 1.64.1**. (The older chromium-1243 = 153.0.8010.12, from Playwright 1.63.0.)
- Forks and embedded engines built on Chromium ≤ 156.0.8078.72.

### A note on the "Playwright is vulnerable" headline

No official announcement literally says "Playwright chromium-1248 and below are vulnerable." That sentence is a *derived* conclusion — drawn publicly by third parties (e.g. S5 Labs' patch checklist, 2026-10-28) from the two facts above. This tool therefore implements the underlying rule — *embedded Chromium < 156.0.8078.73 ⇒ affected* — rather than repeating the headline.

Two follow-ups worth knowing:

- **As of 2026-11-04, no released Playwright version fixes this.** 1.64.1 (the latest stable) still pins chromium-1248; upgrading Playwright alone does not yet help. The project's main branch has moved to newer revisions (1253 / Chromium 158 pre-release), so a fixed release is expected, but its final pin was still changing. Playwright's own position (2026-11-03): its packages bundle no browser; MCP/CLI use your installed Chrome/Edge, and only the test runner uses the pinned build.
- Chrome **157.0.8103.38/.39** became the full Stable release on **2026-11-03** (213 security fixes, 7 Critical) and is this tool's "current stable" reference — fetched live at runtime (see below), not frozen in the code.

## Version numbers are not comparable across vendors

The single most important technical fact behind this tool's verdict logic: **only Chrome itself (and Chrome-for-Testing builds, including Playwright's) stamps the true Chromium version on disk.** Every other vendor stamps its own product version:

| Product | What the file version means | How this tool judges it |
|---|---|---|
| Chrome / Chrome for Testing | The real Chromium version | Direct comparison with the fix build |
| ego lite and similar forks that print `chromium X.Y.Z.W` | The real Chromium version (from `--version` output or fixed version info) | Direct comparison |
| **Edge / WebView2** | Microsoft's own numbering. Only the first component equals the Chromium milestone: Edge 156.0.4314.58 = Chromium **milestone 156**; "4314" has *no* arithmetic relation to Chromium's "8078". The exact Chromium patch base is **not stored anywhere on disk** — only Microsoft's release notes / Security Update Guide state it. | **Milestone only**: < 156 → DANGER; = 156 → WARN (patch level unknowable locally); ≥ 157 → OK |
| Brave, Vivaldi, Opera, Whale, Arc | The vendor's product version; the Chromium base is documented only in vendor changelogs (e.g. Brave "v1.98.63 (Chromium 156.0.8078.80)") | Reported as INFO (unconfirmed) unless a true Chromium version can be established; updating still offered via official channels |
| CEF embeds (OBS, Hancom, …) | `libcef.dll`'s file version is a **CEF version stamp, not a Chromium version** (format `X.Y.Z+g<hash>+chromium-A.B.C.D`, where X = Chromium major). OBS stamps seen in the wild: `127.145.7.0`, `150.0.20.0` | The real Chromium version is read from version strings embedded in the binaries (e.g. OBS's CEF runtime = Chromium 127.0.6533.120); if only the stamp is found, just the milestone is treated as known |
| Electron apps | The main executable's file version is rewritten to the *app's* version. The mapping (Electron 45.x → Chromium 156.0.8078.80, …) is published per release at releases.electronjs.org | Detected via fingerprint/strings where possible; judged on the embedded Chrome version string when found |

Two more caveats this design respects:

- **Backports.** Vendors such as Vivaldi ship an older Chromium *base* (often Extended Stable) with security fixes backported from newer Chromium. A raw version comparison would call them vulnerable forever; this tool marks such products unconfirmed rather than crying wolf.
- **WebView2 Fixed-Version copies** bundled inside individual apps do not auto-update and are not covered by the evergreen runtime's registry keys; they are reported as embedded engines at their own paths.

### Embedded engines are judged differently — on purpose

If an app embeds Chromium (CEF/Electron), you cannot upgrade the engine yourself; only the app vendor can, by shipping a new app version. Flagging a fully-updated OBS as "DANGER: still on Chromium 150" would be noise — the user has already done everything possible. Embedded engines are therefore reported as **INFO** with their engine generation shown, excluded from the "action needed" list, and kept current simply by keeping the host app updated.

## How it works

### Detection

1. **Install records** — Windows uninstall registry keys and `EdgeUpdate` client keys (Edge `{56EB18F8-…}`, WebView2 `{F3017226-…}`), Linux package data and `.desktop` files, macOS app bundles (`Info.plist` + framework fingerprints).
2. **Common locations & `PATH`** — standard install trees and anything on `PATH` whose name matches a browser hint.
3. **Fingerprint folders** — directories containing `chrome.dll` / `chrome_elf.dll` / a Chromium framework are treated as Chromium installs even when the product is unknown.
4. **Playwright cache** — `ms-playwright` folders (`chromium-<rev>`, `chromium_headless_shell-<rev>`).

An **evidence gate** then drops name-only candidates that yield no engine evidence (this is what keeps Windows system files such as `SearchIndexer.exe` — matched only because "search" contains "arc" — out of the report). False-positive helper binaries (`*_proxy.exe`, `pwa_launcher`, `ie_to_edge_stub`, crashpad handlers, brokers, uninstallers) are excluded up front.

### Version extraction (Windows is static-first)

Reading files never launches anything: on Windows the audit uses fixed file-version info, version-named folders, and DLL versions in the app's *own* tree (shared system folders such as `System32` are never mined — their DLLs belong to other products). Only when a browser still has no version after all static methods does the tool run that browser's representative binary **once** with `--version`, after duplicates have been merged — an audit must never pop up a window per browser. CEF embeds additionally get a byte-level scan for the embedded `chromium-A.B.C.D` string.

### Verdicts & thresholds

- `engine ≤ 153.0.8010.12` → DANGER (old generation; chromium-1243 and below)
- `engine < 156.0.8078.73` → DANGER (the 2026-10-27 Criticals are unpatched)
- `engine < current stable` → WARN
- Edge/WebView2 → milestone rules from the table above
- Embedded engines → INFO (generation shown)
- The "current stable" value is fetched at runtime from Google's **VersionHistory API** (`versionhistory.googleapis.com/v1/chrome/platforms/<platform>/channels/stable/versions`, no key required); if the network is unavailable, a built-in fallback value is used and labelled as such.

### Update channels (verified identifiers)

| Product | winget ID | Vendor updater |
|---|---|---|
| Google Chrome | `Google.Chrome` | `GoogleUpdate.exe` / `GoogleUpdater.exe` (`/ua /installsource scheduler`), scheduled tasks |
| Microsoft Edge / WebView2 | `Microsoft.Edge` | `MicrosoftEdgeUpdate.exe`, services `edgeupdate`/`edgeupdatem` |
| Brave | `Brave.Brave` | `BraveUpdate.exe` (under `BraveSoftware\Update`) |
| Vivaldi | `Vivaldi.Vivaldi` | `update_notifier.exe` in the program folder (no service) |
| Opera | `Opera.Opera` | `opera_autoupdate.exe` in the version folder |
| NAVER Whale | `NAVER.Whale` | `whale_update.exe` + `wusvc.exe` service |
| Arc | `TheBrowserCompany.Arc` | In-app only (MSIX). **Note:** Arc is being sunset on 2026-12-22 — treat it as end-of-life, not merely outdated. |
| OBS Studio | `OBSProject.OBSStudio` (not used by this tool — installer/UAC issue) | Built-in updater (startup check / Help → Check for Updates); no documented external trigger |

## Limitations

- Edge/WebView2's exact Chromium patch level cannot be determined locally — by design, not by omission. Only Microsoft's per-release notes have it.
- A fork that stamps only its own version and never prints a Chromium version can be listed (with its product version) but graded INFO.
- CEF/Electron patch levels are exact only when the embedded version string is present; otherwise the milestone is all that is claimed.
- Playwright pins move between releases; the revision→version mapping in this README (1243 → 153.0.8010.12, 1248 → 156.0.8078.4) reflects releases up to 2026-11-04. The tool reads the bundled binary's real version, so its verdicts do not depend on this table.
- `--update` triggers official mechanisms; whether an update is *offered* to a given machine (staged rollouts, enterprise policies) is the vendor's decision. Re-run the audit to confirm the new version afterwards.

## FAQ

**Is it safe to run?** The audit itself only reads files and registry data. `--update` runs official vendor updaters and package managers — the same mechanisms the apps themselves use.

**Why does it say my Edge is only "milestone 156"?** Because that is all that exists on your disk. Microsoft does not store the Chromium patch version locally; anyone claiming a more precise local reading is guessing.

**My OBS is fully updated but listed with an old engine.** That is expected and is why embeds are INFO, not DANGER: OBS ships the CEF build it ships. Keeping OBS itself updated is the only action available — and sufficient.

**Playwright is flagged even after I upgraded it.** As of 2026-11-04 the newest Playwright still pins the affected Chromium (see Background). Watch for the first release that moves past revision 1248.

## License

MIT — see [LICENSE](LICENSE).
