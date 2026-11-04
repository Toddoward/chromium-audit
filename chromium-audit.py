#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
chromium-audit.py — audit every Chromium-based browser on this machine,
and (optionally) update the ones that have an official update path.
Windows / Linux / macOS, Python standard library only.

What it does:
  1. Finds Chromium-based browsers by characteristics, not a fixed name list:
     install records (registry / package managers / .app bundles), PATH,
     common install locations, folders carrying Chromium fingerprint files
     (chrome.dll, chrome_elf.dll, Chromium Framework), and executables whose
     --version output mentions chromium (custom forks such as ego).
  2. Extracts the true engine version several ways: full --version output
     parsing (including separate "chromium X.Y.Z.W" lines), file version
     resources (Windows), version-named folders, macOS framework Versions
     folders, and byte-level strings inside CEF libraries.
  3. Judges each engine against the thresholds below.
  4. With --update, updates only through official channels:
     Playwright via pip; Windows via winget, then the vendor updater;
     macOS via Homebrew casks; Linux via flatpak/snap (apt/dnf/pacman get a
     printed command, never silent elevation). Anything without an official
     path is reported for manual updating, never touched.

Thresholds (verified 2026-11-05; see the README "Background" section):
  - There is no official notice saying "Playwright chromium-1248 and below
    are vulnerable". The authoritative source is Google's Chrome Releases
    post of 2026-10-27: the four Criticals (CVE-2026-118306/118331/118348/
    118344) were fixed in 156.0.8078.73/.74, so any Chromium below
    156.0.8078.73 is affected. chromium-1243 = 153.0.8010.12 (Playwright
    1.63.0); chromium-1248 = 156.0.8078.4 (Playwright 1.64.0/1.64.1) — no
    Playwright release with a newer pin existed as of 2026-11-04.
  - Chrome current stable = 157.0.8103.38 (2026-11-03); fetched live from
    the VersionHistory API at runtime, with this value as fallback.
  - Edge / WebView2 cannot be compared numerically with Chromium (only the
    milestone is shared; the patch level is not on disk) — milestone rules.
  - CEF embeds prefer the real Chromium string embedded in libcef.dll;
    without it, only the milestone is treated as known.

Usage:
  python3 chromium-audit.py              audit only
  python3 chromium-audit.py --update     also update what can be updated
  python3 chromium-audit.py --json       machine-readable output
  python3 chromium-audit.py --lang en    force output language (auto/ko/en)
Exit codes: 0 = nothing to do, 1 = action needed, 2 = nothing found.
Output language: auto-detected from the system locale (Korean systems get
Korean, everything else English); override with --lang or the
CHROMIUM_AUDIT_LANG environment variable.
"""
import argparse
import json
import locale
import os
import re
import shutil
import subprocess
import sys

VULN_CONFIRMED = (153, 0, 8010, 12)   # at/below: old vulnerable generation (chromium-1243)
CVE_FIXED = (156, 0, 8078, 73)        # fix build for the four Criticals (Chrome Releases 2026-10-27)
NOTICE_BOUNDARY = (156, 0, 8078, 4)   # engine version of chromium-1248 (reference)
LATEST_STABLE = (157, 0, 8103, 38)    # built-in fallback; refreshed via the VersionHistory API
PLAYWRIGHT_VULN_MAX = 1248

# ---------------------------------------------------------------- i18n
LANG = "en"

LSTR = {
    "app_desc": {"ko": "Chromium 계열 브라우저 전수 점검 + 자동 업데이트",
                 "en": "Audit all Chromium-based browsers (+ auto-update)"},
    "lvl_danger": {"ko": "[위험]", "en": "[DANGER]"},
    "lvl_warn": {"ko": "[주의]", "en": "[WARN]"},
    "lvl_ok": {"ko": "[양호]", "en": "[OK]"},
    "lvl_info": {"ko": "[정보]", "en": "[INFO]"},
    "unknown": {"ko": "확인 불가", "en": "unknown"},
    "engine_w": {"ko": "엔진", "en": "engine"},
    "product_w": {"ko": "제품", "en": "product"},
    "webview2_name": {"ko": "Edge WebView2 (런타임)", "en": "Edge WebView2 Runtime"},
    "v_noengine": {"ko": "엔진 버전 확인 불가 — 수동 확인 필요",
                   "en": "Engine version could not be determined — check manually"},
    "v_edge_low": {"ko": "Edge 마일스톤 {m} — 156 미만 (취약 세대)",
                   "en": "Edge milestone {m} — below 156 (vulnerable generation)"},
    "v_edge_156": {"ko": "Edge 마일스톤 156 — 세부 Chromium 패치 수준은 디스크에서 확인 불가 (MS 공지 기준). 최신 Edge 유지 필요",
                   "en": "Edge milestone 156 — the exact Chromium patch level is not stored on disk (per Microsoft notices). Keep Edge up to date"},
    "v_edge_ok": {"ko": "Edge 마일스톤 {m} — 최신 세대",
                  "en": "Edge milestone {m} — current generation"},
    "v_old": {"ko": "구세대 취약 빌드 계열 (chromium-1243 이하 상당)",
              "en": "Old-generation vulnerable build (chromium-1243 class or below)"},
    "v_cve": {"ko": "Critical 4건(CVE-2026-118306 등) 수정 빌드 {v} 미만 — 취약",
              "en": "Below the fix build {v} for the four Critical CVEs (CVE-2026-118306 etc.) — vulnerable"},
    "v_behind": {"ko": "최신 안정({v}) 미만 — 업데이트 권장 (벤더 백포트 여부는 별도)",
                 "en": "Behind current stable ({v}) — update recommended (vendor backports aside)"},
    "v_ok": {"ko": "최신 수준", "en": "Up to date"},
    "latest_live": {"ko": "VersionHistory API 실시간", "en": "VersionHistory API (live)"},
    "latest_builtin": {"ko": "내장 기준값", "en": "built-in value"},
    "embed_exact": {"ko": "내장 Chromium 엔진 {v} (CEF 임베드) — 브라우저 기준 미적용. 엔진 교체는 앱 벤더 몫이라 앱 최신 유지가 유일한 조치",
                    "en": "Embedded Chromium engine {v} (CEF) — browser criteria do not apply. Only the app vendor can replace the engine; keep the app updated"},
    "embed_inexact": {"ko": "내장 엔진 마일스톤 {m} (CEF 버전 표기 {v} — 세부 패치 수준은 파일에서 확인 불가) — 앱 최신 유지가 유일한 조치",
                      "en": "Embedded engine milestone {m} (CEF stamp {v} — patch level not readable from files) — keep the app updated"},
    "pw_note": {"ko": " / Playwright 최신 안정(1.64.1)도 아직 1248 고정 — 수정 빌드를 실은 릴리스 미출시(2026-11-04 기준)",
                "en": " / The latest Playwright stable (1.64.1) still pins 1248 — no release with the fix yet (as of 2026-11-04)"},
    "pw_rev": {"ko": " / Playwright 리비전 {rev} <= {mx} (공지 분류상 취약 범위)",
               "en": " / Playwright revision {rev} <= {mx} (inside the announced vulnerable range)"},
    "pw_detail_rev": {"ko": "리비전 {rev}", "en": "revision {rev}"},
    "pw_detail_eng": {"ko": " / 엔진 실측 {v}", "en": " / measured engine {v}"},
    "title": {"ko": "Chromium 계열 브라우저 점검 (Windows/Linux/macOS)",
              "en": "Chromium browser audit (Windows/Linux/macOS)"},
    "criteria": {"ko": "기준: 구세대 취약 <= {a} / CVE 수정 빌드 {b} / 최신 안정 {c} ({src})",
                 "en": "Criteria: old-gen vulnerable <= {a} / CVE fix build {b} / current stable {c} ({src})"},
    "none_found": {"ko": "Chromium 계열 브라우저를 찾지 못했습니다.",
                   "en": "No Chromium-based browsers found."},
    "conclusion": {"ko": "결론 (브라우저별 병합):", "en": "Conclusion (merged per browser):"},
    "merged_n": {"ko": "{n}건 병합", "en": "{n} merged"},
    "summary": {"ko": "집계: 위험 {d} / 주의 {w} / 양호 {o} / 정보 {i}",
                "en": "Summary: DANGER {d} / WARN {w} / OK {o} / INFO {i}"},
    "dropped": {"ko": " / 증거 없어 제외 {n}건", "en": " / {n} dropped (no evidence)"},
    "action_needed": {"ko": "조치 필요: {names}", "en": "Action needed: {names}"},
    "run_update_hint": {"ko": "자동 업데이트 실행: python chromium-audit.py --update (공식 경로가 있는 항목만)",
                        "en": "Run automatic updates: python chromium-audit.py --update (official channels only)"},
    "update_title": {"ko": "자동 업데이트 (공식 경로가 있는 항목만):",
                     "en": "Automatic updates (official channels only):"},
    "no_targets": {"ko": "  업데이트 대상이 없습니다.", "en": "  Nothing to update."},
    "run_label": {"ko": "실행", "en": "run"},
    "updater_launched": {"ko": "  [업데이터 실행] {u}", "en": "  [updater launched] {u}"},
    "updater_fail": {"ko": "  [실패] 업데이터 실행 실패: {u} — {e}",
                     "en": "  [failed] could not launch updater: {u} — {e}"},
    "launched_app": {"ko": "  [실행] 업데이터 파일이 없어 앱을 띄웠습니다 (시작 시 업데이트 확인 기대): {p}",
                     "en": "  [run] no updater file found; launched the app (expecting a startup update check): {p}"},
    "manual_launch_fail": {"ko": "  [수동] {name}: 업데이터를 찾지 못했고 앱 실행도 실패했습니다 — {e}",
                           "en": "  [manual] {name}: no updater found and launching the app failed — {e}"},
    "manual_no_path": {"ko": "  [수동] {name}: 자동 업데이트 경로 없음 — {path} (배포처에서 직접 업데이트)",
                       "en": "  [manual] {name}: no automatic update path — {path} (update from the vendor directly)"},
    "tail_fail": {"ko": "         -> 실패: {e}", "en": "         -> failed: {e}"},
}


def T(key, **fmt):
    s = LSTR[key][LANG]
    return s.format(**fmt) if fmt else s


def detect_lang():
    """Korean on Korean systems, English elsewhere.
    CHROMIUM_AUDIT_LANG wins over the locale."""
    env = (os.environ.get("CHROMIUM_AUDIT_LANG") or "").lower()
    if env.startswith(("ko", "kr")):
        return "ko"
    if env.startswith("en"):
        return "en"
    for var in ("LC_ALL", "LC_MESSAGES", "LANG"):
        v = (os.environ.get(var) or "").lower()
        if v.startswith(("ko", "kr")):
            return "ko"
        if v:
            return "en"
    try:
        loc = (locale.getdefaultlocale()[0] or "").lower()
        if loc.startswith(("ko", "kr")):
            return "ko"
        if loc:
            return "en"
    except Exception:
        pass
    if sys.platform == "win32":
        try:
            import ctypes
            if ctypes.windll.kernel32.GetUserDefaultUILanguage() & 0x3FF == 0x12:
                return "ko"
        except Exception:
            pass
    return "en"


def dname(name):
    """Localized display name for the few internal names containing Korean."""
    if name == "Edge WebView2 (런타임)":
        return T("webview2_name")
    return name


VER4 = re.compile(r"(\d+)\.(\d+)\.(\d+)\.(\d+)")
NAME_HINTS = ("chrom", "brave", "vivaldi", "opera", "whale", "edge", "arc",
              "yandex", "ego", "thorium", "slimjet", "coccoc", "sidekick",
              "wavebox", "browser", "ungoogled", "iridium", "waterfox")

WINGET_IDS = {
    "chrome": "Google.Chrome", "edge": "Microsoft.Edge", "brave": "Brave.Brave",
    "vivaldi": "Vivaldi.Vivaldi", "opera": "Opera.Opera", "whale": "NAVER.Whale",
    "arc": "TheBrowserCompany.Arc",
}
# Family -> winget ID (Windows update routing + attempt deduplication).
# OBS Studio is deliberately absent: its winget route runs the full installer,
# which dies at the UAC prompt (observed). OBS's built-in updater is the
# official path and is reached via the fallback ladder instead.
FAMILY_WINGET = {
    "Chrome": "Google.Chrome", "Edge": "Microsoft.Edge",
    "Edge WebView2 (런타임)": "Microsoft.Edge", "Whale": "NAVER.Whale",
    "Brave": "Brave.Brave", "Vivaldi": "Vivaldi.Vivaldi",
    "Opera": "Opera.Opera",
}
BREW_CASKS = {
    "chrome": "google-chrome", "edge": "microsoft-edge", "brave": "brave-browser",
    "vivaldi": "vivaldi", "opera": "opera", "chromium": "chromium",
}


def vtuple(s):
    m = VER4.search(str(s or ""))
    return tuple(int(x) for x in m.groups()) if m else None


def vstr(t):
    return ".".join(str(x) for x in t) if t else None


def run(cmd, timeout=15):
    try:
        out = subprocess.run(cmd, capture_output=True, encoding="utf-8", timeout=timeout,
                             errors="replace")
        return (out.stdout or "") + (out.stderr or "")
    except Exception:
        return ""


def parse_version_output(text):
    """Extract (product, engine) from --version output.
    Forks like ego that print a separate 'chromium X.Y.Z.W' line win."""
    product, engine = None, None
    for line in (text or "").splitlines():
        m = re.search(r"chromium\D{0,12}?(\d+\.\d+\.\d+\.\d+)", line, re.I)
        if m:
            engine = vtuple(m.group(1))
        if product is None:
            m2 = VER4.search(line)
            if m2:
                product = vtuple(m2.group(0))
    if engine is None:
        engine = product  # families where the product version IS the engine version
    return product, engine


def verdict(engine, family=None, latest=None):
    """Judge an engine version.

    - Edge/WebView2 use their own versioning: only the first component is
      shared with Chromium (the milestone), and the exact patch level is not
      stored on disk, so they are judged by milestone alone.
    - Anything that exposes a true Chromium version (Chrome, Chrome for
      Testing, ego, Playwright pins) is compared with the CVE fix build.
    """
    if latest is None:
        latest = LATEST_STABLE
    if engine is None:
        return "INFO", T("v_noengine")
    if family in ("Edge", "Edge WebView2 (런타임)"):
        major = engine[0]
        if major < 156:
            return "DANGER", T("v_edge_low", m=major)
        if major == 156:
            return "WARN", T("v_edge_156")
        return "OK", T("v_edge_ok", m=major)
    if engine <= VULN_CONFIRMED:
        return "DANGER", T("v_old")
    if engine < CVE_FIXED:
        return "DANGER", T("v_cve", v=vstr(CVE_FIXED))
    if engine < latest:
        return "WARN", T("v_behind", v=vstr(latest))
    return "OK", T("v_ok")


def fetch_latest_stable():
    """Fetch the current stable version from the Chrome VersionHistory API
    (no key required). Falls back to the built-in value on any failure.
    Returns (version_tuple, source_label)."""
    import urllib.request
    plat = {"win32": "win", "darwin": "mac"}.get(sys.platform, "linux")
    url = (f"https://versionhistory.googleapis.com/v1/chrome/platforms/"
           f"{plat}/channels/stable/versions")
    try:
        with urllib.request.urlopen(url, timeout=5) as r:
            data = json.load(r)
        vers = [vtuple(v.get("version", "")) for v in data.get("versions", [])]
        vers = [v for v in vers if v]
        if vers:
            return max(vers), T("latest_live")
    except Exception:
        pass
    return LATEST_STABLE, T("latest_builtin")


# ---------------------------------------------------------------- detection
class Found:
    def __init__(self, name, path, kind, origin=""):
        self.name, self.path, self.kind = name, path, kind
        self.product = None      # tuple
        self.engine = None       # tuple
        self.detail = ""
        self.pw_rev = None       # Playwright revision, when applicable
        self.origin = origin     # known / registry / fingerprint / path / desktop / app
        self.alts = []           # same-group paths folded in by merging
        self.engine_exact = True # False when only the milestone is certain (CEF stamp)

    def key(self):
        try:
            return os.path.realpath(self.path).lower()
        except Exception:
            return self.path.lower()


def version_via_flag(exe):
    out = run([exe, "--version"], timeout=10)
    if not out.strip():
        return None, None
    return parse_version_output(out)


def version_named_subfolder(folder):
    """Find an engine version in a version-named subfolder (e.g. Application/<version>/)."""
    try:
        for name in os.listdir(folder):
            t = vtuple(name)
            if t and t[0] >= 100 and os.path.isdir(os.path.join(folder, name)):
                return t
    except Exception:
        pass
    return None


# ---------------------------------------------------------------- Windows
def win_file_version(path):
    try:
        import ctypes
        from ctypes import wintypes
        ver = ctypes.windll.version
        size = ver.GetFileVersionInfoSizeW(path, None)
        if not size:
            return None
        buf = ctypes.create_string_buffer(size)
        if not ver.GetFileVersionInfoW(path, 0, size, buf):
            return None
        ptr = ctypes.c_void_p()
        ln = ctypes.c_uint()
        if not ver.VerQueryValueW(buf, "\\", ctypes.byref(ptr), ctypes.byref(ln)):
            return None
        arr = ctypes.cast(ptr, ctypes.POINTER(wintypes.DWORD * 13)).contents
        return (arr[2] >> 16, arr[2] & 0xFFFF, arr[3] >> 16, arr[3] & 0xFFFF)
    except Exception:
        return None


def detect_windows():
    found = []
    roots = [os.environ.get("ProgramFiles", ""), os.environ.get("ProgramFiles(x86)", ""),
             os.environ.get("LocalAppData", "")]
    # 1) common install locations
    known = [
        ("Chrome", "Google\\Chrome\\Application\\chrome.exe"),
        ("Edge", "Microsoft\\Edge\\Application\\msedge.exe"),
        ("Whale", "Naver\\Naver Whale\\whale.exe"),
        ("Brave", "BraveSoftware\\Brave-Browser\\Application\\brave.exe"),
        ("Vivaldi", "Vivaldi\\Application\\vivaldi.exe"),
        ("Opera", "Opera\\opera.exe"),
        ("ego", "ego\\ego-browser.exe"), ("ego", "ego\\ego.exe"),
    ]
    for base in roots:
        if not base:
            continue
        for name, rel in known:
            p = os.path.join(base, rel)
            if os.path.isfile(p):
                found.append(Found(name, p, "browser", origin="known"))
    # 2) Uninstall registry sweep — entries whose display name has a browser hint
    try:
        import winreg
        views = [winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY]
        for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
            for view in views:
                try:
                    key = winreg.OpenKey(hive, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                                         0, winreg.KEY_READ | view)
                except OSError:
                    continue
                i = 0
                while True:
                    try:
                        sub = winreg.EnumKey(key, i)
                        i += 1
                    except OSError:
                        break
                    try:
                        sk = winreg.OpenKey(key, sub)
                        disp = winreg.QueryValueEx(sk, "DisplayName")[0]
                        loc = winreg.QueryValueEx(sk, "InstallLocation")[0]
                    except OSError:
                        continue
                    if not disp or not loc or not os.path.isdir(loc):
                        continue
                    low = disp.lower()
                    if not any(h in low for h in NAME_HINTS):
                        continue
                    for dirpath, _dirs, files in os.walk(loc):
                        if dirpath[len(loc):].count(os.sep) > 2:
                            continue
                        for f in files:
                            fl = f.lower()
                            if fl.endswith(".exe") and any(h in fl for h in NAME_HINTS):
                                found.append(Found(disp, os.path.join(dirpath, f), "browser", origin="registry"))
    except ImportError:
        pass
    # 3) fingerprint folders (holding chrome.dll / chrome_elf.dll = Chromium-based)
    for base in roots:
        if not base or not os.path.isdir(base):
            continue
        for vendor in os.listdir(base):
            vdir = os.path.join(base, vendor)
            if not os.path.isdir(vdir):
                continue
            for dirpath, _dirs, files in os.walk(vdir):
                if dirpath[len(base):].count(os.sep) > 4:
                    _dirs[:] = []
                    continue
                low_files = [f.lower() for f in files]
                if "chrome.dll" in low_files or "chrome_elf.dll" in low_files:
                    for f in files:
                        if f.lower().endswith(".exe") and any(h in f.lower() for h in NAME_HINTS):
                            found.append(Found(vendor, os.path.join(dirpath, f), "browser", origin="fingerprint"))
                    _dirs[:] = []
    # 4) executables on PATH (custom forks such as ego)
    for d in os.environ.get("PATH", "").split(os.pathsep):
        if not d or not os.path.isdir(d):
            continue
        for f in os.listdir(d):
            fl = f.lower()
            if fl.endswith(".exe") and any(h in fl for h in NAME_HINTS):
                found.append(Found(os.path.splitext(f)[0], os.path.join(d, f), "browser", origin="path"))
    return found


_CEF_PAT = re.compile(rb"chromium-(\d+\.\d+\.\d+\.\d+)")


def _scan_file_for_chromium(path, limit=450_000_000):
    """Find a 'chromium-A.B.C.D' string in a file's bytes (the CEF runtime stamp)."""
    try:
        if os.path.getsize(path) > limit:
            return None
        tail = b""
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(8 * 1024 * 1024)
                if not chunk:
                    return None
                data = tail + chunk
                m = _CEF_PAT.search(data)
                if m:
                    return vtuple(m.group(1).decode("ascii", "replace"))
                tail = data[-64:]
    except Exception:
        return None


def cef_embedded_version(item):
    """The real Chromium version of a CEF embed, read from the version string
    embedded in the executable itself and in libcef.dll / chrome_elf.dll in
    its install tree. (The CEF stamp in file version info is NOT a Chromium
    version.)"""
    cands = [item.path]
    root = install_root_guess(item.path)
    for dirpath, _dirs, files in os.walk(root):
        if dirpath[len(root):].count(os.sep) > 3:
            _dirs[:] = []
            continue
        for f in files:
            if f.lower() in ("libcef.dll", "chrome_elf.dll"):
                cands.append(os.path.join(dirpath, f))
    for c in cands:
        v = _scan_file_for_chromium(c)
        if v:
            return v
    return None


def inspect_windows(item):
    # Windows inspection never executes the target: an audit must not pop up
    # a browser window per candidate. Only fixed file version info is used;
    # if execution is unavoidable, main tries it once per merged browser,
    # as a last resort.
    fv = win_file_version(item.path)
    if fv and 100 <= fv[0] < 1000:
        item.engine = fv
    elif fv and item.product is None:
        item.product = fv
    if item.engine is None:
        # Estimate from DLL file versions in the app's own tree: chrome.dll
        # first, else the largest DLL carrying an engine version (major >=
        # 100) — this covers forks such as ego. Shared system folders
        # (System32/SysWOW64) are never scanned: their DLLs belong to others.
        folder = os.path.dirname(item.path)
        fl = folder.lower().replace("/", "\\")
        cands = []
        if "\\windows\\system32" not in fl and "\\windows\\syswow64" not in fl:
            for dirpath, _dirs, files in os.walk(folder):
                if dirpath[len(folder):].count(os.sep) > 2:
                    _dirs[:] = []
                    continue
                for f in files:
                    if f.lower().endswith(".dll"):
                        p = os.path.join(dirpath, f)
                        v = win_file_version(p)
                        if v and v[0] >= 100:
                            cands.append((f.lower() == "chrome.dll", os.path.getsize(p), v, p))
        if cands:
            cands.sort(key=lambda c: (c[0], c[1]), reverse=True)
            item.engine = cands[0][2]
    if item.engine is None:
        item.engine = version_named_subfolder(os.path.dirname(item.path))
    # For CEF embeds the file version is only a CEF stamp, so look for the
    # real Chromium version string embedded in the binaries. If it is not
    # found, mark the engine as milestone-only.
    p_low = item.path.lower().replace("\\", "/")
    base_low = os.path.basename(item.path).lower()
    if "cef" in base_low or "obs-browser" in p_low:
        exact = cef_embedded_version(item)
        if exact:
            item.engine = exact
            item.engine_exact = True
        elif item.engine:
            item.engine_exact = False
    if item.product is None:
        item.product = item.engine


# ---------------------------------------------------------------- Linux
def detect_linux():
    found = []
    names = ["google-chrome", "google-chrome-stable", "chromium", "chromium-browser",
             "brave-browser", "brave", "vivaldi", "opera", "microsoft-edge",
             "microsoft-edge-stable", "whale", "naver-whale", "ego-browser", "ego",
             "thorium-browser", "ungoogled-chromium", "slimjet", "yandex-browser",
             "coccoc", "arc", "sidekick"]
    for n in names:
        p = shutil.which(n)
        if p:
            found.append(Found(n, p, "browser"))
    # Exec lines in .desktop files
    desk_dirs = ["/usr/share/applications", os.path.expanduser("~/.local/share/applications"),
                 "/var/lib/flatpak/exports/share/applications",
                 os.path.expanduser("~/.local/share/flatpak/exports/share/applications")]
    for d in desk_dirs:
        if not os.path.isdir(d):
            continue
        for f in os.listdir(d):
            if not f.endswith(".desktop"):
                continue
            try:
                txt = open(os.path.join(d, f), encoding="utf-8", errors="replace").read()
            except Exception:
                continue
            m = re.search(r"^Exec=(\S+)", txt, re.M)
            nm = re.search(r"^Name=(.+)$", txt, re.M)
            if m and any(h in (m.group(1) + (nm.group(1) if nm else "")).lower() for h in NAME_HINTS):
                exe = m.group(1).strip('"')
                if os.path.isfile(exe):
                    found.append(Found(nm.group(1) if nm else f, exe, "browser"))
    # flatpak / snap
    out = run(["flatpak", "list", "--app", "--columns=application"], timeout=10)
    for line in out.splitlines():
        if any(h in line.lower() for h in NAME_HINTS):
            found.append(Found(line.strip(), "flatpak:" + line.strip(), "flatpak"))
    out = run(["snap", "list"], timeout=10)
    for line in out.splitlines()[1:]:
        parts = line.split()
        if parts and any(h in parts[0].lower() for h in NAME_HINTS):
            found.append(Found(parts[0], "snap:" + parts[0], "snap"))
    # under /opt
    if os.path.isdir("/opt"):
        for d in os.listdir("/opt"):
            full = os.path.join("/opt", d)
            if os.path.isdir(full) and any(h in d.lower() for h in NAME_HINTS):
                for f in os.listdir(full):
                    if f.endswith((".sh",)) or os.access(os.path.join(full, f), os.X_OK):
                        if any(h in f.lower() for h in NAME_HINTS):
                            found.append(Found(d, os.path.join(full, f), "browser"))
    return found


def inspect_linux(item):
    if item.kind == "flatpak":
        app = item.path.split(":", 1)[1]
        out = run(["flatpak", "info", app], timeout=10)
        m = re.search(r"Version:\s*(\S+)", out)
        item.product = vtuple(m.group(1)) if m else None
        item.engine = item.product
        return
    if item.kind == "snap":
        out = run(["snap", "info", item.path.split(":", 1)[1]], timeout=10)
        m = re.search(r"installed:\s*(\S+)", out)
        item.product = vtuple(m.group(1)) if m else None
        item.engine = item.product
        return
    prod, eng = version_via_flag(item.path)
    item.product, item.engine = prod, eng
    if item.engine is None:
        item.engine = version_named_subfolder(os.path.dirname(item.path))


# ---------------------------------------------------------------- macOS
def detect_macos():
    found = []
    import plistlib
    for base in ("/Applications", os.path.expanduser("~/Applications"), "/System/Applications"):
        if not os.path.isdir(base):
            continue
        for name in os.listdir(base):
            if not name.endswith(".app"):
                continue
            app = os.path.join(base, name)
            plist_path = os.path.join(app, "Contents", "Info.plist")
            try:
                with open(plist_path, "rb") as fh:
                    pl = plistlib.load(fh)
            except Exception:
                continue
            exe = pl.get("CFBundleExecutable", "")
            exe_path = os.path.join(app, "Contents", "MacOS", exe)
            # Chromium fingerprint: a *Framework.framework / Chromium name under Frameworks
            fw_dir = os.path.join(app, "Contents", "Frameworks")
            is_chromium = False
            eng = None
            if os.path.isdir(fw_dir):
                for fw in os.listdir(fw_dir):
                    if "hromium" in fw or "Chrome" in fw or "Electron" in fw:
                        is_chromium = True
                        vers = os.path.join(fw_dir, fw, "Versions")
                        if os.path.isdir(vers):
                            for v in os.listdir(vers):
                                t = vtuple(v)
                                if t and t[0] >= 100:
                                    eng = t
            label = name[:-4]
            if is_chromium or any(h in label.lower() for h in NAME_HINTS):
                it = Found(label, exe_path if os.path.isfile(exe_path) else app, "browser")
                it.product = vtuple(pl.get("CFBundleShortVersionString", ""))
                it.engine = eng
                found.append(it)
    return found


def inspect_macos(item):
    if item.engine is None and os.path.isfile(item.path):
        prod, eng = version_via_flag(item.path)
        item.product = item.product or prod
        item.engine = eng


# ---------------------------------------------------------------- Playwright
def detect_playwright():
    found = []
    roots = []
    env = os.environ.get("PLAYWRIGHT_BROWSERS_PATH")
    if env and env != "0":
        roots.append(env)
    home = os.path.expanduser("~")
    roots += [os.path.join(home, ".cache", "ms-playwright"),
              os.path.join(home, "AppData", "Local", "ms-playwright"),
              os.path.join(home, "Library", "Caches", "ms-playwright")]
    for root in dict.fromkeys(roots):
        if not os.path.isdir(root):
            continue
        for name in sorted(os.listdir(root)):
            m = re.fullmatch(r"chromium(?:_headless_shell)?-(\d+)", name)
            if not m:
                continue
            rev = int(m.group(1))
            base = os.path.join(root, name)
            exe = None
            for dirpath, _d, files in os.walk(base):
                for f in files:
                    if f in ("chrome", "chrome.exe", "headless_shell", "headless_shell.exe",
                             "chrome-headless-shell", "chrome-headless-shell.exe") or \
                       (f == "Chromium" and "MacOS" in dirpath):
                        exe = os.path.join(dirpath, f)
                        break
                if exe:
                    break
            it = Found(f"Playwright {name}", exe or base, "playwright")
            it.pw_rev = rev
            it.detail = T("pw_detail_rev", rev=rev)
            if exe:
                _p, eng = version_via_flag(exe)
                if eng:
                    it.engine = eng
                    it.detail += T("pw_detail_eng", v=vstr(eng))
            found.append(it)
    return found


# ---------------------------------------------------------------- updates
def install_root_guess(path):
    """Guess the install root by climbing to just below Program Files/AppData."""
    d = os.path.dirname(os.path.abspath(path))
    stops = ("program files", "program files (x86)", "local", "roaming", "programs")
    while True:
        parent = os.path.dirname(d)
        if not parent or parent == d or os.path.basename(parent).lower() in stops:
            return d
        d = parent


def find_updater_exes(root, exclude_path=None):
    """Find executables with 'updat' in the name under the install root.

    Uninstallers, installers and redistributables are excluded (running an
    installer dies at the UAC prompt — observed in practice).
    """
    bad = ("unins", "uninstall", "setup", "install", "redist", "crashpad")
    found = []
    for dirpath, _dirs, files in os.walk(root):
        if dirpath[len(root):].count(os.sep) > 4:
            _dirs[:] = []
            continue
        for f in files:
            fl = f.lower()
            if fl.endswith(".exe") and "updat" in fl and not any(b in fl for b in bad):
                p = os.path.join(dirpath, f)
                if exclude_path and os.path.abspath(p) == os.path.abspath(exclude_path):
                    continue
                found.append(p)
    found.sort(key=lambda p: (len(p), p.lower()))
    return found


def try_update(item, dry_log):
    """Run only official update paths. Returns the commands that ran."""
    cmds = []
    name_low = item.name.lower()
    if item.kind == "playwright":
        cmds = [[sys.executable, "-m", "pip", "install", "-U", "playwright"],
                [sys.executable, "-m", "playwright", "install", "chromium"]]
    elif sys.platform == "win32":
        # Route by family only (substring matching on names misfires, e.g.
        # Search -> Arc). OBS Studio is absent from FAMILY_WINGET on purpose
        # (its winget route runs the full installer and dies at UAC).
        fam = family_of(item) or ""
        wid = FAMILY_WINGET.get(fam)
        if wid and shutil.which("winget"):
            cmds.append(["winget", "upgrade", "--id", wid, "--silent",
                         "--accept-package-agreements", "--accept-source-agreements"])
        # The winget catalog can lag, so wake the vendor updater too
        pf86 = os.environ.get("ProgramFiles(x86)", "")
        pf = os.environ.get("ProgramFiles", "")
        ups = []
        if fam == "Chrome":
            ups = [os.path.join(pf86, "Google", "Update", "GoogleUpdate.exe"),
                   os.path.join(pf, "Google", "Update", "GoogleUpdate.exe")]
        elif fam in ("Edge", "Edge WebView2 (런타임)"):
            ups = [os.path.join(pf86, "Microsoft", "EdgeUpdate", "MicrosoftEdgeUpdate.exe"),
                   os.path.join(pf, "Microsoft", "EdgeUpdate", "MicrosoftEdgeUpdate.exe")]
        for u in ups:
            if u and os.path.isfile(u):
                cmds.append([u, "/ua", "/installsource", "scheduler"])
                break
        if not cmds:
            # Last resort: run an updater-looking executable from the install
            # folder. If there is none, launch the app itself so its startup
            # update check runs. Only when even that fails, report manual.
            root = install_root_guess(item.path)
            ups_found = find_updater_exes(root, exclude_path=item.path)
            if ups_found:
                for u in ups_found[:2]:
                    try:
                        subprocess.Popen([u], cwd=os.path.dirname(u))
                        dry_log.append(T("updater_launched", u=u))
                    except Exception as e:
                        dry_log.append(T("updater_fail", u=u, e=e))
                return []
            launch = item.path
            if fam == "OBS Studio":
                cand = os.path.join(root, "bin", "64bit", "obs64.exe")
                if os.path.isfile(cand):
                    launch = cand
            try:
                subprocess.Popen([launch], cwd=os.path.dirname(launch))
                dry_log.append(T("launched_app", p=launch))
            except Exception as e:
                dry_log.append(T("manual_launch_fail", name=item.name, e=e))
            return []
    elif sys.platform == "darwin":
        for key, cask in BREW_CASKS.items():
            if key in name_low:
                cmds = [["brew", "upgrade", "--cask", cask]]
                break
    elif item.kind == "flatpak":
        cmds = [["flatpak", "update", "-y", item.path.split(":", 1)[1]]]
    elif item.kind == "snap":
        cmds = [["snap", "refresh", item.path.split(":", 1)[1]]]
    if not cmds:
        dry_log.append(T("manual_no_path", name=item.name, path=item.path))
        return []
    done = []
    for c in cmds:
        dry_log.append(f"  [{T('run_label')}] {' '.join(c)}")
        try:
            r = subprocess.run(c, capture_output=True, encoding="utf-8", timeout=600, errors="replace")
            done.append(" ".join(c))
            tail = (r.stdout or "").strip().splitlines()
            if tail:
                dry_log.append(f"         -> {tail[-1][:120]}")
        except Exception as e:
            dry_log.append(T("tail_fail", e=e))
    return done


def family_of(it):
    """Browser family (display name) from the executable/path. None if unknown."""
    p = it.path.lower().replace("\\", "/")
    base = p.rsplit("/", 1)[-1]
    if "msedgewebview2" in base or "/edgewebview/" in p:
        return "Edge WebView2 (런타임)"
    if base.startswith("msedge") or "/microsoft/edge/" in p:
        return "Edge"
    if base.startswith("chrome") or "/google/chrome/" in p:
        return "Chrome"
    if "whale" in base:
        return "Whale"
    if base.startswith("ego"):
        return "ego"
    if "brave" in base:
        return "Brave"
    if "vivaldi" in base:
        return "Vivaldi"
    if "opera" in base:
        return "Opera"
    if "obs" in base or "/obs-studio/" in p:
        return "OBS Studio"
    return None


def is_embed(it):
    """Is this an app embedding Chromium rather than a browser (OBS browser
    sources, Hancom CEF, ...)?

    Users cannot upgrade an embedded engine the way they update a browser —
    only the app vendor can, by shipping a new app version. Judging embeds
    by browser criteria would flag a fully updated app as dangerous forever,
    so embeds are reported separately, as INFO.
    """
    if it.kind != "browser":
        return False
    base = os.path.basename(it.path).lower()
    p = it.path.lower().replace("\\", "/")
    return (family_of(it) == "OBS Studio" or "cef" in base
            or "obs-browser" in p or "libcef" in p)


def normalize_and_gate(items):
    """Engine-version sanity + evidence gate.

    - A value whose major is outside 100-999 is not an engine version, even
      if it came from file version info; demote it to product version (this
      stops false positives like Windows system files 11.0.x, OBS 32.x).
    - Candidates found by name alone on PATH (origin=path) are dropped
      unless they produced valid engine evidence.
    Returns (kept, dropped_count).
    """
    kept, dropped = [], 0
    for it in items:
        if it.engine and not (100 <= it.engine[0] < 1000):
            if it.product is None:
                it.product = it.engine
            it.engine = None
        if it.kind == "browser" and it.origin == "path" and it.engine is None:
            dropped += 1
            continue
        kept.append(it)
    return kept, dropped


def collapse_versions(items):
    """Fold one browser's leftover old-version folders and helper binaries
    into a single item.
    - A version-number parent folder means the folder above it is the root
    - Within a group, the highest engine version wins
    - msedgewebview2.exe is reported separately as a runtime, not a browser"""
    def root_of(it):
        d = os.path.dirname(it.path)
        base = os.path.basename(d)
        if vtuple(base) and len(base.split(".")) == 4:
            return os.path.dirname(d).lower()
        return d.lower()

    groups = {}
    for it in items:
        if it.kind != "browser":
            groups.setdefault(("solo", it.key()), []).append(it)
            continue
        fam = family_of(it)
        name = (fam or it.name).lower()
        groups.setdefault((name, root_of(it)), []).append(it)
    out = []
    for g in groups.values():
        g.sort(key=lambda x: (x.engine or (0, 0, 0, 0), -len(x.path)), reverse=True)
        winner = g[0]
        if winner.product is None:
            for x in g:
                if x.product is not None:
                    winner.product = x.product
                    break
        fam = family_of(winner)
        if fam:
            winner.name = fam
        winner.alts = [x.path for x in g if x.path != winner.path]
        out.append(winner)
    return out


# ---------------------------------------------------------------- main
def main():
    global LANG
    ap = argparse.ArgumentParser(
        description="chromium-audit -- audit all Chromium-based browsers")
    ap.add_argument("--update", action="store_true",
                    help="also update items that have an official update path")
    ap.add_argument("--json", action="store_true", help="print JSON")
    ap.add_argument("--lang", choices=("auto", "ko", "en"), default="auto",
                    help="output language (default: auto-detect)")
    args = ap.parse_args()
    LANG = detect_lang() if args.lang == "auto" else args.lang

    if sys.platform == "win32":
        items, inspect = detect_windows(), inspect_windows
    elif sys.platform == "darwin":
        items, inspect = detect_macos(), inspect_macos
    else:
        items, inspect = detect_linux(), inspect_linux
    items += detect_playwright()

    helper_pat = re.compile(r"crashpad|_handler|notification|elevation|uninstall|setup|updater|"
                            r"_update|helper|proxy|pwa_launcher|stub|broker")
    uniq, seen = [], set()
    for it in items:
        if it.kind == "browser" and helper_pat.search(os.path.basename(it.path).lower()):
            continue  # helper binaries are not the browser itself
        k = it.key()
        if k not in seen:
            seen.add(k)
            uniq.append(it)
    for it in uniq:
        if it.kind not in ("playwright",):
            inspect(it)
    uniq, dropped = normalize_and_gate(uniq)
    uniq = collapse_versions(uniq)

    if sys.platform == "win32":
        # Last resort: only for merged representatives that still have no
        # engine after static inspection, run --version once per group path
        # (bounded per browser).
        for it in uniq:
            if it.kind == "browser" and it.engine is None:
                for p in [it.path] + list(getattr(it, "alts", [])):
                    prod, eng = version_via_flag(p)
                    if eng:
                        it.engine = eng
                        if it.product is None:
                            it.product = prod
                        break

    latest, latest_src = fetch_latest_stable()

    rows = []
    worst = 0
    for it in uniq:
        level, why = verdict(it.engine, family_of(it), latest)
        if is_embed(it) and it.engine:
            level = "INFO"
            if it.engine_exact:
                why = T("embed_exact", v=vstr(it.engine))
            else:
                why = T("embed_inexact", m=it.engine[0], v=vstr(it.engine))
        if it.pw_rev is not None and it.pw_rev <= PLAYWRIGHT_VULN_MAX:
            why += T("pw_note")
            if level == "OK":
                level = "WARN"
            why += T("pw_rev", rev=it.pw_rev, mx=PLAYWRIGHT_VULN_MAX)
        if level in ("DANGER", "WARN"):
            worst = 1
        rows.append({
            "name": it.name, "path": it.path, "kind": it.kind,
            "product": vstr(it.product), "engine": vstr(it.engine),
            "level": level, "why": why, "detail": it.detail,
        })

    if args.json:
        print(json.dumps(rows, ensure_ascii=False, indent=2))
    else:
        print("=" * 72)
        print(T("title"))
        print(T("criteria", a=vstr(VULN_CONFIRMED), b=vstr(CVE_FIXED),
                c=vstr(latest), src=latest_src))
        print("=" * 72)
        if not rows:
            print(T("none_found"))
        mark = {"DANGER": T("lvl_danger"), "WARN": T("lvl_warn"),
                "OK": T("lvl_ok"), "INFO": T("lvl_info")}
        for r in rows:
            print(f"{mark[r['level']]} {dname(r['name'])} — {T('engine_w')} "
                  f"{r['engine'] or T('unknown')} / {T('product_w')} {r['product'] or '-'}")
            print(f"       {r['path']}")
            print(f"       {r['why']}" + (f" / {r['detail']}" if r['detail'] else ""))
        if rows:
            print("-" * 72)
            print(T("conclusion"))
            order = {"DANGER": 0, "WARN": 1, "INFO": 2, "OK": 3}
            fams = {}
            for it, r in zip(uniq, rows):
                f = fams.setdefault(r["name"], {"rows": [], "engines": []})
                f["rows"].append(r)
                if it.engine:
                    f["engines"].append(it.engine)
            for name, f in sorted(fams.items(),
                                  key=lambda kv: min(order[x["level"]] for x in kv[1]["rows"])):
                lvl = min(f["rows"], key=lambda x: order[x["level"]])["level"]
                eng = vstr(max(f["engines"])) if f["engines"] else T("unknown")
                print(f"  {mark[lvl]} {dname(name)} — {T('engine_w')} {eng} / "
                      f"{T('merged_n', n=len(f['rows']))}")
            counts = {k: sum(1 for r in rows if r["level"] == k) for k in mark}
            tail = T("dropped", n=dropped) if dropped else ""
            print(T("summary", d=counts["DANGER"], w=counts["WARN"],
                    o=counts["OK"], i=counts["INFO"]) + tail)
            need = [n for n, f in fams.items()
                    if any(x["level"] in ("DANGER", "WARN") for x in f["rows"])]
            if need and not args.update:
                print(T("action_needed", names=", ".join(dname(n) for n in need)))
                print(T("run_update_hint"))

    if args.update and rows:
        print("-" * 72)
        print(T("update_title"))
        log = []
        attempted = set()
        for it, r in zip(uniq, rows):
            if r["level"] in ("DANGER", "WARN"):
                if it.kind == "browser":
                    fam = family_of(it) or it.name
                    # Families sharing one winget ID (Edge + WebView2) are tried once
                    key = FAMILY_WINGET.get(fam) or fam
                    if key in attempted:
                        continue
                    attempted.add(key)
                try_update(it, log)
        print("\n".join(log) if log else T("no_targets"))

    if not rows:
        return 2
    return worst


if __name__ == "__main__":
    sys.exit(main())
