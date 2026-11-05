# chromium-audit

**내 PC에 깔린, Chromium 엔진으로 만들어진 모든 프로그램을 찾아내, 2026-10-13부터 2026-11-03까지 Google이 낸 Stable 패치 웨이브 6개의 치명적(Critical) 취약점 27건(CVE-2026-118306, CVSS 9.6 포함)의 영향권인지 하나씩 확인하고, 업데이트 가능한 것은 업데이트까지 해주는 도구입니다. 명령 한 번이면 됩니다.**

English: [README.md](README.md)

---

## 핵심 요약

**무엇을 대상으로 하나.** 2026-10-13부터 2026-11-03까지 Google이 낸 데스크톱 Stable 패치 웨이브 6개의 치명적(Critical) 취약점입니다. 보안 수정 686건 중 Critical이 27건입니다. 각 웨이브의 수정 빌드보다 오래된 Chromium 엔진은 그 웨이브의 Critical에 그대로 노출되며, 여기에는 구형 Chrome 빌드, 153 세대 이하 전체, 그 빌드들을 기반으로 한 모든 포크, 그리고 다른 앱 속에 내장된 엔진까지 전부 포함됩니다. 엔진마다 어떤 웨이브(CVE)가 빠져 있는지를 목록으로 알려줍니다.

**무엇을 찾아내나.** 아는 브라우저만이 아니라, 내 컴퓨터에서 Chromium 엔진으로 돌아가는 *전부*입니다.

- 독립 브라우저: Chrome, Edge, Brave, Vivaldi, Opera, NAVER Whale, Arc, Chromium, 그리고 잘 알려지지 않은 포크들;
- 많은 Windows 앱이 공유하는 Edge WebView2 런타임;
- 다른 프로그램 *속에 내장된* Chromium 엔진 (CEF/Electron) — OBS Studio의 브라우저 소스, 오피스 프로그램, 메신저 등, 업데이트를 잊기 쉬운 바로 그 사본들;
- Playwright 같은 개발 도구가 고정해 쓰는 브라우저 빌드 (버전 참고용으로만 표시 — 배경의 주석 참조).

사본마다 버전이 다르고 업데이트 경로도 달라서, 내장된 것일수록 잊히기 쉽습니다.

**무엇을 하나.** 찾아낸 사본마다 앱이 표시하는 버전이 아니라 디스크에서 **실제 엔진 버전**을 읽고, 어떤 것이 영향권인지 알기 쉽게 알려주며, `--update`를 주면 **공식 업데이트 경로로만** 업데이트합니다. 출력 언어는 자동입니다 — 한국어 시스템에서는 한국어, 그 외에는 영어로 나오고 `--lang`으로 강제할 수 있습니다.

## 빠른 시작

**Windows** — `run.bat`을 더블클릭하세요 (Python이 없으면 설치까지 해주고, 이어서 점검을 실행합니다):

```
run.bat            점검만
run.bat --update   점검 + 업데이트
```

**Linux / macOS:**

```sh
chmod +x run.sh
./run.sh            # 점검만
./run.sh --update   # 점검 + 업데이트
```

**Python 3.8 이상이 이미 있다면 어디서든:**

```sh
python3 chromium-audit.py            # 점검만
python3 chromium-audit.py --update   # 점검 + 업데이트
python3 chromium-audit.py --json     # 기계 판독용 출력
python3 chromium-audit.py --lang en  # 출력 언어: auto(기본) / ko / en
```

의존성은 없습니다. Python 표준 라이브러리만 사용합니다.

## 무엇을 점검하나

| 대상 | 예시 | 엔진 버전을 얻는 방법 |
|---|---|---|
| 독립 브라우저 | Chrome, Edge, Brave, Vivaldi, Opera, NAVER Whale, Arc, Chromium, Thorium, ego lite 같은 포크 | 파일 버전 정보, 버전 이름 폴더, 패키지/레지스트리 기록 |
| 내장 Chromium (CEF) | OBS Studio 브라우저 소스, 한컴오피스, 기타 CEF 앱 | `libcef.dll`·호스트 실행 파일에 박힌 버전 문자열 |
| Edge WebView2 런타임 | 많은 Windows 앱이 공유하는 상시 업데이트 런타임 | 레지스트리 + 설치 폴더; 마일스톤으로 판정 (아래 참조) |
| Playwright 브라우저 | Playwright 캐시의 `chromium-1243`, `chromium-1248`, 헤드리스 셸 | 폴더 리비전 + 내장 바이너리의 실제 버전 |

탐지는 **고정된 이름 목록이 아니라 특징 기반**입니다. 설치 기록, `PATH`, Chromium 지문 파일(`chrome.dll`, `chrome_elf.dll`, Chromium 프레임워크), 버전 출력까지 사용하므로 목록에 없는 포크도 찾아내고, 반대로 이름에 "browser"만 들어간 무관한 프로그램은 증거 게이트에서 걸러냅니다.

## 결과 읽는 법

각 브라우저는 **제품당 한 줄**로 병합되어 표시됩니다 (구버전 폴더와 보조 실행 파일은 접어 넣음). 뒤에는 병합된 결론이 붙습니다.

| 등급 | 의미 |
|---|---|
| **[위험]** | 패치 웨이브가 하나라도 빠져 있는 엔진입니다. 빠져 있는 웨이브와 그 Critical CVE를 항목 아래에 목록으로 표시합니다. 지금 업데이트하세요. |
| **[주의]** | 알려진 패치 웨이브는 전부 적용됐지만 현재 안정 버전보다 뒤처졌거나, Edge/WebView2 마일스톤 156처럼 디스크에서 세부 패치 수준을 읽을 수 없는 경우. |
| **[정보]** | 엔진 버전을 확정하지 못했거나, *내장* 엔진인 경우 (아래 "내장 엔진" 참조). |
| **[양호]** | 최신 상태입니다. |

종료 코드: `0` = 조치 불필요, `1` = 업데이트 필요한 항목 있음, `2` = 아무것도 찾지 못함.

## 업데이트 (`--update`)가 하는 일

[위험]·[주의] 항목마다 다음 순서로 시도합니다.

1. **공식 경로** — Windows 브라우저는 `winget` → 실패하거나 없으면 벤더 자체 업데이터(`GoogleUpdate.exe`, `MicrosoftEdgeUpdate.exe` 등), macOS는 Homebrew cask, Linux는 flatpak/snap (apt/dnf/pacman 시스템은 무단 승격 대신 실행할 명령을 안내).
2. **앱 자체 업데이터 파일** — 설치 폴더에 업데이터 실행 파일이 있으면 그것을 실행 (인스톨러와 언인스톨러는 절대 실행하지 않음).
3. **앱 직접 실행** — 많은 앱이 시작할 때 업데이트를 확인합니다.
4. 여기까지 전부 실패한 항목만 **수동**으로 보고합니다 (경로 포함).

**절대 하지 않는 것:** 비공식 출처에서 바이너리를 내려받지 않고, 프로그램 파일을 직접 패치하거나 교체하지 않으며, 정체를 특정하지 못한 항목은 건드리지 않습니다. OBS Studio는 winget으로 업데이트하지 않습니다. 그 경로는 전체 인스톨러를 실행하는데 Windows 관리자 확인창(UAC)에서 죽는 것이 실측됐기 때문입니다. OBS는 2~3단계, 즉 자체 내장 업데이터로 처리합니다.

## 요구 사항

- Python 3.8 이상 (없으면 실행 파일이 설치해줍니다: Windows는 winget, macOS는 Homebrew, Linux는 사용 중인 패키지 매니저).
- Windows 10/11, macOS, Linux. 관리자 권한은 업데이트 경로 자체가 요구할 때만 필요합니다.

---

## 배경: 2026년 10~11월 Chromium 취약점

### 지금까지 알려진 사실 (2026-11-05 기준)

**2026-10-27**, Google의 *Chrome Releases* 블로그("Stable Channel Update for Desktop")가 보안 수정 52건(Critical 4, High 46, Medium 2)을 담은 Chrome **156.0.8078.73/.74**(Windows/Mac), **156.0.8078.73**(Linux)을 배포했습니다. Critical 4건은 전부 Anthropic 소속 연구자 한 명이 신고한 것입니다.

| CVE | 구성 요소 | CVSS (CISA/NVD) | 비고 |
|---|---|---|---|
| CVE-2026-118306 | FileSystem | **9.6** | 스코프 변경 벡터 — 샌드박스 탈출 계열. 설명 문구는 출처마다 다름("use after free" vs "메모리 손상"). |
| CVE-2026-118331 | FileAPI | 8.8 | 검증 불충분 / use-after-free (출처마다 다름). |
| CVE-2026-118348 | Skia | 8.8 | 정수 오버플로 / 부적절한 검증 (출처마다 다름). |
| CVE-2026-118344 | Layout | 8.8 | Use after free (출처 일치). |

Google은 CVSS를 공개하지 않습니다. 위 점수는 NVD를 통해 CISA ADP가 매긴 것입니다.

**결론:** **156.0.8078.73보다 오래된 모든 Chromium 엔진**에 취약한 코드가 들어 있습니다. 여기에는 다음이 포함됩니다.

- 2026-10-27 릴리스 이전의 Chrome/Chromium 빌드, 그리고 153 세대 이하 전체.
- Chromium ≤ 156.0.8078.72를 기반으로 만든 포크와 내장 엔진들.

### 웨이브 전체 사다리 (2026-10-13 – 2026-11-03)

2026-10-27 업데이트는 3주 동안 나온 데스크톱 Stable 업데이트 **여섯 개 중 하나**입니다. 이 도구는 여섯 개 전부를 기준으로 판정합니다. 엔진이 어떤 웨이브의 수정 빌드보다 낮으면 그 웨이브가 빠져 있는 것입니다.

| 날짜 | 첫 수정 빌드 | 수정 건수 | Critical | Critical CVE (구성 요소) |
|---|---|---|---|---|
| 2026-10-13 | 155.0.8059.79 | 37 | 7 | CVE-2026-110152 (ANGLE), CVE-2026-110149 (Browser), CVE-2026-110136 (PDF), CVE-2026-110161 (Network), CVE-2026-110165 (Core), CVE-2026-110148 (SVG), CVE-2026-110151 (Media) |
| 2026-10-15 | 155.0.8059.84 | 10 | 1 | CVE-2026-110922 (Prerender) |
| 2026-10-20 | 156.0.8078.47 | 353 | 7 | CVE-2026-120931 (WebGL), CVE-2026-113341 (Skia), CVE-2026-113279 (Accessibility), CVE-2026-113072 (CSS), CVE-2026-113280 (Paint), CVE-2026-113271 (Accessibility), CVE-2026-113303 (WebRTC) |
| 2026-10-27 | 156.0.8078.73 | 52 | 4 | CVE-2026-118306 (FileSystem), CVE-2026-118331 (FileAPI), CVE-2026-118348 (Skia), CVE-2026-118344 (Layout) |
| 2026-10-29 | 156.0.8078.79 | 21 | 1 | CVE-2026-76024 (MediaStream) |
| 2026-11-03 | 157.0.8103.38 | 213 | 7 | CVE-2026-121156 (Dawn), CVE-2026-121247 (Dawn), CVE-2026-121229 (ANGLE), CVE-2026-121246 (WebGL), CVE-2026-121035 (Prerender), CVE-2026-121203 (Geometry), CVE-2026-121126 (Core) |

합계: 수정 686건, Critical 27건. 모든 수치는 Chrome Releases의 "Stable Channel Update for Desktop" 공지 기준입니다.

### "Playwright가 취약하다"는 제목에 대해

"Playwright chromium-1248 이하는 취약하다"고 말하는 공식 공지는 없습니다. 그 주장은 두 사실 — Critical 4건이 156.0.8078.73에서 수정됐다는 것과, Playwright 1.64.0 / 1.64.1이 chromium-1248 = Chromium 156.0.8078.4를 고정한다는 것 (구버전 chromium-1243 = 153.0.8010.12, Playwright 1.63.0) — 을 제3자(S5 Labs의 패치 체크리스트, 2026-10-28 등)가 연결한 내용이 SNS에 퍼진 것입니다. Playwright는 2026-11-03에 이를 공식 반박했습니다: 패키지 자체는 브라우저를 포함하지 않고, MCP/CLI는 사용자 PC에 설치된 Chrome/Edge를 구동하며, 고정 빌드를 쓰는 것은 테스트 러너뿐이라는 것입니다.

그래서 이 도구는 Playwright를 걸지 않습니다. 캐시 빌드는 버전을 참고용으로 표시만 할 뿐, 판정도 업데이트도 하지 않습니다. 고정 빌드가 수정 빌드보다 낮다는 것은 사실이지만, 거기서 "Playwright 자체가 취약하다"로 가는 것은 반박된 비약입니다.

- Chrome **157.0.8103.38/.39**는 **2026-11-03** 정식 안정판이 됐고 (보안 수정 213건, Critical 7건), 이 도구의 "현재 안정" 기준입니다 — 코드에 고정된 값이 아니라 실행할 때 실시간으로 가져옵니다 (아래 참조).

## 버전 번호는 벤더끼리 비교할 수 없습니다

이 도구의 판정 로직 뒤에 있는 가장 중요한 기술적 사실: **디스크에 실제 Chromium 버전을 찍어두는 것은 Chrome 본가(와 Playwright 포함 Chrome-for-Testing 빌드)뿐입니다.** 나머지 벤더는 전부 자기 제품 버전을 찍습니다.

| 제품 | 파일 버전의 의미 | 이 도구의 판정 |
|---|---|---|
| Chrome / Chrome for Testing | 실제 Chromium 버전 | 패치 웨이브 수정 빌드들과 직접 비교 |
| ego lite 등 `chromium X.Y.Z.W`를 출력하는 포크 | 실제 Chromium 버전 (`--version` 출력 또는 고정 버전 정보) | 직접 비교 (같은 웨이브 사다리) |
| **Edge / WebView2** | Microsoft 자체 번호 체계. 공유되는 것은 첫 자리뿐: Edge 156.0.4314.58 = Chromium **마일스톤 156**. "4314"는 Chromium의 "8078"과 산술적 관계가 없습니다. 정확한 Chromium 패치 기반은 **디스크 어디에도 저장돼 있지 않고**, Microsoft 릴리스 노트 / 보안 업데이트 가이드에만 있습니다. | **마일스톤만으로 판정**: 156 미만 → 위험; 156 → 주의 (세부 패치는 로컬에서 알 수 없음); 157 이상 → 양호 |
| Brave, Vivaldi, Opera, Whale, Arc | 벤더 제품 버전. Chromium 기반은 벤더 변경 로그에만 문서화 (예: Brave "v1.98.63 (Chromium 156.0.8078.80)") | 실제 Chromium 버전을 확정할 수 없으면 [정보]; 업데이트는 공식 경로로 제공 |
| CEF 내장 (OBS, 한컴 등) | `libcef.dll`의 파일 버전은 Chromium 버전이 아니라 **CEF 버전 스탬프** (형식 `X.Y.Z+g<해시>+chromium-A.B.C.D`, X = Chromium 메이저). 실측된 OBS 스탬프: `127.145.7.0`, `150.0.20.0` | 바이너리에 박힌 버전 문자열에서 실제 Chromium 버전을 읽음 (예: OBS의 CEF 런타임 = Chromium 127.0.6533.120). 스탬프만 있으면 마일스톤만 확정된 것으로 취급 |
| Electron 앱 | 메인 실행 파일의 파일 버전은 *앱* 버전으로 덮어써짐. 매핑(Electron 45.x → Chromium 156.0.8078.80 등)은 releases.electronjs.org에 릴리스별로 공개 | 지문·문자열로 탐지되는 경우 내장 Chrome 버전 문자열로 판정 |

이 설계가 존중하는 주의 사항 두 가지:

- **백포트.** Vivaldi 같은 벤더는 오래된 Chromium *기반*(주로 Extended Stable)에 새 Chromium의 보안 수정을 백포트해서 배포합니다. 원시 버전 비교로는 영원히 취약하다고 오판하게 되므로, 이런 제품은 단정 대신 "미확인"으로 표시합니다.
- **WebView2 고정 버전 사본**은 개별 앱에 묶여 배포되며 자동 업데이트되지 않고, 상시형 런타임의 레지스트리 키로도 잡히지 않습니다. 각자의 경로에서 내장 엔진으로 따로 보고합니다.

### 내장 엔진은 일부러 다르게 판정합니다

앱이 Chromium을 내장한 경우(CEF/Electron), 사용자 스스로 엔진을 올릴 방법은 없습니다. 앱 벤더가 새 버전을 내야만 따라갑니다. 완전히 업데이트된 OBS를 "위험: 여전히 Chromium 150"이라고 표시하는 것은 소음일 뿐입니다 — 사용자가 할 수 있는 일은 이미 다 한 것이니까요. 그래서 내장 엔진은 엔진 세대를 표시하는 **[정보]**로 보고하고, "조치 필요" 목록에서는 빼며, 호스트 앱을 최신으로 유지하는 것으로 충분하다고 안내합니다.

## 작동 방식

### 탐지

1. **설치 기록** — Windows 제거 레지스트리 키와 `EdgeUpdate` 클라이언트 키 (Edge `{56EB18F8-…}`, WebView2 `{F3017226-…}`), Linux 패키지 데이터와 `.desktop` 파일, macOS 앱 번들(`Info.plist` + 프레임워크 지문).
2. **흔한 위치와 `PATH`** — 표준 설치 트리와, 이름이 브라우저 단서와 맞는 `PATH`상의 실행 파일.
3. **지문 폴더** — `chrome.dll` / `chrome_elf.dll` / Chromium 프레임워크를 가진 폴더는 제품명을 몰라도 Chromium 설치로 취급.
4. **Playwright 캐시** — `ms-playwright` 폴더 (`chromium-<rev>`, `chromium_headless_shell-<rev>`).

이어지는 **증거 게이트**가 엔진 증거 없이 이름만으로 잡힌 후보를 떨어뜨립니다 ("search"에 "arc"가 들어갔다는 이유만으로 걸린 `SearchIndexer.exe` 같은 Windows 시스템 파일이 보고서에 섞이지 않는 이유). 보조 바이너리(`*_proxy.exe`, `pwa_launcher`, `ie_to_edge_stub`, crashpad 핸들러, 브로커, 언인스톨러)는 처음부터 제외합니다.

### 버전 추출 (Windows는 정적 우선)

파일을 읽는 행위는 아무것도 실행하지 않습니다. Windows 점검은 고정 파일 버전 정보, 버전 이름 폴더, 앱 *자기* 트리 안 DLL의 버전만을 사용합니다 (`System32` 같은 공용 폴더는 남의 DLL이 섞여 있어 절대 뒤지지 않음). 정적 방법으로 끝내 버전이 안 잡힌 브라우저에 한해, 중복을 병합한 뒤 대표 실행 파일을 `--version`으로 **한 번만** 실행합니다 — 점검이 브라우저마다 창을 띄우는 일은 없어야 하니까요. CEF 내장 앱은 추가로 바이트 단위에서 `chromium-A.B.C.D` 문자열을 찾습니다.

### 판정과 기준값

- `엔진 ≤ 153.0.8010.12` → [위험] (구세대; chromium-1243 이하)
- 패치 웨이브가 하나라도 빠져 있으면 (그 웨이브의 수정 빌드보다 낮으면) → [위험], 빠져 있는 웨이브와 Critical CVE 목록을 함께 표시
- 웨이브는 전부 적용됐지만 `엔진 < 현재 안정` → [주의]
- Edge/WebView2 → 위 표의 마일스톤 규칙
- 내장 엔진 → [정보] (세대 표시)
- "현재 안정" 값은 실행 시 Google **VersionHistory API** (`versionhistory.googleapis.com/v1/chrome/platforms/<플랫폼>/channels/stable/versions`, 키 불필요)로 가져오고, 네트워크가 안 되면 내장 폴백값을 쓰며 그 사실을 표시합니다.

### 업데이트 경로 (확인된 식별자)

| 제품 | winget ID | 벤더 업데이터 |
|---|---|---|
| Google Chrome | `Google.Chrome` | `GoogleUpdate.exe` / `GoogleUpdater.exe` (`/ua /installsource scheduler`), 예약 작업 |
| Microsoft Edge / WebView2 | `Microsoft.Edge` | `MicrosoftEdgeUpdate.exe`, 서비스 `edgeupdate`/`edgeupdatem` |
| Brave | `Brave.Brave` | `BraveUpdate.exe` (`BraveSoftware\Update` 아래) |
| Vivaldi | `Vivaldi.Vivaldi` | 프로그램 폴더의 `update_notifier.exe` (서비스 없음) |
| Opera | `Opera.Opera` | 버전 폴더의 `opera_autoupdate.exe` |
| NAVER Whale | `NAVER.Whale` | `whale_update.exe` + `wusvc.exe` 서비스 |
| Arc | `TheBrowserCompany.Arc` | 앱 내 업데이트만 (MSIX). **주의:** Arc는 2026-12-22 서비스 종료 예정 — "구버전"이 아니라 수명 종료(EOL)로 보세요. |
| OBS Studio | `OBSProject.OBSStudio` (이 도구는 사용하지 않음 — 인스톨러/UAC 문제) | 내장 업데이터 (시작 시 확인 / 도움말 → 업데이트 확인); 문서화된 외부 실행 방법 없음 |

## 한계

- Edge/WebView2의 정확한 Chromium 패치 수준은 로컬에서 알 수 없습니다. 누락이 아니라 설계상 그렇습니다. Microsoft의 릴리스별 노트에만 있습니다.
- 자기 버전만 찍고 Chromium 버전을 절대 출력하지 않는 포크는 목록에 올리되 (제품 버전 표시) 등급은 [정보]가 됩니다.
- CEF/Electron의 패치 수준은 내장 버전 문자열이 있을 때만 정확하고, 없으면 마일스톤까지만 주장합니다.
- Playwright 고정 버전은 릴리스마다 바뀝니다. 이 README의 리비전↔버전 대응 (1243 → 153.0.8010.12, 1248 → 156.0.8078.4)은 2026-11-04까지의 릴리스 기준입니다. 도구는 내장 바이너리의 실제 버전을 읽으므로, 표시되는 버전이 이 표에 의존하지는 않습니다.
- `--update`는 공식 메커니즘을 깨울 뿐입니다. 특정 기기에 업데이트가 *제공되는지* (단계적 배포, 기업 정책)는 벤더가 결정합니다. 끝나고 점검을 다시 돌려 새 버전을 확인하세요.

## 자주 묻는 질문

**실행해도 안전한가요?** 점검 자체는 파일과 레지스트리를 읽기만 합니다. `--update`는 앱들이 스스로 쓰는 공식 업데이터와 패키지 매니저를 실행합니다.

**왜 Edge는 "마일스톤 156"으로만 나오나요?** 디스크에 있는 정보가 그것뿐이기 때문입니다. Microsoft는 Chromium 패치 버전을 로컬에 저장하지 않습니다. 그보다 정밀한 로컬 판정을 주장하는 도구가 있다면, 그것은 추측입니다.

**OBS를 다 업데이트했는데도 오래된 엔진으로 나옵니다.** 정상입니다. 그래서 내장은 [위험]이 아니라 [정보]입니다. OBS가 실어주는 CEF 빌드가 그 빌드인 것이고, OBS 자체를 최신으로 유지하는 것이 가능한 유일한 조치이자 충분한 조치입니다.

**Playwright 캐시는 왜 [정보]로만 나오나요?** 고정 빌드는 실제로 탐색에 쓰는 브라우저가 아니라 테스트 러너가 내려받는 구성 요소이고, 그 버전을 근거로 한 "Playwright가 취약하다"는 주장은 Playwright가 반박했습니다 (배경 참조). 그래서 도구는 버전을 참고용으로만 표시하고 판정·업데이트를 하지 않습니다.

## 라이선스

MIT — [LICENSE](LICENSE) 참조.
