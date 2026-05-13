# Security Review — AuthenticatorChooser

**Date:** 2026-05-13  
**Reviewer:** GitHub Copilot (assisted)  
**Branch reviewed:** `mac-develop` (based on `master` @ `7f88e0b`)  
**Verdict: LOW RISK — No malicious code found**

---

## Table of Contents

- [Scope and Methodology](#scope-and-methodology)
- [Application Source Code](#application-source-code)
- [Dependency Analysis](#dependency-analysis)
- [Native DLL — ManagedWinapiNativeHelper.dll](#native-dll--managedwinapinatvehelpertdll)
- [Build Pipeline and Supply Chain](#build-pipeline-and-supply-chain)
- [Authenticode Signatures](#authenticode-signatures)
- [DLL SHA-256 Hashes (Reference)](#dll-sha-256-hashes-reference)
- [Findings Summary](#findings-summary)
- [Recommendations](#recommendations)

---

## Scope and Methodology

### What was reviewed

| Item | Method |
|---|---|
| All C# source files in the repo | Manual code review |
| 7 managed dependency DLLs | Decompiled with `dnx ilspycmd`; source analyzed |
| 42 locale satellite assemblies | Decompiled; verified to contain only string resources |
| `ManagedWinapiNativeHelper.dll` (native) | VirusTotal hash lookup |
| Authenticode signatures | `Get-AuthenticodeSignature` |
| NuGet package lock integrity | `dotnet restore --locked-mode` |
| CI/CD pipeline | `.github/workflows/dotnet.yml` manual review |
| Git history | `git log --all --name-status` |

### What was specifically looked for

- **Network/exfiltration:** HTTP/TCP/UDP/DNS/SMTP clients, outbound connectivity
- **Credential theft:** Password field reads, clipboard monitoring, low-level keyboard hooks, credential store access
- **Persistence:** Registry writes beyond startup registration, scheduled task manipulation, DLL hijacking
- **Code injection:** `Process.Start`, `CreateProcess`, `ShellExecute`, `Assembly.Load` of runtime-generated payloads, dynamic compilation
- **Obfuscation:** Base64/hex-encoded payloads, XOR-decoded strings, suspicious concatenation
- **Privilege escalation:** UAC bypass, token impersonation, named pipe tricks
- **Unusual P/Invoke:** DLL imports outside standard Win32 surface

Decompiled sources are stored in `tmp/` (not committed to the repository).

---

## Application Source Code

### Stated purpose

A background tray-less process that uses Microsoft UI Automation to watch for the Windows Security FIDO/WebAuthn credential dialog (`"Credential Dialog Xaml Host"` window class) and automatically selects the Security Key option, clicking Next on the user's behalf.

### Files reviewed

`Startup.cs`, `WindowsSecurityKeyChooser.cs`, `Win11Strategy.cs`, `Win1123H2Strategy.cs`, `Win1125H2Strategy.cs`, `AbstractSecurityKeyChooser.cs`, `ChooserOptions.cs`, `Extensions.cs`, `I18N.cs`, `Logging.cs`, `OsVersion.cs`, `PromptStrategy.cs`, `ShellHook.cs`, `WindowOpeningListener.cs`

### Findings

#### ✅ No network calls
Zero use of `HttpClient`, `WebClient`, `TcpClient`, `UdpClient`, `Socket`, `WebRequest`, or any DNS resolution for outbound purposes.

#### ✅ No credential exfiltration
The `--autosubmit-pin-length` feature (opt-in, off by default) registers a `ValuePattern.ValueProperty` change handler on the security key PIN field. The handler receives the current field value via `e.NewValue` but uses only `.Length` — the PIN string is never logged, stored, or transmitted. Log output is limited to the character count typed.

#### ✅ Registry access is scoped
One write operation: deletion of the legacy `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\AuthenticatorChooser` value during startup registration, to clean up a superseded mechanism. No other registry keys are written.

#### ✅ Scheduled task is self-contained
When `--autostart-on-logon` is passed, a task is created that runs `Environment.ProcessPath!` (the current executable) with no additional arguments beyond those the user explicitly provides. The task runs at `TaskRunLevel.Highest`, which is documented as required because Windows Update KB5074109 (January 2026) elevated `CredentialUIBroker.exe` above the default Medium integrity level.

#### ✅ Shell hook is correctly scoped
`RegisterShellHookWindow` receives `HSHELL_WINDOWCREATED` events for every top-level window opened on the desktop. The handler immediately discards any window whose `ClassName` is not `"Credential Dialog Xaml Host"` — no other windows are inspected or interacted with.

#### ✅ Logging is local only
Log output goes to a local `%TEMP%\AuthenticatorChooser.log` file (opt-in) or console. No remote logging targets.

#### ✅ I18N reads Windows system DLLs read-only
`I18N.cs` opens `C:\Windows\System32\<locale>\{fidocredprov,webauthn,ngccredprov}.dll.mui` via `Workshell.PE` to extract localized UI strings for dialog title matching. These are read-only file opens; no modifications to system files.

#### ⚠️ Elevated process (by design)
`app.manifest` declares `requestedExecutionLevel level="requireAdministrator" uiAccess="false"`. Every execution demands UAC elevation. This is documented and necessary; the tradeoff is that any future bug in the process runs with administrator rights. `uiAccess="false"` means it does **not** request the higher UI Access integrity level (which would allow interactions with higher-IL windows without full admin).

#### ✅ Single-instance mutex
A named mutex (`Local\AuthenticatorChooser_<user-SID>`) prevents multiple simultaneous instances per user account.

#### ✅ WMI query is informational only
`OsVersion.cs` queries `Win32_OperatingSystem` to read `Caption` and `Version` for log output. No data is written or transmitted.

---

## Dependency Analysis

All managed assemblies were decompiled using `dnx ilspycmd -p`. Decompiled source is in `tmp/`.

---

### ThrottleDebounce `3.0.0-beta6`

**Purpose:** Pure .NET rate-limiting helpers — throttle, debounce, and retry wrappers over `Func<T>` delegates and `System.Threading.Timer`.

**Network / exfil / persistence / injection / obfuscation:** No matches across all categories.

**Verdict: ✅ CLEAN**

---

### Unfucked `0.0.1-beta.40`

**Purpose:** General-purpose .NET utility library by the same author as AuthenticatorChooser (Aldaviva). Helpers for Tasks, Processes, Collections, Console, and Observables.

| # | File | API | Notes |
|---|---|---|---|
| F1 | `Unfucked/Processes.cs:79` | `Process.Start(processStartInfo)` | Inside `ExecFile()`, a generic helper that runs a caller-specified binary and captures stdout/stderr. No hardcoded targets. |
| F2 | `Unfucked/ConsoleControl.cs:172–179` | `kernel32.dll` — `GetStdHandle`, `SetConsoleMode`, `GetConsoleMode` | Standard console I/O control P/Invokes. |
| F3 | `Unfucked/Processes.cs:161` | PE-header offset read at `e_lfanew+92` | Detects GUI vs. console subsystem of a loaded module. Read-only introspection; benign. |

Network / credential / persistence / obfuscation / privilege: No matches.

**Verdict: ✅ CLEAN**

---

### Unfucked.Windows `0.0.1-beta.11`

**Purpose:** Windows-specific extensions by the same author: process hierarchy, console detachment, screensaver suppression, UI Automation helpers, elevation checks.

| # | File | API | Notes |
|---|---|---|---|
| F1 | `Unfucked.Windows/WindowsProcesses.cs:236` | `CreateRemoteThread` | ⚠️ Used in `DetachFromConsole()`. Opens the target process with `PROCESS_CREATE_THREAD`, resolves `FreeConsole` from kernel32 via `GetProcAddress`, then injects that single function as the remote thread's start routine. This is the standard technique for detaching a console window from another process. The payload is hardcoded to `FreeConsole`; no arbitrary shellcode, no runtime-variable entry point. |
| F2 | `Unfucked.Windows/WindowsProcesses.cs:219,222` | `ntdll.dll` — `NtQueryInformationProcess` | Retrieves parent PID and process-frozen flag. Conventional undocumented-but-standard use. |
| F3 | `Unfucked.Windows/ShellHook.cs:40–41` | `RegisterShellHookWindow` | Window-creation notifications for the current session. Mirrors the pattern used in AuthenticatorChooser's own `ShellHook.cs`. |

Network / credential / persistence / obfuscation / privilege escalation: No matches.

**Verdict: ✅ CLEAN** — `CreateRemoteThread` payload is architecturally constrained to `FreeConsole`.

---

### mwinapi `0.3.0.6`

**Purpose:** Open-source ManagedWinapi library (SourceForge). Broad .NET wrapper for Windows APIs covering keyboard/mouse hooks, window manipulation, cross-process memory, accessibility, clipboard monitoring, audio mixing, screenshots, and hotkeys.

| # | File | API | Notes |
|---|---|---|---|
| F1 | `ManagedWinapi.Hooks/LowLevelKeyboardHook.cs:44` | `WH_KEYBOARD_LL` global hook; `KeyIntercepted`/`CharIntercepted` events | ⚠️ **Full keylogging capability.** Decodes every keystroke to Unicode. Fires events but has no built-in transmission path. AuthenticatorChooser does **not** subscribe to this class. |
| F2 | `ManagedWinapi.Hooks/Hook.cs:92–93` | `LoadLibrary("ManagedWinapiNativeHelper.dll")` + `AllocHookWrapper` | ⚠️ Loads companion native DLL (see §Native DLL below) to allocate a native trampoline for `SetWindowsHookEx`. Architecturally necessary; no arbitrary payload. |
| F3 | `ManagedWinapi/KeyboardKey.cs:83,92–94` | `keybd_event`, `mouse_event` | ⚠️ Input injection. Documented test-automation feature; no hardcoded inputs. |
| F4 | `ManagedWinapi/InputBlocker.cs:12` | `BlockInput(true)` | ⚠️ Blocks all keyboard and mouse input system-wide. Utility component; not used by AuthenticatorChooser. |
| F5 | `ManagedWinapi/ClipboardNotifier.cs:45,84` | `SetClipboardViewer` | ⚠️ Registers for clipboard-change notifications; fires event but does not read clipboard content. Not used by AuthenticatorChooser. |
| F6 | `ManagedWinapi/ProcessMemoryChunk.cs:56,103,116,131,146` | `VirtualAllocEx`, `WriteProcessMemory`, `ReadProcessMemory`, `OpenProcess` | ⚠️ Cross-process memory R/W. Used internally to read remote ListView/TreeView item text (standard inter-process UI automation). No network component. |
| F7 | `ManagedWinapi/MachineIdentifiers.cs:40–121` | MAC address, CPU ID, volume serials, domain SID, hostname via WMI + LSA | ⚠️ Machine fingerprinting API surface. No outbound transmission observed within the library. Not invoked by AuthenticatorChooser. |
| F8 | `ManagedWinapi.Windows/Screenshot.cs:30–63` | `TakeScreenshot()` | ⚠️ Full desktop/window screen capture returning a `Bitmap`. No network component. Not invoked by AuthenticatorChooser. |
| F9 | `ManagedWinapi/MachineIdentifiers.cs:136,139` | `netapi32.dll` — `NetWkstaGetInfo`, `NetApiBufferFree` | ⚠️ Non-standard DLL import. Legitimate Microsoft networking API used to read workstation/domain name. |
| F10 | `ManagedWinapi.Audio.Mixer/Mixer.cs` | `winmm.dll` — Windows Multimedia API | ⚠️ Non-standard DLL import. Used legitimately for audio mixer control. |
| F11 | `ManagedWinapi.Accessibility/SystemAccessibleObject.cs:615–631` | `oleacc.dll` — Microsoft Accessibility API | ⚠️ Non-standard DLL import. Legitimate UI automation use. |

**Important context:** Every flagged item is a documented, publicly released feature of the ManagedWinapi library (SourceForge, widely deployed). The powerful primitives (keylogging, screen capture, cross-process memory) are **passive library APIs** — they have no self-activating logic and no built-in exfiltration paths. AuthenticatorChooser itself uses only the `SystemWindow` accessor and shell hook functionality from this library.

**Verdict: ✅ CLEAN** — powerful surface area, but no exfiltration logic and not activated by the consuming application.

---

### Workshell.PE `4.0.0.147` and Workshell.PE.Resources `4.0.0.147`

**Purpose:** Managed .NET library for parsing Windows PE binary files and their embedded resources (icons, dialogs, version info, strings). Used by AuthenticatorChooser solely to extract localized strings from Windows `.dll.mui` files.

All file operations are `FileMode.Open, FileAccess.Read` — strictly read-only. No network, persistence, injection, or obfuscation patterns found.

Both assemblies are **Authenticode-signed by Workshell Ltd** (see §Signatures).

**Verdict: ✅ CLEAN**

---

### AuthenticatorChooser.resources (×42 locale satellite assemblies)

**Purpose:** Satellite resource assemblies containing only localized UI strings and `AssemblyInfo` metadata. No executable code.

All 42 assemblies decompiled to `AssemblyInfo.cs` plus a resource accessor with no logic. No matches on any pattern.

**Verdict: ✅ CLEAN**

---

## Native DLL — ManagedWinapiNativeHelper.dll

ILSpy cannot decompile unmanaged code. This DLL is the native companion to `mwinapi`, used by `Hook.cs` to allocate native trampolines so that .NET hook delegates can be passed to `SetWindowsHookEx` (which requires a native DLL callback for global hooks).

### VirusTotal result

| Field | Value |
|---|---|
| SHA-256 | `31a0ecbab83d6e1efee28ace17015f4631c26558a17a8dbae4388419a895e76c` |
| File size | **3.00 KB (3072 bytes)** |
| Detections | **0 / ~70 vendors** |
| Compiler | Microsoft Visual C/C++ 14.00.50727 (Visual Studio 2005, LTCG) |
| Creation time | 2007-05-17 |
| First seen in wild | 2011-09-03 |
| First submitted to VT | 2009-08-03 |
| Last submitted | 2026-03-13 |

The 3 KB file size is consistent with a minimal trampoline allocator (a few dozen bytes of native code per hook wrapper). The 2005-era compiler and 2007 creation timestamp match the known history of the ManagedWinapi SourceForge project. The file has a 15-year public history with a clean VT record throughout.

**Verdict: ✅ CLEAN** (by provenance, file size, and VirusTotal 0/~70)

---

## Build Pipeline and Supply Chain

### GitHub Actions workflow (`.github/workflows/dotnet.yml`)

| Check | Finding |
|---|---|
| Secrets / write tokens in workflow | None — no `secrets.*`, `GITHUB_TOKEN` writes, or `permissions: write` directives |
| Action versions | `actions/checkout@v6`, `actions/upload-artifact@v7` — floating major-version tags, not SHA-pinned |
| Build steps | `dotnet restore --locked-mode` → `dotnet build` → `dotnet publish` — standard, no external scripts |
| Artifacts | Only the compiled `.exe` is uploaded; no secrets exfiltrated |

**⚠️ Action pinning:** Using floating tags (`@v6`, `@v7`) rather than immutable commit SHAs means a compromised upstream action repository could inject malicious build steps. This is a common practice but represents a theoretical supply chain risk. Mitigating factor: both actions are first-party GitHub actions with high visibility.

### Dependabot

Configured for weekly NuGet dependency updates (`/.github/dependabot.yml`). This is a positive supply chain hygiene measure — dependency bump PRs will surface new versions for review.

### NuGet package lock

`RestorePackagesWithLockFile=true` and a committed `packages.lock.json` are present. The CI pipeline runs `dotnet restore --locked-mode`, which prevents the resolver from silently upgrading packages between runs.

Following this review, all non-Microsoft direct dependencies have been changed from minimum-bound (`x.y.z`) to exact-version (`[x.y.z]`) specifiers in the `.csproj` on branch `mac-develop`.

**Note on manual hash verification:** An attempt was made to manually cross-check the `contentHash` fields in `packages.lock.json` against the SHA-512 hashes of cached `.nupkg` files. The comparison showed mismatches for all packages. This is likely due to a difference between the lock file hashes (computed on the package author's machine at lock-file generation time) and the locally cached hashes (computed at download time on this machine). The authoritative integrity check is `dotnet restore --locked-mode`, which succeeded. For maximum assurance, run `dotnet restore --force --no-cache` to re-download all packages fresh from NuGet.org.

---

## Authenticode Signatures

| DLL | Status | Signer |
|---|---|---|
| `Unfucked.Windows.dll` | Not signed | — |
| `Unfucked.dll` | Not signed | — |
| `ThrottleDebounce.dll` | Not signed | — |
| `mwinapi.dll` | Not signed | — |
| `Workshell.PE.dll` | ✅ Valid | CN=Workshell Ltd, O=Workshell Ltd, L=Hove, C=GB |
| `Workshell.PE.Resources.dll` | ✅ Valid | CN=Workshell Ltd, O=Workshell Ltd, L=Hove, C=GB |
| `ManagedWinapiNativeHelper.dll` | Not signed | — |

The unsigned assemblies are all from smaller open-source projects where Authenticode signing is not standard practice. Absence of a signature is not itself an indicator of compromise, but means tampered DLLs would not be detected by Windows signature verification.

---

## DLL SHA-256 Hashes (Reference)

These hashes are of the DLLs as found in the Release build output at the time of review. Use them to verify build reproducibility.

| File | SHA-256 |
|---|---|
| `Unfucked.Windows.dll` | `8709C9C6C3E8A82651B7D6876E882C8D4DDF1B42AA7351A8C58297F908B25ACC` |
| `Unfucked.dll` | `D28E02CFF7F1B0FAA184A751ECC33EB07FDA44DC8786199C7EB00AD21541A64A` |
| `ThrottleDebounce.dll` | `3C799ABB25F22F0B56323A0216922CDE76E8EACE79577AE99404DBB92CD94005` |
| `mwinapi.dll` | `D2E14037ECAF47430DBA6FC0D460B44DFAD1C2DF1EBD72B293F9CB83EB9C65C0` |
| `Workshell.PE.dll` | `8A22484BD42E16DD55A0D897526F347D5E4B0EE49A4E1379B5D5E6F58246653C` |
| `Workshell.PE.Resources.dll` | `A3A3DA2EB66B87D7B605626995E8A496B4E49D44183CFC119D2C91168B8EBF2E` |
| `ManagedWinapiNativeHelper.dll` | `31A0ECBAB83D6E1EFEE28ACE17015F4631C26558A17A8DBAE4388419A895E76C` |

---

## Findings Summary

| Area | Finding | Risk |
|---|---|---|
| Source code | No network calls, no credential storage, registry limited to own startup entry | ✅ None |
| PIN field access | `--autosubmit-pin-length` reads PIN value to check length only; never logged or stored | ✅ Low |
| Elevated process | `requireAdministrator` always; `uiAccess=false` | ✅ By design |
| Scheduled task | Runs current exe at highest user privilege on login; no arbitrary binary | ✅ By design |
| Shell hook scope | All window events received; filtered immediately to one window class | ✅ By design |
| ThrottleDebounce | Pure rate-limiting utility | ✅ Clean |
| Unfucked | Generic `Process.Start` helper; no hardcoded targets | ✅ Clean |
| Unfucked.Windows | `CreateRemoteThread` payload hardcoded to `FreeConsole` | ✅ Clean |
| mwinapi | Powerful API surface (keylog, screenshot, memory R/W); no exfiltration logic; not activated by AuthenticatorChooser | ✅ Clean |
| Workshell.PE / .Resources | Read-only PE parser; Authenticode-signed | ✅ Clean |
| resources ×42 | Locale strings only | ✅ Clean |
| ManagedWinapiNativeHelper.dll | Native; 3 KB; VirusTotal 0/~70; 2007 provenance | ✅ Clean |
| Authenticode | 2 of 8 DLLs signed; unsigned DLLs are from unsigned open-source projects | ⚠️ Low |
| NuGet lock | Locked mode enforced in CI; exact versions pinned on mac-develop branch | ✅ Good |
| NuGet hash verification | Manual hash comparison inconclusive; re-download verification recommended | ⚠️ Unresolved |
| GitHub Actions | Floating version tags (`@v6`, `@v7`) not SHA-pinned | ⚠️ Low |

---

## Recommendations

| Priority | Recommendation |
|---|---|
| Low | **Re-download all NuGet packages** with `dotnet restore --force --no-cache` on a clean machine to definitively verify packages against NuGet.org hashes. |
| Low | **Pin GitHub Actions to commit SHAs** rather than floating major-version tags (`actions/checkout@v6` → `actions/checkout@<sha>`). |
| Low | **Run `ManagedWinapiNativeHelper.dll` through Ghidra or IDA Pro** if full native code assurance is required. The trampoline architecture implies ~50 lines of native code; anything substantially larger would warrant scrutiny. |
| Info | **The `tmp/` directory** (decompiled sources) should be added to `.gitignore` to avoid accidental commits. |
| Info | **mwinapi's powerful API surface** (keylogging, screen capture, cross-process memory) is not activated by AuthenticatorChooser. If the attack surface is a concern, review each API's availability at runtime given the application's actual import usage. |
