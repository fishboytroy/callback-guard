# Callback Guard

A Windows-first `/callback` skill and standalone inspection tool for checking agents, skills, Markdown instructions, software downloads, source archives, and Android APKs before use.

It combines conservative static checks with Microsoft Defender. Findings are review leads, not proof of malicious behavior. A passing result means only that the implemented checks passed on the recorded bytes; it is not a security certification.

## Requirements

- Windows with Microsoft Defender available for the antivirus gate.
- Python 3.12 or newer; the desktop interface also requires Tkinter.
- Git only for the optional Git checkout monitor.
- No third-party Python packages or hosted AI API key required.

## Use without an AI assistant

Review the source, download the repository, and extract it to a writable folder. Double-click `Launch Guard.cmd`, or run:

```powershell
python guard.py --gui
python guard.py --source 'C:\path\to\SKILL.md'
python guard.py --url 'https://github.com/owner/repository'
```

The GUI supports local files, APKs, and HTTPS downloads. It shows a summary, full JSON report, scan history, and the report folder. It does not install inspected software.

## Use as a skill

Place this complete repository folder, including `SKILL.md` and the Python files, in your agent's user skill directory under the folder name `callback`. For Codex on Windows, a typical destination is `$HOME\.codex\skills\callback`. Check for an existing installation first; do not overwrite it without preserving your configuration.

Invoke `$callback <URL>` in a compatible agent. `/callback <URL>` is conversational shorthand where the agent supports it; this repository does not register a universal slash command or an MCP server. Use `/callback <URL> scan only` when you want a report without installation. The skill directs an agent to stop on held or incomplete scans and verify the exact checked bytes before any authorized installation.

The skill loads its tools from its own directory and does not depend on the original author's filesystem paths. Reading the skill in an AI service can still expose material you give that service under its own policies.

## What it checks

- Hidden characters and selected instruction override or concealment patterns.
- Potential outbound requests, callbacks, telemetry, credential access, dynamic execution, and persistence commands.
- ZIP and TAR members, unsafe paths, links, unsupported formats, nested archives, encryption, and bounded sizes.
- Microsoft Defender custom scan with remediation disabled for the requested scan. Existing Defender machine and cloud policies remain in effect.
- APK package metadata, manifest permissions/components, archive integrity, member hashes, and compiled-file string indicators.

Ordinary URLs and legitimate installer commands can trigger review. The scanner intentionally favors holding uncertain inputs over automatic continuation. It does not execute inspected source or extract inspected archives.

## Results and limits

| Result | Meaning |
| --- | --- |
| `checks-passed` / exit 0 | Implemented checks completed with no findings and no antivirus detection. Applies only to the recorded hash. |
| `held` / exit 2 | Findings, unsupported content, antivirus problems, or incomplete analysis block automatic continuation. |
| `review-required` / exit 2 | APK triage completed with no antivirus detection; further review is always required. |
| Other failures or missing reports | Stop; never interpret them as a pass. |

Reports and inert payload copies are saved under `intake/`. A successful payload is named `payload.checked`. Verify its SHA-256 against `report.json` before use. Existing source files remain untouched and accessible; holding an intake copy does not quarantine the original.

Input limit: 80 MiB. Source archive limits: 25 MiB expanded, 500 entries, 2 MiB per text member. APK limits: 256 MiB expanded, 10,000 entries, 64 MiB per member, 4 MiB binary manifest. UTF-8 and BOM-marked UTF-16 text are supported.

This is not a sandbox, an OS-enforced quarantine, a dependency vulnerability scanner, a complete semantic analysis, or a signature/provenance verifier. Git history, unresolved dependencies, submodules, and Git LFS contents are not implicitly covered. APK inspection does not decompile or execute apps or verify Android signing; APKs never pass automatically. Private download authentication is not integrated. NVIDIA SkillSpector is not bundled or invoked.

## Optional automatic monitoring

Automatic monitoring is off until you explicitly run:

```powershell
.\install-automatic.ps1
```

This adds a Windows login shortcut and a user Git template post-checkout hook, then starts a background monitor. It refuses to replace an existing conflicting Git hooks/template configuration. Run `uninstall-automatic.ps1` to remove login startup and restore the previous template when still owned by this tool. Hook copies in repositories already created remain; the uninstaller reports that limitation.

The monitor polls watched Downloads folders every three seconds and completed-download metadata in Chrome, Edge, and Brave every 30 seconds to cover Save As paths. It queries local browser databases for completed-download paths only and may create temporary database snapshots. It scans files after they appear stable in two polls. Existing files at first setup are baselined, not scanned. The latest 200 download records per browser profile and a 20,000-file inventory limit mean coverage is not exhaustive. Other browsers are covered only through watched folders.

The Git hook scans after checkout. Files already exist at that point; the hook does not undo checkout. Bare or no-checkout clones, alternate hooks/templates, disabled hooks, existing repositories without this hook, and clients ignoring Git configuration can bypass coverage. These features do not block execution or replace the manual pre-install gate.

Use `Open Automatic Reports.cmd` for reports and `Stop Automatic Monitor.cmd` to request a stop. Runtime files live under `automatic-state/`. Add custom watched directories in `automatic-state/config.json` under `extra_download_folders`.

## Privacy

The bundled scanner has no hosted AI integration or creator-notification endpoint. Network access is used for a URL you ask it to download. Microsoft Defender may contact Microsoft according to your existing configuration. Optional monitoring reads local download metadata. Reports may contain private local paths, antivirus output, and untrusted APK strings; keep them private. Scan state, payloads, and logs are excluded from version control by `.gitignore`.

## Verification

```powershell
python -m unittest -v test_guard.py test_automatic.py test_apk_inspection.py
```

Unit tests mock antivirus responses; passing tests do not establish a live Defender scan or universal detection accuracy. Run a separate scan on the exact artifact you intend to use.

No open-source license has been selected. Repository availability alone does not grant a license to redistribute or modify this work.
