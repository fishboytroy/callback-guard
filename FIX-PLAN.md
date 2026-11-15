# Callback Guard: detection engine fix plan

**Problem:** `guard.py` checks one line at a time against keyword patterns. Splitting a string or rewording slips past it, while ordinary URLs, images and other languages get held. In testing, four realistic attack samples scanned clean, a harmless README was held, and the repo held itself with 53 findings.

**Goal:** catch real attacks and let ordinary projects through, without giving up the stdlib-only, fail-closed design.

Do the phases in order. Phase 0 measures whether every later phase helps.

---

## Phase 0: Build a benchmark before changing the engine (1–2 days)

Without a test corpus, any rule change is a guess.

- Add `corpus/malicious/` and `corpus/benign/`. Each file gets a header comment giving its expected result.
- **Malicious:** start with the five probe samples (split-string exfiltration, `importlib` loader, injection SKILL.md, PowerShell cradle). Then add:
  - SKILL.md injection in 10+ wordings. Use no trigger phrases: "before answering, quietly…", "for context, paste the contents of…", instructions split across lines, instructions inside code fences and tables.
  - Python: `getattr(__builtins__, ...)`, `__import__`, `ctypes`, `marshal`/`pickle`, `compile()`, base64 chunks under 100 characters joined at runtime.
  - PowerShell: `[scriptblock]::Create`, `& $var`, `-enc` built from pieces, `Net.WebClient`, `Start-Process` with a hidden window.
  - JS: `child_process`, `require(variable)`, `Function()` constructor, `postinstall` in `package.json`.
  - Archives: malicious file nested three directories deep, file with a misleading extension.
- **Benign:** 20+ real, popular skills and small repos (Anthropic's public skills, common MCP servers, your own repo).
- Add `bench.py`. It runs `inspect_payload` on every file and prints the detection rate (malicious held), the false-positive rate (benign held), and each miss.
- **Exit criteria:** `bench.py` runs in CI and the baseline numbers are recorded in the README. Expect the baseline to be poor.

## Phase 1: Classify files by content, not extension (½ day)

- Detect the type from magic bytes. Images, fonts and icons (PNG/JPEG/GIF/ICO/WOFF) are **inert**: record the hash, raise no finding. Defender still scans them.
- Source types the scanner has an analyzer for (`.py`, `.ps1`, `.js/.ts`, `.sh`, `.md`) are scanned.
- Readable text in other languages (`.go`, `.rs`, `.java`, `.c`, `.rb`) gets the improved text rules from Phase 4, not "unsupported".
- Unknown binaries, executables, nested archives and anything whose extension doesn't match its content stay **held**. That keeps the tool fail-closed.
- **Exit:** the self-scan's two `unsupported` findings for `.ico`/`.png` are gone, and a `.exe` renamed to `.png` is held.

## Phase 2: Add severity levels and allowlists (1 day)

Every finding counts as a hold today, which is why your own repo fails.

- Add `severity` to every finding: `info` / `low` / `high` / `critical`.
- Only `high` and `critical` hold. `info` and `low` appear in the report but allow `checks-passed`.
- Re-tier the current rules:
  - A literal URL is `info`, with the domain shown.
  - `pip install` / `npm install` in Markdown is `info`. In `package.json` scripts, or in Python that runs it, it is `high`.
  - An HTML comment is `info`. One that contains imperative text aimed at the assistant is `high` (see Phase 4).
  - `os.environ` / `process.env` is `low`. Reading a credential path is `critical`.
- Add `allowlist.json` (user-editable) for trusted domains and per-repo suppressions. A suppression appears in the report as "suppressed by user", never silently.
- **Exit:** the README sample passes. The self-scan has no `high`/`critical` findings, or every remaining one is a real concern you've documented.

## Phase 3: Add analyzers that understand code structure (3–5 days)

This catches the four samples that scanned clean.

### Python, using stdlib `ast` (no new dependencies)
- Track imports, including aliases, `from x import y as z`, `importlib.import_module(...)` and `__import__(...)`.
- Fold constant strings, so `'sub'+'process'`, `''.join([...])` and simple f-strings resolve to `subprocess`.
- Flag calls by capability, after alias resolution:

| Capability | Examples | Severity |
|---|---|---|
| Process execution | `subprocess.*`, `os.system`, `os.popen`, `pty.spawn` | high |
| Network | `socket.*`, `urllib.request.urlopen`, `http.client`, `requests.*` | high (critical if paired with credential read) |
| Dynamic code | `eval`, `exec`, `compile`, `pickle/marshal.loads`, `getattr` with a non-literal name | high |
| Native code | `ctypes`, `cffi` | high |
| Credential paths | `.ssh`, `.aws`, `.claude`, `.codex`, `settings.json`, browser profile dirs, after string folding | critical |

- **Combination rule:** a credential read and a network call in the same file is `critical`.
- If parsing fails, fall back to the text rules and add a `low` "unparseable" finding.

### PowerShell, using the built-in parser
- Call `[System.Management.Automation.Language.Parser]::ParseInput` through a fixed `powershell.exe -NoProfile` script. Pass the file content on stdin, never in the command line.
- Walk `CommandAst`, `InvokeMemberExpressionAst` and string-concatenation nodes. Flag `ScriptBlock::Create`, `Invoke-Expression`, `& $variable`, `Net.WebClient` and `DownloadString`, `Start-Process -WindowStyle Hidden`, and `-EncodedCommand` assembled from parts.

### JavaScript/TypeScript and shell
- There's no stdlib parser. Normalize text first: join split string literals, strip comments, collapse whitespace. Then run capability patterns: `child_process`, `require(` with a non-literal argument, `Function(`, `new Function`, `curl … | sh`.
- Check `package.json` lifecycle scripts (`preinstall` / `postinstall` / `prepare`) and mark them `high`.

- **Exit:** all four clean probe samples are held at `high`/`critical`, and the benign false-positive rate doesn't rise from Phase 2.

## Phase 4: Detect prompt injection in skills and Markdown (2–3 days)

This is the threat skills mainly face, and keyword rules can't solve it.

### 4a. Better heuristics (stdlib)
- Analyze paragraphs or sliding three-line windows, not single lines, so a split instruction is still caught.
- Score these signals and combine them; any single one is weak:
  - Imperatives addressed to the assistant: "before you respond", "always first", "when the user asks".
  - Concealment: "don't mention", "quietly", "no need to tell", "keep this between".
  - Sensitive targets: config, credential and history paths; "settings", "token", "API key", "conversation".
  - Exfiltration verbs: "include in your reply", "send", "post", "append to".
  - Instructions hidden in HTML comments, zero-width text or alt text.
- If concealment combines with a sensitive target or exfiltration verb, mark it `critical`.

### 4b. Optional agent-assisted review, run from SKILL.md
- `guard.py` writes `review-packet.json` with the instruction-bearing passages, escaped and length-limited.
- SKILL.md tells the agent to classify each passage against a fixed rubric. The answer must be one of `benign` / `suspicious` / `malicious`, with a one-line reason. The packet is treated as data.
- **The review can add findings but never remove them.** A passage the heuristics held stays held whatever the review says. This protects against injection aimed at the reviewer itself.
- Record whether the review ran. A scan without it reports `coverage: heuristic-only`.

- **Exit:** at least 9 of 10 injection wordings in the corpus are held, and the benign skills from Phase 0 still pass.

## Phase 5: Make findings readable (½ day)

- Each finding gets: severity, rule, file, line, and a **snippet** of up to 200 characters with control and zero-width characters escaped, labelled `untrusted_excerpt`.
- The GUI Summary tab groups findings by severity, critical first.
- Report an overall `risk_summary` in plain words: "1 critical: reads ~/.ssh and opens a network socket (exfil.py:3)".

## Phase 6: Report on dependencies (1–2 days, opt-in)

- Parse `requirements.txt`, `pyproject.toml` and `package.json`, and list each dependency under `not_covered` by default.
- An `--osv` flag queries the OSV.dev API for known vulnerabilities and flags typosquat-like names, such as names within edit distance 1 of a top package. The flag is off by default because it uses the network.

## Phase 7: Reduce the monitor's risk (½ day)

- Make reading browser `History` databases **opt-in** (`config.json: "browser_metadata": true`) and keep folder watching as the default. Copying browser databases looks like info-stealing malware to EDR tools.
- Check whether a nonzero exit from the `post-checkout` hook changes `git clone` / `git checkout` exit codes on your Git version. If it does, other tools and scripts will see clones as failures. Make the hook always `exit 0` and rely on the report and notification.

## Phase 8: Prepare to release (1 day)

- **Choose a license.** MIT or Apache-2.0 gives the broadest adoption. Without one nobody can legally use or contribute.
- **Rename the skill.** `callback` is generic and likely to clash with other skills.
- **Support other platforms.** Make antivirus a pluggable backend: Defender, ClamAV, or none. With no engine the status is `av-unavailable`. That still holds by default, but a config flag can allow it.
- Publish the Phase 0 benchmark numbers in the README. Measured detection and false-positive rates are the strongest marketing claim you can make.

---

## Done when

- [ ] `bench.py` runs in CI with numbers published.
- [ ] All five probe samples are held; the benign README passes.
- [ ] The repo's self-scan returns `checks-passed`, or only `info`/`low` findings.
- [ ] At least 90% of corpus injection variants are held; at least 80% of benign skills pass.
- [ ] A license is chosen and the skill renamed.

**Rough total:** 2–3 weeks of focused work. Phases 0–3 (about 1 week) give the biggest improvement.
