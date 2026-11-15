# Benchmark corpus

This folder measures how well `guard.py` tells malicious input from ordinary
project files. It is the baseline for the detection-engine rewrite (Phase 0 of
the fix plan).

## Layout

```
corpus/
  benign/      files a real project contains; must scan clean (0 findings)
  malicious/
    injection/ prompt-injection fixtures (plain text instructions)
    code/       executable-malware samples  <-- not shipped; see below
  manifest.json  expected result for every sample
```

## Running it

```powershell
python bench.py
```

`bench.py` runs the current scanner over every file listed in `manifest.json`
and prints:

- **detection rate** - malicious files the scanner held (produced >=1 finding)
- **false-positive rate** - benign files the scanner wrongly held
- a list of every miss and every false positive

Expect a poor baseline today: the current line-by-line keyword rules miss
reworded or split injection and flag ordinary URLs and `pip install` text.

### Baseline (current keyword engine, 2026-11-15)

```
Malicious detected : 2/6  (33% detection)
Benign clean       : 4/7  (43% false positives)
```

- Missed injection: plain wording, instruction split across list items, text
  inside a code fence, and a false authorization claim.
- False positives: `data_helpers.py` (reads one env var), and two READMEs that
  mention `pip install` / `npm install` in prose.

This is the number the engine rewrite (Phases 1-4) must beat. Target: >=90%
detection and <=10% false positives, plus the executable-malware `code/`
samples once sourced.

### After Phase 1 (content classification)

```
Malicious detected : 3/7  (43% detection)
Benign clean       : 6/9  (33% false positives)
```

Phase 1 classifies by magic bytes instead of extension. The inert PNG and the
`.go` source now scan clean (both were held before), and a PE executable
renamed `.png` is now caught. The remaining false positives (`pip install`
prose, one env-var read) and the four missed injections are Phases 2 and 4.

### After Phase 2 (severity tiers + allowlist)

```
Malicious detected : 3/7  (43% detection)
Benign clean       : 9/9  (0% false positives)
```

Only `high` and `critical` findings hold a scan now (`guard.blocking`). A bare
URL, a `pip install` mention, and reading one env var are `info`/`low`: still
reported, no longer blocking. All three earlier false positives clear. Detection
is unchanged; the four missed injections need semantic detection (Phase 4).

Note: running the scanner over its own `guard.py` still reports high/critical
findings, because that file literally contains the attack signatures (`.ssh`,
`id_rsa`, the base64 pattern). That is expected for a signature file and does
not reflect behavior on ordinary projects, where the 0% rate above applies.

An `allowlist.json` at the repo root can downgrade specific domains or rules;
suppressed findings are marked `suppressed`, never dropped.

## On the `code/` samples

The malicious **code** samples (reverse-exec, credential exfiltration, native
memory, loaders) are intentionally **not committed to this repo**. Generating a
library of working exploits is unnecessary and unsafe. `manifest.json` lists the
techniques the benchmark needs under `code_samples_to_source`; populate
`corpus/malicious/code/` from an established, clearly-licensed public test set
or your own red-team fixtures, then add matching entries to the `samples` list.
Suggested sources:

- Published prompt-injection / agent-security evaluation datasets.
- Vendor malware-analysis test corpora with explicit redistribution terms.
- The four probe snippets used in the red-team review (recreate locally; keep
  them out of version control).

`bench.py` treats any manifest entry whose file is missing as **unsourced** and
reports the count separately, so the benchmark runs and stays honest even before
the code samples are in place.

## Adding a sample

1. Drop the file in the right subfolder.
2. Add an entry to `manifest.json` with `label` (`malicious` or `benign`) and a
   short `detail`/`note`.
3. Re-run `python bench.py`.

Keep benign samples realistic (copy shapes from real popular skills and small
repos) so the false-positive rate reflects real use.
