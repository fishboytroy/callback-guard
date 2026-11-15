"""Detection benchmark for Callback Guard.

Runs the current scanner's static inspection over every sample in
corpus/manifest.json and reports detection and false-positive rates. This is the
Phase 0 baseline: it does not call antivirus and does not download anything, so
it runs the same on any machine and in CI.

A sample is "held" if static inspection returns at least one finding. That
mirrors guard.run's status logic, where any finding blocks `checks-passed`.

Exit code:
  0  every present sample met its expectation (perfect score)
  1  at least one miss or false positive
  2  corpus/manifest problem (cannot run)

Use --strict in CI once the engine is improved, to fail the build on any
regression. Without it, the script still prints the scorecard and exits 1 on
imperfect results but is meant for local inspection.
"""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CORPUS = ROOT / 'corpus'

# Make `import guard` work regardless of how the script is launched, including
# under isolated flags (python -I / -E -s) that drop the script directory.
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
import guard  # noqa: E402


def findings_for(path):
    """Static inspection only (no antivirus, no network). Returns a findings list.

    A raised exception from archive handling counts as held (the scanner stops),
    represented here as a synthetic finding so the sample is scored as detected.
    """
    data = path.read_bytes()
    try:
        return guard.inspect_payload(data, path.name)
    except Exception as exc:  # oversized/unsafe archive etc. -> scanner holds
        return [{'rule': 'held-exception', 'file': path.name, 'reason': str(exc)}]


def load_manifest():
    manifest_path = CORPUS / 'manifest.json'
    if not manifest_path.is_file():
        print(f'ERROR: {manifest_path} not found', file=sys.stderr)
        sys.exit(2)
    try:
        return json.loads(manifest_path.read_text(encoding='utf-8'))
    except json.JSONDecodeError as exc:
        print(f'ERROR: manifest is not valid JSON: {exc}', file=sys.stderr)
        sys.exit(2)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--strict', action='store_true',
                        help='exit 1 on any miss or false positive (for CI)')
    parser.add_argument('--json', action='store_true',
                        help='emit machine-readable results instead of a table')
    args = parser.parse_args()

    manifest = load_manifest()
    samples = manifest.get('samples', [])
    if not samples:
        print('ERROR: manifest has no samples', file=sys.stderr)
        sys.exit(2)

    mal_total = mal_detected = 0
    ben_total = ben_clean = 0
    misses, false_positives, unsourced = [], [], []
    rows = []

    for entry in samples:
        rel = entry['path']
        label = entry['label']
        path = CORPUS / rel
        if not path.is_file():
            unsourced.append(rel)
            continue
        findings = findings_for(path)
        held = len(findings) > 0
        rules = sorted({f['rule'] for f in findings})
        rows.append({'path': rel, 'label': label, 'held': held, 'rules': rules})
        if label == 'malicious':
            mal_total += 1
            if held:
                mal_detected += 1
            else:
                misses.append(rel)
        elif label == 'benign':
            ben_total += 1
            if held:
                false_positives.append({'path': rel, 'rules': rules})
            else:
                ben_clean += 1

    # Count code techniques still to source (files absent by design).
    to_source = len(manifest.get('code_samples_to_source', []))

    det_rate = (mal_detected / mal_total * 100) if mal_total else 0.0
    fp_rate = (len(false_positives) / ben_total * 100) if ben_total else 0.0

    if args.json:
        print(json.dumps({
            'malicious_total': mal_total, 'malicious_detected': mal_detected,
            'detection_rate_pct': round(det_rate, 1),
            'benign_total': ben_total, 'false_positives': len(false_positives),
            'false_positive_rate_pct': round(fp_rate, 1),
            'misses': misses, 'false_positive_files': false_positives,
            'unsourced_present': unsourced, 'code_techniques_to_source': to_source,
            'rows': rows,
        }, indent=2))
    else:
        print('=' * 64)
        print('Callback Guard detection benchmark (static inspection only)')
        print('=' * 64)
        print(f'Malicious detected : {mal_detected}/{mal_total}  ({det_rate:.0f}% detection)')
        print(f'Benign clean       : {ben_clean}/{ben_total}  ({fp_rate:.0f}% false positives)')
        if misses:
            print('\nMISSED (malicious scanned clean):')
            for m in misses:
                print(f'  - {m}')
        if false_positives:
            print('\nFALSE POSITIVES (benign held):')
            for fp in false_positives:
                print(f"  - {fp['path']}  [{', '.join(fp['rules'])}]")
        if unsourced:
            print(f'\nUnsourced sample files (listed in manifest, not present): {len(unsourced)}')
        if to_source:
            print(f'Code techniques still to source into corpus/malicious/code/: {to_source}')
        print()

    perfect = not misses and not false_positives
    if args.strict:
        sys.exit(0 if perfect else 1)
    sys.exit(0 if perfect else 1)


if __name__ == '__main__':
    main()
