# Contributing

Thanks for your interest in Callback Guard.

## License of contributions and the DCO

Callback Guard is source-available under the [Business Source License 1.1](LICENSE),
and paid editions reuse this code (see [LICENSING.md](LICENSING.md)). For that to
stay possible, every contribution must be one the project can license under those
terms.

We use the **Developer Certificate of Origin (DCO)**. Sign off each commit:

```
git commit -s -m "Your message"
```

The `-s` adds a `Signed-off-by: Your Name <you@example.com>` line, which certifies
you wrote the change (or have the right to submit it) and agree it may be licensed
under this project's terms. Pull requests whose commits are not signed off cannot
be merged. The full DCO text is at https://developercertificate.org/.

## Development

- Python 3.12 or newer. No third-party packages are required; the GUI also needs
  Tkinter.
- Run the tests before opening a pull request:

  ```
  python -m unittest -v test_guard.py test_automatic.py test_apk_inspection.py
  ```

- Run the detection benchmark and keep it from regressing:

  ```
  python bench.py
  ```

  New detections should add a corpus sample and a unit test; changes that touch
  rule severity should keep the benchmark's false-positive rate at zero.

## Scope and safety

- Do not commit working malware. Detection fixtures in `corpus/malicious/` must be
  inert; cover riskier techniques with unit tests using short inline snippets.
- Keep findings fail-closed: anything the scanner cannot analyze should be held,
  not passed.
