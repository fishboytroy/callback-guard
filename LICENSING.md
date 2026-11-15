# Licensing and editions

Callback Guard is **source-available** under the [Business Source License 1.1](LICENSE),
not an OSI open-source license. This page explains what that means in practice
and how the planned paid editions relate to the free one.

> This document describes intent, not legal advice. The [LICENSE](LICENSE) file
> is the binding text. Have a lawyer review the license parameters (Licensor
> name, Change Date, Additional Use Grant) before you rely on them commercially.

## What the BSL allows today

- **Read, copy, modify, and redistribute** the source freely.
- **Non-production use** (evaluation, development, testing, research) with no
  restriction.
- **Production use inside your own organization** — see the Additional Use Grant
  in [LICENSE](LICENSE).
- What you may **not** do: offer Callback Guard (modified or not) to third
  parties as a hosted/managed/SaaS product or a competing commercial scanning
  service. That needs a commercial license.
- On the **Change Date** (currently 2030-11-15), each released version converts
  to **Apache-2.0**, a full open-source license.

## Editions

The free edition is the complete local scanner. Paid editions are planned around
the team and fleet features that a local tool cannot provide; they are **not**
in this repository.

| | Community (this repo) | Pro | Business |
| --- | --- | --- | --- |
| License | BSL 1.1 | Commercial | Commercial |
| Scanner engine (all detection, CLI + GUI) | Yes | Yes | Yes |
| Local reports and allowlist | Yes | Yes | Yes |
| Centrally-managed policy & allowlists | — | Yes | Yes |
| Signature / rule updates feed | — | Yes | Yes |
| CI/CD integration & team reporting | — | Yes | Yes |
| SSO, audit logs, shared dashboard | — | — | Yes |
| Non-Windows / enterprise AV backends | — | — | Yes |
| Support | Community | Email | SLA |

The split is deliberate: the detection engine is free so people can trust and
adopt it; the paid value is the management, update, and support layer around it.

## Contributing and the right to sell

Because paid editions reuse this code, the project must retain the right to
relicense contributions. Contributions are therefore accepted under the
Developer Certificate of Origin (see [CONTRIBUTING.md](CONTRIBUTING.md)); by
signing off a commit you certify you may submit it and license it under this
project's terms. Keep this in place **before** accepting outside contributions,
or the dual model becomes legally difficult to maintain.
