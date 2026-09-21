# jev-policy-lint

`jevlint` lints a **witness / cilock / pushgate** policy for *meaning*, not schema.

`cilock policy validate` tells you a policy parses. It does not tell you the
policy will refuse every push, admit every tenant, verify nothing, or quietly
got weaker than the last release. Those pass validation and still break a repo —
one signed draft in the wild denied every push because a rendered Rego rule had
an unconditional `deny`, and `validate` was green.

`jevlint` reads the policy the way a reviewer would, and diffs two versions to
catch a gate being silently loosened.

## Install

```
go install github.com/manzil-infinity180/jev-policy-lint@latest
```

or build from source:

```
git clone https://github.com/manzil-infinity180/jev-policy-lint
cd jev-policy-lint && go build -o jevlint .
```

## Use

```
jevlint lint <policy.json>              # structural + Jev
jevlint lint <policy.json> --structural-only   # deterministic only, no key, no egress
jevlint diff <old.json> <new.json>      # flag where NEW is weaker than OLD
jevlint version
```

The API key is read, in order, from `--api-key`, `$TYPESAFE_API_KEY` /
`$JEVLINT_API_KEY`, `~/.config/typesafe/api_key`, then the macOS keychain.

## Two kinds of check

| kind | how | catches |
|---|---|---|
| **structural** | deterministic, never calls Jev, never fails open | no `roots`, no `timestampauthorities`, no intermediates, expired policy, a step with no functionary, a functionary that admits any tenant via `spiffe://…/*`, empty cert constraints, an **unconditional `deny`** (blatant case, caught offline), and a **secret in the policy** — a private key or API token where only public certs and Rego belong |
| **semantic** | a typed judgment from [TypeSafe Jev](https://typesafe.ai) over the decoded Rego | subtler **unconditional denials**, an **underspecified check** (reads a field it never compares), and — with `--context` — an **over-scoped** policy |

The flagship check — a deny that refuses all evidence — is caught **both**
deterministically (so `--structural-only` and keyless CI catch the blatant case)
and by Jev (for the subtle ones); the two are de-duplicated so it reports once.

The split is deliberate. Anything security-critical and decidable from the
document is deterministic, so an outage can never turn it into "looks fine". Jev
is used only where a schema validator is blind — reading intent out of Rego. A
Jev call that cannot answer (no key, timeout, non-2xx, junk) is reported as
`COULD-NOT-CHECK` and the tool exits `2`. It is never counted as a pass.

## Configuration

cobra + viper, so every flag has an env and config-file equivalent, in
precedence order flag → env → config → default:

| flag | env | config key | default |
|---|---|---|---|
| `--model` | `JEVLINT_MODEL` | `model` | `jev-1.13.0` |
| `--min-prob` | `JEVLINT_MIN_PROB` | `min-prob` | `0.70` |
| `--api-key` | `TYPESAFE_API_KEY` | `api-key` | file / keychain |
| `--json` | `JEVLINT_JSON` | `json` | `false` |

Config file: `~/.config/jevlint/config.yaml` (or `--config <path>`).

## Try it

```
jevlint lint examples/deny-everything.policy.json   # flags HIGH: unconditional-deny + wildcard functionary
jevlint lint examples/good.policy.json              # clean
jevlint diff examples/good.policy.json examples/deny-everything.policy.json   # weakening
```

## Exit codes

`0` clean · `1` findings (or weakenings) · `2` could-not-check or error. The `2`
maps onto a gate that must refuse rather than guess.

## Thresholds

From adversarial testing of Jev on supply-chain evidence: refuse at **~0.90**,
warn from **~0.60**. `--min-prob` sets where a finding is reported. Jev is a
strong presence-and-behaviour detector but a poor version oracle — it confuses a
patched dependency with a vulnerable one — so `jevlint` never asks it CVE or
version questions. Treat every Jev finding as a reviewer's flag, not a verdict.

## What it does not do

- It does not evaluate the policy against evidence — that is `cilock` / `pushgate`.
- It does not judge CVEs or versions — that belongs in `govulncheck` / `osv-scanner`.

## Scope

The witness policy document is shared across cilock and pushgate, so one linter
covers all three; `jevlint` auto-detects the flavor and `--type` overrides it.
