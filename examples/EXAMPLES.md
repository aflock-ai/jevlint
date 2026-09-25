# jevlint examples

Every example here was run through `jevlint` and its documented findings/exit
match the tool's actual output. Names ending `.policy.json` are witness-model
policies (the shape shared by witness, cilock and pushgate).

## How to test

Two modes:

```
# deterministic only — no API key, no network. Catches the worst bugs offline.
jevlint lint examples/<name>.policy.json --structural-only

# full — adds TypeSafe Jev's semantic checks (unconditional-deny on subtle cases,
# underspecified-check, and — with --context — over-scoped). Needs a key:
export TYPESAFE_API_KEY="$(cat ~/.config/typesafe/api_key)"
jevlint lint examples/<name>.policy.json
```

Jev findings are reported at calibrated per-question thresholds (see the README);
`--min-prob <n>` overrides them with one threshold for every question. Exit
codes: `0` clean · `1` findings (or weakenings) · `2` could-not-check or error.
A `REVIEW` is shown but does not fail the run.

## Lint examples (verified)

| example | mode to see it | findings | exit |
|---|---|---|---|
| `clean-cert.policy.json` | either | *clean* | 0 |
| `clean-keybased.policy.json` | either | *clean* (public-key policy: no roots/TSA needed) | 0 |
| `unconditional-deny.policy.json` | either | HIGH `unconditional-deny` | 1 |
| `wildcard-functionary.policy.json` | either | HIGH `wildcard-functionary` | 1 |
| `mixed-uri.policy.json` | either | HIGH `wildcard-functionary` (caught beside a pinned URI) | 1 |
| `trusts-any-root.policy.json` | either | MEDIUM `trusts-any-root` | 1 |
| `no-roots.policy.json` | either | HIGH `no-roots` | 1 |
| `missing-tsa.policy.json` | either | LOW `no-tsa` | 1 |
| `expired.policy.json` | either | HIGH `expired` | 1 |
| `expiring-soon.policy.json` | either | MEDIUM `expiring-soon` | 1 |
| `no-functionary.policy.json` | either | HIGH `no-functionary` | 1 |
| `private-key-in-root.policy.json` | either | HIGH `secret-in-policy` | 1 |
| `token-in-rego.policy.json` | either | HIGH `secret-in-policy` | 1 |
| `underspecified.policy.json` | **full Jev** | MEDIUM `underspecified-check` | 1 |
| `over-scoped.policy.json` | **full Jev + `--context`** | MEDIUM `over-scoped` | 1 |
| `good.policy.json` | either | *clean* | 0 |
| `deny-everything.policy.json` | either | HIGH `unconditional-deny`, `wildcard-functionary`; LOW `no-tsa`, `no-intermediates` | 1 |
| `leaky.policy.json` | either | HIGH `unconditional-deny`, `wildcard-functionary`, `secret-in-policy`; LOW `no-tsa`, `no-intermediates` | 1 |

Notes:
- `underspecified` and `over-scoped` are **Jev-only** — under `--structural-only`
  they report clean (exit 0). Run them with a key to see the finding.
- `over-scoped` needs repo context, or the check is skipped:
  ```
  jevlint lint examples/over-scoped.policy.json --context "README-only docs repo, no build, no tests"
  ```
  Without `--context` it is clean (exit 0).
- The flagship `unconditional-deny` is caught **both** deterministically and by
  Jev; the two are de-duplicated so it reports once.

## Diff examples (verified)

`diff` flags where a NEW policy is weaker than the OLD one:

```
jevlint diff examples/diff/base.policy.json examples/diff/weakened.policy.json
```

Output: HIGH `check-dropped` (secretscan removed), HIGH `functionary-widened`
(pinned → wildcard), MEDIUM `tsa-removed`, MEDIUM `rule-dropped` (the
`no-secrets` rule). 4 weakenings, exit 1.

## Real witness policies (verified clean)

`examples/real/` holds two **real** policies from the witness test suite
(`~/work-dir/witness/test/`), included to prove jevlint is correct on genuine
files across both trust models:

- `witness-fulcio.policy.json` — cert/keyless (decoded from the signed DSSE
  `fulcio-policy-presigned.json`).
- `witness-keybased.policy.json` — public-key (`policy.json`).

Both lint **clean** (exit 0), including the key-based one that has no roots or
TSA by design:

```
jevlint lint examples/real/witness-fulcio.policy.json --structural-only
jevlint lint examples/real/witness-keybased.policy.json --structural-only
```

## Run the whole suite

```
export TYPESAFE_API_KEY="$(cat ~/.config/typesafe/api_key)"
for f in examples/*.policy.json examples/real/*.policy.json; do
  echo "== $f"
  jevlint lint "$f" ${JEV:+} --structural-only || true   # drop --structural-only for full Jev
done
jevlint diff examples/diff/base.policy.json examples/diff/weakened.policy.json || true
```
