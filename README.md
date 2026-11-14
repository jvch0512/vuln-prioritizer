# vuln-prioritizer

A scanner that reports 3,000 findings with CVSS 7 or more is not a plan, it is a backlog nobody will clear. What decides which vulnerability hurts you is not the base score: it is whether it is being exploited, whether it faces the internet, and what it sits on. vuln-prioritizer takes your findings and puts them in an order you can defend.

**Live demo:** https://jvch0512.github.io/vuln-prioritizer/ (a report on 39 synthetic findings with fictional CVE-2099 identifiers)

R, base R only, no packages.

## Use

```bash
Rscript bin/vuln-prioritizer findings.csv
Rscript bin/vuln-prioritizer findings.csv --html > report.html
Rscript bin/vuln-prioritizer findings.csv --top 25 --fail-on-p0     # exit 1 if anything is P0
```

Input is a CSV with `host`, `cve`, `cvss`, and optionally `epss`, `kev` (yes/no), `criticality` (1 to 5) and `exposed` (yes/no). Missing optional columns get neutral defaults (EPSS 1%, criticality 3, not exposed). Export EPSS and the CISA KEV flag from your scanner or from the public feeds, nothing is fetched at run time.

How it scores:

```
likelihood = EPSS, raised to at least 0.9 if the vulnerability is on the CISA KEV list
score      = (0.35 x CVSS/10 + 0.65 x likelihood) x asset criticality x exposure     (0..100)
P0 fix now      known exploited and internet-facing, or score 70+
P1 this sprint  score 40+
P2 this quarter score 20+
P3 backlog      the rest
```

The report opens with the comparison that sells the idea: how many findings CVSS 7+ would call urgent, how many are really urgent, how many high-CVSS findings fall away, and which low-CVSS findings rise.

See [examples/findings.csv](examples/findings.csv) and [docs/sample-output.txt](docs/sample-output.txt).

## Limits

- The weights and thresholds are a defensible default, not a law. Change `R/prioritize.R` to match your risk appetite, and say so in your report.
- The ordering is only as good as the inputs: stale EPSS, a wrong criticality or a missing KEV flag changes the result. A finding with no exploitation data gets a low likelihood, which is a reasoned default and not a guarantee.
- It does not model compensating controls (WAF, segmentation) or attack chains. Two medium findings that chain into a critical one will not be linked.

## Where it fits

Vulnerability management reporting, "why we patched these 40 and not those 2,000" for auditors and boards, a pre-sales or consulting deliverable, and a quick triage of a scanner export.

## Tests

```bash
make test    # 23 checks
```

MIT.
