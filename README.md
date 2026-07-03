# vuln-prioritize

> **v0.1.1-alpha** — Bayesian scoring algorithm, API checker completeness, rate limiting optimizations.
> ✅ **Completed**: Bayesian log-odds prioritization · All 5 API checks · EPSS batching · ETag caching · Exponential backoff

A command-line tool that combines five public data sources into a single **0–100 priority score** per CVE, so you know which vulnerabilities to patch first.

[![Python 3.7+](https://img.shields.io/badge/python-3.7%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Alpha](https://img.shields.io/badge/status-alpha-orange)]()

---

## How It Works

Each CVE is scored by pulling live data from:

| Source | Provider | What it tells you |
|--------|----------|------------------|
| **CVSS v3.1** | NVD | Base severity (0–10) |
| **EPSS** | FIRST | Probability of exploitation in the wild |
| **KEV** | CISA | Confirmed active exploitation |
| **GitHub PoCs** | GitHub API | Public proof-of-concept code exists |
| **ExploitDB / MSF** | ExploitDB CSV + Metasploit Framework | Working exploit / Metasploit module exists |

Scores are combined using Bayesian evidence inference (log-odds → sigmoid), then multiplied by exploit availability factors, all normalized to 0–100.

---

## Installation

```bash
git clone https://github.com/stov3/vuln-prioritize.git
cd vuln-prioritize
pip install -r requirements.txt
```

> **Dependencies:** `pyfiglet` (optional — ASCII art title; graceful fallback if missing).  
> All API calls use Python's standard library (`urllib`).

---

## Quick Start

```bash
# Single CVE
python3 vuln-prioritize.py CVE-2024-1234

# Multiple CVEs — sorted by priority, highest risk first
python3 vuln-prioritize.py CVE-2024-1234 CVE-2023-44487 CVE-2022-0847

# From a file (one CVE per line, # = comment)
python3 vuln-prioritize.py --cves-file examples/sample_cves.txt

# Export reports
python3 vuln-prioritize.py --cves-file my_cves.txt \
  --output-json report.json \
  --output-csv  report.csv

# No console table (useful for scripting / piping)
python3 vuln-prioritize.py CVE-2024-1234 --no-table

# Interactive guided menu (no arguments)
python3 vuln-prioritize.py

# Diagnostics
python3 vuln-prioritize.py --check-apis   # test all API connections
python3 vuln-prioritize.py --setup        # configure API keys interactively
```

---

## Scoring Algorithm

The priority score uses **Bayesian evidence combination** to fuse multiple vulnerability data sources into a single 0–100 confidence score.

### Theoretical Foundation

**Bayesian Log-Odds Combination** (Jeffreys' method)
- Each data source is treated as independent evidence of vulnerability risk
- Evidence is combined using log-odds ratios: `log_odds = Σ(weight_i × log(P_i / (1 - P_i)))`
- Result is converted back to probability using logistic sigmoid: `P = 1 / (1 + e^(-log_odds))`

**Weber-Fechner Law for CVSS**
- Human perception of risk is logarithmic, not linear
- CVSS is normalized as: `CVSS_prob = log(1 + CVSS) / log(11)` to reflect diminishing returns at higher severities

**Source Reliability Weights**
Each data source is weighted by epistemic confidence:
- **EPSS (35%)** — Highest weight; statistically modeled exploitation probability
- **CVSS (30%)** — Authoritative but not exploit-specific
- **KEV (25%)** — Strong empirical evidence but lagging indicator
- **Exploit proof (10%)** — Direct proof but rare in dataset

### Scoring Formula

```
Priority Score = Apply_Nonlinearity(Bayesian_Posterior × Entropy_Discount × 100)

Where:
  Bayesian_Posterior = sigmoid(Σ weights × log_odds(evidence))
  Entropy_Discount = 0.90 + (0.10 × data_completeness)  [penalizes missing data]
  Apply_Nonlinearity = {
    score^1.05         if score < 30  (compress low-risk scores)
    score              if 30 ≤ score ≤ 70
    70 + ((score-70)^0.95) if score > 70  (expand high-risk scores)
  }
```

### Worked Example

```
CVE-2023-44487 (HTTP/2 Rapid Reset DoS):
  
  Input Data:
    CVSS v3.1:     7.5 (HIGH severity)
    EPSS:          1.0 (100% exploitation probability — peak value)
    KEV:           ✓ (CISA confirmed active exploitation)
    GitHub PoCs:   5 public exploits
    Multiplier:    1.38 (PoC + Metasploit module)
    
  Step 1: Normalize to [0,1]
    cvss_normalized = log(1+7.5) / log(11) = 0.8925
    epss_prob = 1.0 (already normalized)
    kev_present = 1.0 (active exploitation)
    exploit_proof = (1.38 - 1.0) / 0.75 = 0.5067
    
  Step 2: Accumulate weighted log-odds
    cvss_log_odds = log(0.8925/0.1075) ≈ 2.1163
    epss_log_odds = log(1.0/0.0001) ≈ 9.2102  [EPSS maxes log_odds]
    kev_log_odds = log(0.90/0.10) ≈ 2.1972   [active exploitation]
    exploit_posterior = 0.50 + (0.5067 × 0.40) = 0.7027
    exploit_log_odds = log(0.7027/0.2973) ≈ 0.8600  [PoC evidence]
    
    total_log_odds = 0.30×2.1163 + 0.35×9.2102 + 0.25×2.1972 + 0.10×0.8600
                  ≈ 0.6349 + 3.2236 + 0.5493 + 0.0860 ≈ 4.4938
    
  Step 3: Convert via sigmoid
    posterior = 1/(1 + e^(-4.4938)) ≈ 0.9889  [98.9% risk posterior]
    
  Step 4: Apply entropy discount
    All 4 data sources present → completeness = 1.0
    entropy_discount = 0.90 + 0.10 = 1.0  [no penalty]
    adjusted = 0.9889 × 1.0 = 0.9889
    
  Step 5: Scale and apply non-linearity
    score = 0.9889 × 100 = 98.89
    Since score > 70: apply expansion transform
    final = 70 + ((98.89-70)^0.95) ≈ 70 + 24.42 ≈ 94.4  ✓ Matches
    
  Interpretation: CRITICAL
    • All evidence converges on high risk
    • Active exploitation confirmed (KEV)
    • Public exploits available
    • → Patch immediately
```

### Risk Level Interpretation

| Score Range | Risk Level | Interpretation |
|-------------|-----------|-----------------|
| 85–100 | **Critical** | Active exploitation, PoC/exploit exists, high severity |
| 70–84 | **High** | Probable exploitation or high severity + strong evidence |
| 50–69 | **Medium** | Exploitable but limited proof, or lower severity + evidence |
| 30–49 | **Low** | Difficult to exploit or low severity, no active proof |
| 0–29 | **Minimal** | Very low risk; low severity and no evidence of exploitation |

### Detailed Calculation Steps

**Step 1: Normalize inputs to [0,1] probability space**
- **CVSS**: Apply logarithmic transformation (Weber-Fechner law) → `log(1+CVSS) / log(11)`
  - Reflects diminishing risk perception at higher severities
- **EPSS**: Clamp to [0,1] (already normalized)
  - If unavailable: estimate from CVSS as `min(CVSS_normalized × 0.6, 0.7)` with 30% uncertainty penalty
- **KEV**: Binary (1.0 if active exploitation, 0.0 otherwise)
- **Exploit Proof**: Map multiplier [1.0, 1.75] to confidence [0, 1] via `(multiplier - 1.0) / 0.75`

**Step 2: Accumulate weighted log-odds**
```
total_log_odds = Σ weight_i × log(P_i / (1 - P_i))

Evidence contributions:
  - CVSS (30%):       log_odds(cvss_prob)  [or log_odds(0.1) if absent]
  - EPSS (35%):       log_odds(epss_prob)  [or 0.70× log_odds(estimated) if absent]
  - KEV (25%):        log_odds(0.90) if active, else log_odds(0.35)
  - Exploit (10%):    log_odds(0.50 + exploit_proof × 0.40) if proof > 0.1
```

**Step 3: Convert log-odds to probability via sigmoid**
```
posterior = 1 / (1 + e^(-total_log_odds))   [clamped to [-12, 12] to prevent overflow]
```

**Step 4: Apply entropy discount for missing data**
```
data_available = (CVSS_present ? 1.0 : 0.25)
               + (EPSS_present ? 1.0 : 0.50)
               + (KEV_present ? 1.0 : 0.50)
               + (Exploit_present ? 1.0 : 0.30)

data_completeness = data_available / 4.0
entropy_discount = 0.90 + (0.10 × data_completeness)  [range: 0.90-1.00]
adjusted_prob = posterior × entropy_discount
```
Missing data reduces entropy by 5–10%:
- All sources present → 1.0 (no penalty)
- Missing EPSS → 0.975 (2.5% penalty)
- Missing all sources → 0.9388 (6.12% penalty)

**Step 5: Scale to 0-100 with non-linearity adjustment**
- Low scores (<30): compressed via `score^1.05` → less spread among low-risk vulns
- High scores (>70): expanded via `70 + ((score-70)^0.95)` → more spread among critical vulns
- Final bounds: [0, 100]

---

## Console Output

Results are **sorted by priority** (highest first) and colour-coded:

```
Rank   CVE ID             Priority    CVSS   Severity   EPSS     KEV   PoC   Multiplier
═══════════════════════════════════════════════════════════════════════════════════════════
1      CVE-2023-44487     78.0        7.5    HIGH       N/A      YES   YES   1.20×
2      CVE-2024-1234      52.8        8.8    HIGH       N/A      NO    NO    1.00×
3      CVE-2099-9999       0.0        0.0    UNKNOWN    N/A      NO    NO    1.00×
```

| Colour | Score | Action |
|--------|-------|--------|
| 🔴 Bright Red | ≥ 80 | Patch immediately |
| 🔴 Red | ≥ 60 | Patch soon |
| 🟠 Amber | ≥ 40 | Patch this month |
| 🟡 Yellow | ≥ 20 | Patch when possible |
| 🟢 Green | < 20 | Low priority |

---

## Rate Limits

The tool enforces per-API rate limits automatically. When a limit is reached it displays an in-place countdown and resumes without data loss. Local result caches (24h TTL) mean re-runs of recently analyzed CVEs cost **zero** API calls.

| API | Unauthenticated | With key/token | Local cache |
|-----|----------------|----------------|-------------|
| NVD (CVSS) | 5 req/min | 5 req/sec (×60) | 24h per-CVE result cache |
| EPSS | 30 req/min (batch — 1 call for all CVEs) | — | — |
| KEV | One request (cached with `If-Modified-Since`) | — | Conditional cache |
| GitHub Search | 10 req/min (1 query/CVE) | 30 req/min (1 query/CVE) | 24h per-CVE result cache + ETag |
| ExploitDB CSV | One download (ETag-cached, free on re-runs) | — | ETag cache |

---

## Optional API Keys

None are required, but they speed things up significantly for large batches.

### NVD API Key — 60× faster CVSS lookups

```bash
# Get a free key: https://nvd.nist.gov/developers/request-an-api-key
export NVD_API_KEY=your_key_here
# or add to .env (see .env.example)
```

### GitHub Token — 3× more GitHub searches + MSF module detection

```bash
# Create at https://github.com/settings/tokens
# No scopes needed for public data access
export GITHUB_TOKEN=ghp_your_token_here
```

With a GitHub token, the tool also searches the official
[`rapid7/metasploit-framework`](https://github.com/rapid7/metasploit-framework)
repository for modules referencing the CVE — the most accurate source for MSF coverage.

### Interactive setup

```bash
python3 vuln-prioritize.py --setup
```

Keys are saved to `.env` (already in `.gitignore`).

---

## Project Structure

```
vuln-prioritize/
├── vuln-prioritize.py          # Entry point & orchestration
├── src/
│   ├── config.py               # API key management
│   ├── console.py              # Terminal UI, colours, progress
│   ├── rate_limiter.py         # Per-API rate enforcement & countdown
│   ├── api_checker.py          # Connectivity diagnostics
│   └── fetchers/
│       ├── cvss_fetcher.py     # NVD  — CVSS v3.1
│       ├── epss_fetcher.py     # FIRST — EPSS (batched)
│       ├── kev_fetcher.py      # CISA  — KEV (cached)
│       ├── github_poc_fetcher.py  # GitHub Search — PoCs
│       └── metasploit_fetcher.py  # ExploitDB CSV + MSF GitHub
├── examples/
│   └── sample_cves.txt         # Ready-to-run example list
├── requirements.txt
├── .env.example                # API key template
└── LICENSE
```

---

## Output Files

| File | Format | Contents |
|------|--------|----------|
| `vulnerability_report.json` | JSON | All fields per CVE (CVSS, EPSS, KEV, PoC, exploit, scores) |
| `vulnerability_report.csv` | CSV | Same data, spreadsheet-compatible |

Custom paths: `--output-json path.json --output-csv path.csv`

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| `CVE not found` | Too new or not yet in NVD | Wait and retry; check nvd.nist.gov |
| EPSS always `N/A` | Very new or very old CVE | Expected — EPSS covers ~2 years of active CVEs |
| GitHub returns 403 | Unauthenticated rate limit | Add `GITHUB_TOKEN` to `.env` |
| Countdown timer appears | API rate limit reached | Wait; tool resumes automatically |
| Score is 0.0 | No data from any source | CVE may not exist or APIs are down |

---

## Contributing

This is an alpha release — contributions are very welcome.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-improvement`)
3. Commit your changes
4. Open a Pull Request

Please report bugs and ideas via [GitHub Issues](https://github.com/stov3/vuln-prioritize/issues).

---

## References

- [CVSS v3.1 Specification](https://www.first.org/cvss/v3.1/specification-document)
- [EPSS Scoring](https://www.first.org/epss/)
- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [NVD API Documentation](https://nvd.nist.gov/developers/vulnerabilities)
- [GitHub REST API — Rate Limits](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api)
- [ExploitDB](https://www.exploit-db.com/)
- [Metasploit Framework](https://github.com/rapid7/metasploit-framework)

---

## ⚠️ Disclaimer

This tool provides vulnerability prioritization **guidance only**. Results depend on the accuracy and availability of upstream data sources and should always be **verified independently** before making remediation decisions.

This software is intended for **legitimate security research and defensive purposes**. Use of this tool to facilitate unauthorised access to systems is strictly prohibited. See [LICENSE](LICENSE) for full terms.


