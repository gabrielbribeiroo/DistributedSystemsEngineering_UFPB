# Assignment 1 — SAST & DAST on the GoFood server (before / after)

Applies static (SAST) and dynamic (DAST) analysis to two versions of the
same server: `vuln/` (original state, with `V1`-`V20`) and `fixed/`
(corrected version, see Assignment 2 / Q4-Q7).

Full report with evidence: [`TAREFA1-SAST-DAST.md`](./TAREFA1-SAST-DAST.md)

## How to reproduce

```bash
# 1. install dependencies for both servers
cd vuln && npm install && cd ../fixed && npm install && cd ..

# 2. SAST (custom rule-based scanner, see rules.yml)
node sast_scan.js vuln  sast-vuln-results.json
node sast_scan.js fixed sast-fixed-results.json

# 3. DAST — vulnerable server (port 3001)
node vuln/server.js &
python dast_probe.py http://localhost:3001 vuln-dast.json
kill %1

# 4. DAST — fixed server (port 3002)
node fixed/server.js &
python dast_probe_fixed.py http://localhost:3002 fixed-dast.json
kill %1
```

## Summary of results

| | SAST (findings) | DAST (exploitable vectors) |
|---|---|---|
| `vuln/` | 11 | 9/9 |
| `fixed/` | 0 | 0/10 |

## Methodology note (transparency)

The `semgrep` binary and its official rule registry were not reachable in
the environment used to build this repository. Instead of skipping the
SAST step, `sast_scan.js` was written: a regex-based scanner (same idea
as Semgrep — rule → pattern → file/line → finding) with rules documented
in `rules.yml`, mapped to the `V1`-`V20` vulnerabilities. **DAST was
actually executed**: both servers were started locally (in-memory mock
database in `db.js`) and attacked with real HTTP requests via
`dast_probe.py` / `dast_probe_fixed.py` — this is not a simulation, the
results in `vuln-dast.json` / `fixed-dast.json` come from real runs.
