# DistributedSystemsEngineering_UFPB

Repository for the assignments of the **Distributed Systems Engineering**
course, Computer Science program at the Federal University of Paraíba
(UFPB), semester 2026.2.

- **Professor:** Raoni Kulesza
- **Term:** P7 - 2026.2

Two assignments so far, both centered on application security (Material
2: Information Security). **Assignment 1** applies SAST and DAST to a
small Express server, comparing an intentionally vulnerable version
against a fixed one — the DAST is real: both servers are actually started
and attacked over HTTP, not simulated. **Assignment 2** is the "GoFood"
exercise: a SPA (React) + REST API (Node/Express) e-commerce app shipped
with 20 seeded vulnerabilities (`V1`-`V20`), which we map to the OWASP Top
10 (2021), analyze as concrete attacks (XSS token theft, SQL injection),
and fix module by module (auth, orders, server config, frontend), closing
with a sequence diagram, a defense-in-depth architecture discussion, and a
DevSecOps pipeline proposal.

## Author

[<img src="https://github.com/gabrielbribeiroo.png?size=100" width=100><br><sub>Gabriel Ribeiro</sub>](https://github.com/gabrielbribeiroo)

## Assignments

| #  | Topic                                              | Directory                                            | Status    |
| -- | --------------------------------------------------- | ----------------------------------------------------- | --------- |
| 1  | SAST & DAST on a server, before/after a fix          | [`tarefa1-sast-dast/`](./tarefa1-sast-dast)           | Delivered |
| 2  | GoFood — SPA Security Exercise (OWASP Top 10, Q1-Q10)| [`tarefa2-exercicio/`](./tarefa2-exercicio)           | Delivered |

Each directory contains its own `README.md` with usage instructions, plus
the reports/answers for that assignment.

## Layout

```
DistributedSystemsEngineering_UFPB/
├── README.md                      # this file
├── .gitignore
├── tarefa1-sast-dast/              # Assignment 1 - SAST & DAST, before/after
│   ├── README.md
│   ├── TAREFA1-SAST-DAST.md        # report: 11 SAST findings / 9-9 -> 0-10 in DAST
│   ├── rules.yml                   # SAST rules (regex-based, Semgrep-style)
│   ├── sast_scan.js                # SAST scanner (no semgrep binary available)
│   ├── dast_probe.py               # DAST probe against the vulnerable server
│   ├── dast_probe_fixed.py         # DAST probe against the fixed server
│   ├── sast-vuln-results.json / sast-fixed-results.json
│   ├── vuln-dast.json / fixed-dast.json
│   ├── vuln/                       # vulnerable server (Express + in-memory db mock)
│   └── fixed/                      # fixed server (bcrypt, JWT expiry, cookies, zod, helmet...)
└── tarefa2-exercicio/               # Assignment 2 - GoFood security exercise
    ├── README.md
    ├── docs/
    │   ├── 01-solucao-exercicio.md          # Q1-Q10 answers
    │   └── 02-relatorio-sast-comparativo.md # comparative SAST report (with limitations)
    ├── backend/                    # fixed backend (Q4, Q5, Q7)
    ├── frontend/src/App.jsx        # fixed frontend SPA (Q6)
    ├── analise-seguranca/
    │   ├── codigo-vulneravel/      # original vulnerable code from the assignment sheet
    │   ├── rules.yml
    │   ├── vulneravel-results.json / corrigido-results.json
    └── sonar-project.properties    # SonarCloud config (Q10 - DevSecOps pipeline)
```

## Quick start

Each subdirectory is self-contained and has its own `README.md` with
detailed instructions. The common cases:

```sh
# Assignment 1 — install deps for both servers
cd tarefa1-sast-dast/vuln  && npm install && cd ../fixed && npm install && cd ..

# Assignment 1 — run the custom SAST scanner (Semgrep-style regex rules)
node sast_scan.js vuln  sast-vuln-results.json
node sast_scan.js fixed sast-fixed-results.json

# Assignment 1 — run DAST against the vulnerable server (real HTTP attacks)
node vuln/server.js &
python dast_probe.py http://localhost:3001 vuln-dast.json

# Assignment 1 — run DAST against the fixed server
node fixed/server.js &
python dast_probe_fixed.py http://localhost:3002 fixed-dast.json

# Assignment 2 — run the fixed GoFood backend
cd tarefa2-exercicio/backend
npm install
node server.js   # http://localhost:3002 (in-memory db mock)
```

## Tech stack

- **Node.js / Express** for both server implementations (vulnerable and
  fixed), with an in-memory mock database so nothing depends on a real
  Postgres/MySQL instance.
- **jsonwebtoken**, **bcryptjs**, **zod**, **helmet**,
  **express-rate-limit**, **cookie-parser**, **cors** for the security
  fixes (Assignment 2, Q4-Q7).
- **React** + **DOMPurify** for the fixed SPA frontend.
- **Python 3** (standard library only) for the DAST probes.
- A small **custom SAST scanner** (`sast_scan.js`, regex-based rules in
  `rules.yml`) used in place of Semgrep, whose binary/rule registry
  wasn't reachable in the environment this repo was built in — see the
  methodology note in `tarefa1-sast-dast/README.md`.
- **OWASP ZAP**, **Burp Suite**, **SpiderFoot**, **SqlMap** referenced as
  pentest tooling in the DevSecOps pipeline discussion (Assignment 2, Q10).

## Note on AI usage

Part of this material was produced with the help of an AI assistant
(Claude) and reviewed by the author.
