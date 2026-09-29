# Assignment 2 — GoFood Security Exercise (Q1–Q10)

Solution to the "Practical Exercise: SPA Security — GoFood" assignment sheet.

## Layout

```
tarefa2-exercicio/
├── docs/
│   ├── 01-solucao-exercicio.md          # full Q1-Q10 answers
│   └── 02-relatorio-sast-comparativo.md # comparative SAST report (with limitations)
├── backend/                             # fixed code (Q4, Q5, Q7)
│   ├── auth.js  orders.js  server.js  db.js
├── frontend/
│   └── src/App.jsx                      # fixed frontend (Q6)
├── analise-seguranca/
│   ├── codigo-vulneravel/               # original vulnerable code from the sheet (V1-V20)
│   ├── rules.yml                        # SAST rules (shared with Assignment 1)
│   ├── vulneravel-results.json          # SAST findings on the vulnerable code
│   └── corrigido-results.json           # SAST findings on the fixed code
└── sonar-project.properties             # SonarCloud config (runs in CI)
```

## Where to start

The full answers (Q1 through Q10, with the reasoning for each attack and
the fixed code) are in
[`docs/01-solucao-exercicio.md`](./docs/01-solucao-exercicio.md).

The evidence that the fixed code actually removes the vulnerabilities
(real SAST + DAST, server running and attacked over HTTP) is in
Assignment 1: [`../tarefa1-sast-dast/TAREFA1-SAST-DAST.md`](../tarefa1-sast-dast/TAREFA1-SAST-DAST.md).

## Running the fixed backend locally

```bash
cd backend
npm install
node server.js   # http://localhost:3002 (uses the in-memory db mock in db.js)
```
