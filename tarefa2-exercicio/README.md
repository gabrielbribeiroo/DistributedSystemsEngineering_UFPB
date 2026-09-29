# Tarefa 2 — Exercício GoFood (Q1–Q10)

Resolução do "Exercício Prático: Segurança em SPA — GoFood".

## Estrutura

```
tarefa2-exercicio/
├── docs/
│   ├── 01-solucao-exercicio.md          # respostas Q1–Q10 completas
│   └── 02-relatorio-sast-comparativo.md # relatório SAST (com limitações)
├── backend/                             # código corrigido (Q4, Q5, Q7)
│   ├── auth.js  orders.js  server.js  db.js
├── frontend/
│   └── src/App.jsx                      # frontend corrigido (Q6)
├── analise-seguranca/
│   ├── codigo-vulneravel/               # código original do enunciado (V1-V20)
│   ├── rules.yml                        # regras de SAST (compartilhadas com a Tarefa 1)
│   ├── vulneravel-results.json          # achados SAST no código vulnerável
│   └── corrigido-results.json           # achados SAST no código corrigido
└── sonar-project.properties             # config para SonarCloud (roda no CI)
```

## Onde começar

As respostas completas (Q1 a Q10, com o raciocínio de cada ataque e o
código corrigido) estão em
[`docs/01-solucao-exercicio.md`](./docs/01-solucao-exercicio.md).

A validação de que o código corrigido realmente elimina as
vulnerabilidades (SAST + DAST real, servidor rodando e sendo atacado via
HTTP) está na Tarefa 1: [`../tarefa1-sast-dast/TAREFA1-SAST-DAST.md`](../tarefa1-sast-dast/TAREFA1-SAST-DAST.md).

## Rodando o backend corrigido localmente

```bash
cd backend
npm install
node server.js   # http://localhost:3002 (usa banco em memória mockado em db.js)
```
