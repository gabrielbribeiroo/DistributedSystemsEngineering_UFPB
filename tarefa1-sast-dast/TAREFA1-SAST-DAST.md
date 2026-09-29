# Tarefa 1 — SAST e DAST no servidor GoFood (antes e depois)

**Aluno:** Gabriel · Engenharia de Sistemas Distribuídos — UFPB

Este relatório aplica SAST e DAST às duas versões do servidor GoFood
mantidas neste diretório: `vuln/` (código do enunciado, com as
vulnerabilidades V1–V20) e `fixed/` (código corrigido, correspondente às
respostas Q4–Q7 da Tarefa 2).

## 1. Metodologia

- **SAST**: `sast_scan.js`, um scanner baseado em regras (regex por
  linha, mesmo princípio do Semgrep), definidas em `rules.yml` e
  mapeadas a V1–V20 / OWASP Top 10. Usado porque o binário `semgrep` e o
  registry oficial de regras não estavam acessíveis no ambiente de
  execução — ver nota de transparência no `README.md`.
- **DAST**: os servidores `vuln/server.js` (porta 3001) e
  `fixed/server.js` (porta 3002) foram **efetivamente executados**
  localmente (com um banco em memória mockado em `db.js`, sem
  dependência de Postgres real) e atacados via requisições HTTP reais
  por `dast_probe.py` / `dast_probe_fixed.py`.

## 2. Resultado SAST

### `vuln/` — 11 achados

| Regra | Arquivo:linha | OWASP | Vulnerabilidade |
|---|---|---|---|
| hardcoded-jwt-secret | auth.js:6 | A02 | V1 — secret hardcoded |
| sql-string-concat-template | auth.js:12 | A03 | V2 — query concatenada no login |
| plaintext-password-in-query | auth.js:12 | A02 | V2 — senha comparada em texto claro |
| jwt-sign-no-expiry | auth.js:21 | A07 | V3 — token sem expiração |
| auth-header-token | auth.js:31 | A05 | V5/V12 — token via header, sem cookie HttpOnly |
| sql-string-concat-template | orders.js:9 | A03 | V6 — query concatenada em /orders/:id |
| sql-string-concat-template | orders.js:20 | A03 | V9 — insert concatenado |
| admin-route-no-role-check | orders.js:25 | A01 | V10 — rota admin sem checagem de role |
| cors-open | server.js:7 | A05 | V16 — CORS aberto |
| json-body-no-limit | server.js:8 | A05 | V17 — sem limite de tamanho de body |
| error-handler-exposes-stack | server.js:20 | A05 | V20 — stack trace exposto |

*(V4, V7, V8, V13–V15, V18–V19 não são detectáveis por regex simples sobre
o backend puro — V13–V15 vivem no frontend React, V7/V8 exigem entender o
fluxo de dados, e V18/V19 são *ausência* de configuração, não um padrão
para casar. Foram cobertas manualmente na análise da Tarefa 2, Q1.)*

### `fixed/` — 0 achados

Nenhuma das regras acima disparou no código corrigido — as queries são
parametrizadas, o secret vem de variável de ambiente, o JWT tem
`expiresIn`, o token é lido do cookie, a rota admin tem `requireRole`, o
CORS tem `origin` explícito, `express.json` tem `limit`, e o error handler
não expõe `err.stack`.

## 3. Resultado DAST (ataques reais via HTTP)

### `vuln/` rodando em `http://localhost:3001` — **9/9 vetores exploráveis**

| Vulnerabilidade | Teste executado | Resultado |
|---|---|---|
| V2 | Login com `' OR '1'='1' --` | Autenticou sem credenciais válidas |
| V4 | Inspeção do corpo da resposta de login | `token` e `role` expostos |
| V6 | `GET /orders/<UNION SELECT ... FROM users -->` com token roubado | Vazou `email`/`password`/`role` de todos os usuários |
| V9 | `POST /orders` com `price: 0.01` | Servidor aceitou o preço enviado pelo cliente |
| V10 | `GET /admin/orders` com token de usuário comum | Retornou 200 com todos os pedidos |
| V16 | Requisição com `Origin: https://evil.com` | Sem bloqueio (CORS aberto) |
| V18 | 10 tentativas de login em sequência | Nenhuma bloqueada (sem rate limit) |
| V20 | `POST /login` com JSON malformado | Resposta incluiu `stack` |
| **V8 (extra)** | `POST /orders` sem `items` | **O processo do servidor caiu inteiro** (TypeError não tratada em handler `async` → unhandled promise rejection → crash) |

> Achado não previsto no enunciado original: a ausência de validação de
> input (V8) não causa só dados inconsistentes — é um **DoS trivial**:
> uma única requisição malformada derruba o servidor inteiro, afetando
> todos os usuários, não só quem enviou a requisição.

### `fixed/` rodando em `http://localhost:3002` — **0/10 vetores exploráveis**

Todos os mesmos ataques foram repetidos (adaptando ao novo fluxo de
autenticação via cookie): SQL Injection, exposição de token/role, IDOR,
acesso admin sem role, CORS aberto, brute force sem rate limit, preço
manipulado pelo cliente, payload sem `items`, e JSON malformado. Nenhum
teve sucesso — o payload sem `items` retorna `400` (Zod) e o processo
segue de pé; o JSON malformado retorna erro genérico sem `stack`.

## 4. Conclusão

| Etapa | `vuln/` | `fixed/` |
|---|---|---|
| SAST — achados | 11 | 0 |
| DAST — vetores exploráveis | 9/9 | 0/10 |

A correção elimina, de forma verificável (estática **e** dinamicamente),
as vulnerabilidades identificadas no código original, incluindo um vetor
de negação de serviço (crash por exceção não tratada) que não estava
explicitamente listado como V1–V20 mas decorre diretamente de V8.

Os arquivos JSON brutos (`sast-vuln-results.json`, `sast-fixed-results.json`,
`vuln-dast.json`, `fixed-dast.json`) ficam neste diretório para conferência.
