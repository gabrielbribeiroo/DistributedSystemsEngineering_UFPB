# Tarefa 1 — SAST e DAST no servidor GoFood (antes / depois)

Aplica análise estática (SAST) e dinâmica (DAST) sobre duas versões do
mesmo servidor: `vuln/` (estado original, com V1–V20) e `fixed/` (versão
corrigida, ver Tarefa 2 / Q4–Q7).

Relatório completo com evidências: [`TAREFA1-SAST-DAST.md`](./TAREFA1-SAST-DAST.md)

## Como reproduzir

```bash
# 1. instalar dependências dos dois servidores
cd vuln && npm install && cd ../fixed && npm install && cd ..

# 2. SAST (scanner próprio baseado em regras, ver rules.yml)
node sast_scan.js vuln  sast-vuln-results.json
node sast_scan.js fixed sast-fixed-results.json

# 3. DAST — servidor vulnerável (porta 3001)
node vuln/server.js &
python dast_probe.py http://localhost:3001 vuln-dast.json
kill %1

# 4. DAST — servidor corrigido (porta 3002)
node fixed/server.js &
python dast_probe_fixed.py http://localhost:3002 fixed-dast.json
kill %1
```

## Resultado resumido

| | SAST (achados) | DAST (vetores exploráveis) |
|---|---|---|
| `vuln/` | 11 | 9/9 |
| `fixed/` | 0 | 0/10 |

## Nota metodológica (transparência)

O binário `semgrep` e o registry oficial de regras não estavam disponíveis
no ambiente de execução usado para montar este repositório. Em vez de
pular a etapa de SAST, foi escrito `sast_scan.js`: um scanner baseado em
regex (mesmo princípio do Semgrep — regra → padrão → arquivo/linha → achado)
com regras documentadas em `rules.yml`, mapeadas às vulnerabilidades V1–V20.
O **DAST foi executado de fato**: os dois servidores foram subidos localmente
(banco em memória mockado em `db.js`) e atacados via requisições HTTP reais
com `dast_probe.py` / `dast_probe_fixed.py` — não é uma simulação, os
resultados em `vuln-dast.json` / `fixed-dast.json` vêm de execuções reais.
