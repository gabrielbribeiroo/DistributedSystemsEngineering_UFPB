# Tarefas da disciplina de Engenharia de Sistemas Distribuídos

**Aluno:** Gabriel.

## Estrutura

```
.
├── tarefa1-sast-dast/     # Tarefa 1: aplicar SAST e DAST no servidor (antes/depois)
│   ├── TAREFA1-SAST-DAST.md    # relatório: 11 achados SAST / 9-9 → 0-10 no DAST
│   ├── vuln/  fixed/            # dois servidores executáveis (Express + db mock)
│   ├── dast_probe*.py           # probes DAST (atacam a app rodando de verdade)
│   ├── *-dast.json              # resultados DAST
│   └── rules.yml, sast_scan.js, sast-*.json   # SAST (scanner próprio, estilo Semgrep)
│
└── tarefa2-exercicio/     # Tarefa 2: exercício GoFood Q1–Q10
    ├── README.md               # descrição do repositório do exercício
    ├── docs/
    │   ├── 01-solucao-exercicio.md          # respostas Q1–Q10
    │   └── 02-relatorio-sast-comparativo.md # relatório SAST (com limitações)
    ├── backend/  frontend/     # código corrigido (Q4–Q7)
    ├── sonar-project.properties             # pipeline DevSecOps (Q10)
    └── analise-seguranca/      # regras + resultados + código vulnerável
```

## As duas tarefas

**Tarefa 1 — SAST e DAST no servidor, antes e depois.**
Análise estática (scanner próprio baseado em regras, estilo Semgrep) **e
dinâmica de verdade** (os dois servidores — vulnerável e corrigido — foram
subidos localmente com banco em memória mockado e atacados via requisições
HTTP reais). Resultado: 11 achados SAST e 9/9 vetores DAST exploráveis no
código vulnerável, reduzidos a 0 no código corrigido. Um achado extra —
não previsto no enunciado — foi descoberto durante o DAST: falta de
validação de input derruba o processo inteiro do servidor (DoS). Detalhes
e reprodução em `tarefa1-sast-dast/TAREFA1-SAST-DAST.md`.

**Tarefa 2 — Exercício GoFood (Q1–Q10).**
Mapeamento OWASP das 20 vulnerabilidades, análise dos ataques (XSS, SQLi),
código corrigido (auth, orders, server, SPA), diagrama de sequência,
análise arquitetural defense-in-depth e pipeline DevSecOps. Respostas em
`tarefa2-exercicio/docs/01-solucao-exercicio.md`.

## Metodologia e limitações (transparência)

O SAST rodou com um scanner próprio baseado em regras (`sast_scan.js` +
`rules.yml`), no mesmo princípio do Semgrep, porque o binário `semgrep` e
o registry oficial de regras não estavam acessíveis no ambiente usado para
montar este repositório. O **SonarCloud está configurado
(`sonar-project.properties`), mas não foi executado** — roda no CI após o
push. O **DAST foi executado de fato**, subindo os servidores localmente
com banco em memória mockado e atacando-os com `dast_probe.py` /
`dast_probe_fixed.py`. Detalhes na seção de metodologia de
`tarefa1-sast-dast/TAREFA1-SAST-DAST.md` e em
`tarefa2-exercicio/docs/02-relatorio-sast-comparativo.md`.

## Ferramentas de pentest de referência

OWASP ZAP · Burp Suite · SpiderFoot · SqlMap — ver uso de cada uma na
seção Q10 de `tarefa2-exercicio/docs/01-solucao-exercicio.md`.

## Nota sobre uso de IA

Parte deste material foi produzida com apoio de assistente de IA (Claude)
e revisada pelo autor.
