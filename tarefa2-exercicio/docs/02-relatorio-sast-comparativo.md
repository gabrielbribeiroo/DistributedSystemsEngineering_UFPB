# Relatório SAST comparativo — código vulnerável vs. corrigido

Este relatório reaproveita o scanner e as regras da Tarefa 1
(`../../tarefa1-sast-dast/sast_scan.js`, `rules.yml`) sobre o mesmo par de
código deste exercício: `analise-seguranca/codigo-vulneravel/` (estado
original do enunciado) e `backend/` (código corrigido das respostas Q4–Q7).

## Resultado

| | Achados SAST |
|---|---|
| `analise-seguranca/codigo-vulneravel/` | 11 (ver `vulneravel-results.json`) |
| `backend/` (corrigido) | 0 (ver `corrigido-results.json`) |

O detalhe achado-a-achado (regra, arquivo, linha, OWASP, vulnerabilidade
V1–V20 correspondente) está descrito na seção 2 de
`../../tarefa1-sast-dast/TAREFA1-SAST-DAST.md`, que é o relatório completo
e a fonte de verdade — este arquivo existe apenas para satisfazer a
estrutura de pasta pedida pelo professor (`analise-seguranca/`) dentro do
próprio diretório do exercício, sem duplicar a análise.

## Limitações conhecidas

1. **Semgrep real não executado**: o ambiente de desenvolvimento usado não
   tinha acesso ao binário `semgrep` nem ao registry oficial de regras.
   `sast_scan.js` reimplementa o mesmo princípio (regra → padrão → achado)
   com regex simples, o que é suficiente para os padrões didáticos deste
   exercício (concatenação de SQL, secret hardcoded, etc.), mas não tem a
   cobertura de um mecanismo real de análise de fluxo de dados (taint
   analysis) — não detecta, por exemplo, uma vulnerabilidade que atravesse
   várias funções ou arquivos.
2. **SonarCloud configurado, não executado**: `sonar-project.properties`
   está pronto; a análise real roda no pipeline de CI (ver Q10 da solução)
   após o push ao GitHub, quando houver um token do SonarCloud disponível.
3. **DAST não incluído neste relatório**: a Tarefa 1 já cobre DAST real
   (servidores subindo e sendo atacados via HTTP) — os arquivos
   `vuln-dast.json` / `fixed-dast.json` em `tarefa1-sast-dast/` usam o
   mesmo par vuln/fixed de código deste exercício, então não foram
   duplicados aqui.
