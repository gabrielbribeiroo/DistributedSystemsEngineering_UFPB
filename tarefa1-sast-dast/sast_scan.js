#!/usr/bin/env node
// Mini-SAST: aplica as regras de rules.yml (regex) sobre os arquivos .js de um
// diretório e imprime/salva os achados em JSON. Criado porque o binário `semgrep`
// e o registry oficial de regras não estavam acessíveis no ambiente de execução
// desta tarefa — o formato do output (id, path, line, message, owasp, severity)
// foi mantido compatível com o que o Semgrep produziria, para facilitar a
// migração para o Semgrep real no CI (ver tarefa2-exercicio/analise-seguranca).
const fs = require('fs');
const path = require('path');

// As regras vivem em rules.yml (formato legível/versionável); aqui elas são
// reproduzidas como RegExp nativas para evitar depender de um parser YAML
// completo (sem instalar js-yaml). Mantenha as duas em sincronia manualmente.
function loadRules() {
  return [
    { id: 'hardcoded-jwt-secret', pattern: /(SECRET|SIGNING_KEY)\s*=\s*["'].+["']/i, message: "Secret/chave de assinatura JWT hardcoded no código-fonte (V1)", owasp: "A02:2021 - Cryptographic Failures", severity: "HIGH" },
    { id: 'sql-string-concat-template', pattern: /(SELECT|INSERT|UPDATE|DELETE).*\$\{/i, message: "Query SQL montada por concatenação/template string (V2/V6/V9)", owasp: "A03:2021 - Injection", severity: "HIGH" },
    { id: 'jwt-sign-no-expiry', pattern: { test: (line) => /jwt\.sign\(/.test(line) && !/expiresIn/.test(line) }, message: "jwt.sign sem opção expiresIn — token não expira (V3)", owasp: "A07:2021 - Identification and Authentication Failures", severity: "MEDIUM" },
    { id: 'auth-header-token', pattern: /req\.headers\.authorization/, message: "Token lido diretamente do header Authorization, sem cookie HttpOnly (V5/V12)", owasp: "A05:2021 - Security Misconfiguration", severity: "MEDIUM" },
    { id: 'admin-route-no-role-check', pattern: /router\.get\('\/admin\/.*',\s*authMiddleware,\s*async/, message: "Rota /admin sem middleware de checagem de role antes do handler (V10)", owasp: "A01:2021 - Broken Access Control", severity: "HIGH" },
    { id: 'dangerously-set-inner-html', pattern: /dangerouslySetInnerHTML/, message: "Uso de dangerouslySetInnerHTML (revisar sanitização — V15/XSS)", owasp: "A03:2021 - Injection", severity: "HIGH" },
    { id: 'cors-open', pattern: /cors\(\s*\)/, message: "cors() chamado sem opções — aceita qualquer origem (V16)", owasp: "A05:2021 - Security Misconfiguration", severity: "MEDIUM" },
    { id: 'json-body-no-limit', pattern: /express\.json\(\s*\)/, message: "express.json() sem limite de tamanho (V17)", owasp: "A05:2021 - Security Misconfiguration", severity: "LOW" },
    { id: 'error-handler-exposes-stack', pattern: /stack:\s*err\.stack/, message: "Error handler retorna err.stack ao cliente (V20)", owasp: "A05:2021 - Security Misconfiguration", severity: "MEDIUM" },
    { id: 'plaintext-password-in-query', pattern: /password\s*=\s*'\$\{password\}'/, message: "Senha comparada em texto claro dentro da query, sem hashing (V2)", owasp: "A02:2021 - Cryptographic Failures", severity: "HIGH" },
  ];
}

function scanDir(dir, rules) {
  const findings = [];
  const files = fs.readdirSync(dir).filter(f => f.endsWith('.js'));
  for (const file of files) {
    const full = path.join(dir, file);
    const lines = fs.readFileSync(full, 'utf8').split('\n');
    lines.forEach((line, idx) => {
      for (const rule of rules) {
        try {
          if (rule.pattern.test(line)) {
            findings.push({
              rule_id: rule.id,
              path: path.relative(process.cwd(), full),
              line: idx + 1,
              message: rule.message,
              owasp: rule.owasp,
              severity: rule.severity,
              snippet: line.trim().slice(0, 160),
            });
          }
        } catch (e) { /* regex inválida para essa linha, ignora */ }
      }
    });
  }
  return findings;
}

const targetDir = process.argv[2];
const outFile = process.argv[3];
if (!targetDir) {
  console.error('Uso: node sast_scan.js <diretorio> [saida.json]');
  process.exit(1);
}

const rules = loadRules();
const findings = scanDir(targetDir, rules);

const result = {
  tool: 'mini-sast (regex, estilo Semgrep)',
  target: targetDir,
  timestamp: new Date().toISOString(),
  total_findings: findings.length,
  findings,
};

console.log(JSON.stringify(result, null, 2));
if (outFile) {
  fs.writeFileSync(outFile, JSON.stringify(result, null, 2));
  console.error(`\nSalvo em ${outFile} — ${findings.length} achados.`);
}
