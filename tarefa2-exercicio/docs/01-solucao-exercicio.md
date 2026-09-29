# Exercício Prático: Segurança em SPA — GoFood — Solução

**Disciplina:** Engenharia de Sistemas Distribuídos — UFPB · Prof. Raoni Kulesza
**Aluno:** Gabriel

O código corrigido completo (Q4–Q7) está em [`../backend`](../backend) e
[`../frontend`](../frontend), executável de verdade — não é apenas um
recorte de trecho. O código vulnerável original está em
[`../analise-seguranca/codigo-vulneravel`](../analise-seguranca/codigo-vulneravel).
Os resultados de SAST/DAST comparando as duas versões estão na Tarefa 1
(`../../tarefa1-sast-dast/`) e resumidos em
[`02-relatorio-sast-comparativo.md`](./02-relatorio-sast-comparativo.md).

---

## Parte 1 — Análise

### Q1 — Mapeamento OWASP Top 10 (V1–V20)

| Cód. | Descrição da vulnerabilidade | OWASP Top 10 (2021) | Vetor de ataque |
|---|---|---|---|
| V1 | Secret JWT hardcoded no código-fonte | A02 - Cryptographic Failures | Qualquer pessoa com acesso ao repositório (ou ao código decompilado) descobre a chave e forja tokens JWT válidos com qualquer role, inclusive admin. |
| V2 | Query SQL montada por concatenação de string no login | A03 - Injection | Atacante injeta `' OR '1'='1' --` no e-mail/senha e contorna a autenticação sem credenciais válidas. |
| V3 | JWT gerado sem expiração (`exp`) | A07 - Identification and Authentication Failures | Um token roubado (ex.: via XSS) permanece válido indefinidamente. |
| V4 | Resposta de login expõe `role`/`userId` no corpo | A04 - Insecure Design | Incentiva o frontend a confiar em dados de autorização vindos do cliente (leva a V13/V14). |
| V5 | Middleware lê token direto do header `Authorization` sem validar esquema | A05 - Security Misconfiguration | Ausência de padronização (Bearer) e de tratamento de token ausente/malformado reduz a robustez do middleware. |
| V6 | Query SQL de pedidos concatenada com `req.params.id` | A03 - Injection | Atacante usa `UNION SELECT` no `id` para ler tabelas arbitrárias do banco. |
| V7 | `/orders/:id` não verifica se o pedido pertence ao usuário autenticado | A01 - Broken Access Control (IDOR) | Qualquer usuário autenticado lê pedidos de terceiros trocando o ID na URL. |
| V8 | Criação de pedido sem validação de input | A04 - Insecure Design | Payloads malformados chegam direto à lógica de negócio/banco — inclusive causando **crash do processo** (ver Tarefa 1, DAST). |
| V9 | Preço do item calculado a partir de dados enviados pelo cliente | A04 - Insecure Design (falha de lógica de negócio) | Atacante altera `item.price` no corpo da requisição e compra por qualquer valor, inclusive R$0. |
| V10 | `/admin/orders` sem checagem de role | A01 - Broken Access Control | Qualquer usuário autenticado (não-admin) acessa dados administrativos. |
| V11 | Chamada da SPA usa `http://` em vez de `https://` | A02 - Cryptographic Failures | Tráfego em texto claro permite interceptação (MITM) de credenciais e tokens. |
| V12 | Token JWT salvo em `localStorage` | A02 - Cryptographic Failures (armazenamento inseguro) | Qualquer script no contexto da página (ex.: via XSS) lê `localStorage.getItem('token')` livremente. |
| V13 | Role do usuário salva em `localStorage` | A01 - Broken Access Control | O dado de autorização fica sob controle do cliente — pode ser lido, forjado ou exfiltrado via XSS. |
| V14 | Painel admin renderizado com base no `role` do `localStorage` | A01 - Broken Access Control | Basta editar `localStorage` no DevTools para ver a UI administrativa no cliente. |
| V15 | Comentários renderizados com `dangerouslySetInnerHTML` sem sanitização | A03 - Injection (XSS) | Atacante injeta HTML/JS malicioso em um comentário; executa no navegador de quem visualiza o produto. |
| V16 | `cors()` sem restrição de origem | A05 - Security Misconfiguration | Qualquer site faz requisições autenticadas à API a partir do navegador da vítima. |
| V17 | `express.json()` sem limite de tamanho | A05 - Security Misconfiguration | Payloads JSON enormes esgotam memória/CPU do servidor (DoS). |
| V18 | Ausência de rate limiting | A07 - Identification and Authentication Failures | Permite brute force / credential stuffing no `/login` e abuso em massa de qualquer endpoint. |
| V19 | Ausência de `helmet` (headers de segurança) | A05 - Security Misconfiguration | Faltam CSP, X-Frame-Options, HSTS, facilitando XSS, clickjacking e downgrade de protocolo. |
| V20 | Error handler retorna stack trace ao cliente | A05 - Security Misconfiguration (efeito colateral em A09) | Mensagens de erro revelam caminhos internos, versões de libs e lógica do servidor. |

### Q2 — Ataque Prático: Roubo de Token via XSS

**a) O que acontece quando outro usuário visualiza a página do produto**

1. O comentário malicioso foi salvo no banco sem sanitização (não há validação/escape no backend nem no frontend).
2. Quando a vítima abre a página do produto, `ProductComments` renderiza `c.text` via `dangerouslySetInnerHTML` (V15), injetando o HTML bruto no DOM.
3. O navegador tenta carregar a imagem com `src="x"`; como essa URL não existe, o evento `onerror` dispara.
4. O handler `onerror` executa JavaScript arbitrário no contexto de origem da SPA — com acesso total ao `localStorage` daquela origem.
5. O script lê `localStorage.getItem('token')` (V12) e envia o valor via `fetch` para `https://evil.com/steal`, exfiltrando o token sem nenhuma ação da vítima além de abrir a página.

**b) Por que o ataque funciona mesmo sem o usuário roubado ser admin**

A rota `GET /admin/orders` (V10) não verifica em nenhum momento o `role` do usuário — apenas confirma que o token é válido (assinatura correta) via `authMiddleware`. Como o token roubado pertence a um usuário autenticado qualquer, ele passa por essa checagem trivialmente. Além disso, como o `role` só existia no `localStorage` do cliente (V13) e nunca foi validado como fonte de autorização no servidor, não há nenhuma barreira real impedindo que um usuário comum acesse dados administrativos — a "proteção" do painel admin era puramente cosmética, decidida no frontend (V14).

**c) Diferença de impacto: `localStorage` vs. cookie `HttpOnly`**

Um cookie `HttpOnly` não pode ser lido por JavaScript (`document.cookie` não o expõe), então o mesmo payload de XSS simplesmente falharia em capturar o valor. O impacto mudaria de "roubo de credencial reutilizável em qualquer lugar" para, na pior hipótese, "abuso da sessão em tempo real dentro da própria origem" (o script injetado ainda poderia disparar `fetch('/api/admin/orders', {credentials:'include'})` enquanto a vítima está com a aba aberta — um ataque tipo CSRF-via-XSS), mitigável com `SameSite=Strict/Lax` e tokens CSRF. `HttpOnly` não elimina o risco de XSS, mas elimina a exfiltração direta do token para um domínio de terceiros.

### Q3 — Ataque Prático: SQL Injection

**a) Query resultante com `' OR '1'='1' --`**

```sql
SELECT * FROM users WHERE email = '' OR '1'='1' --'
AND password = 'qualquercoisa'
```

O `--` comenta o restante da query (inclusive a checagem de senha). A condição `WHERE` se reduz a `(email = '') OR ('1'='1')`, sempre verdadeira, e o SGBD retorna a primeira linha de `users` que satisfaz a cláusula — sem que nenhuma credencial real tenha sido validada.

**b) `UNION SELECT` na rota de pedidos**

```sql
SELECT * FROM orders WHERE id = 1
UNION SELECT id, email, password, role, NULL, NULL FROM users --
```

Como `orders` e o `SELECT` injetado retornam o mesmo número de colunas, o resultado combinado inclui `id`, `email`, `password` e `role` de todos os usuários, disfarçado de linha de pedido. Isso é possível mesmo autenticado porque o `authMiddleware` só valida a assinatura do JWT (autenticação) — nunca verifica autorização/propriedade do recurso (V7) nem sanitiza o parâmetro usado na query (V6). Autenticação e prevenção de injection são camadas independentes.

**c) Relação entre V1 (secret hardcoded) e o impacto do SQL Injection**

Mesmo que o atacante obtenha as senhas via SQLi, ele nem precisa delas: como o `SECRET` do JWT está hardcoded (V1), basta assinar seu próprio token — `jwt.sign({ userId: 1, role: 'admin' }, 'gofood2024secret')` — para se autenticar como administrador instantaneamente, sem tocar no banco. V1 torna a camada de autenticação irrelevante, o que amplia drasticamente o impacto de qualquer vazamento de informação.

---

## Parte 2 — Correção (Implementação Segura)

O código completo, executável, está nos diretórios [`backend/`](../backend) (auth.js, orders.js, server.js, db.js) e [`frontend/src/App.jsx`](../frontend/src/App.jsx). Resumo do que cada um corrige:

### Q4 — `backend/auth.js`
- Secrets via `process.env.JWT_ACCESS_SECRET` / `JWT_REFRESH_SECRET` (corrige V1)
- Query parametrizada `SELECT ... WHERE email = $1` (corrige V2)
- Senha comparada com `bcrypt.compare` contra `password_hash` (corrige V2)
- Access token com `expiresIn: '15m'` + refresh token de 7 dias persistido (hash) para permitir revogação (corrige V3)
- Nenhum token/role no corpo da resposta — tudo via `res.cookie(..., { httpOnly: true, secure, sameSite: 'strict' })` (corrige V4, V12)
- `authMiddleware` lê `req.cookies.accessToken`, não o header `Authorization` (corrige V5)

### Q5 — `backend/orders.js`
- `GET /orders/:id`: query parametrizada (corrige V6) + `order.user_id !== req.user.userId` com 403 caso não seja dono nem admin (corrige V7)
- `POST /orders`: schema Zod valida `items`/`address` (corrige V8); preço vem de `SELECT price FROM products WHERE id = ANY($1)`, nunca do body (corrige V9)
- `requireRole('admin')` como middleware explícito na rota `/admin/orders` (corrige V10)

### Q6 — `frontend/src/App.jsx`
- Todas as chamadas usam `https://` e `credentials: 'include'` (corrige V11)
- Nenhum `localStorage.setItem` para token ou role — estado de admin vem de `GET /api/me` a cada carregamento (corrige V12, V13, V14)
- `ProductComments` sanitiza com `DOMPurify.sanitize` antes de `dangerouslySetInnerHTML` (corrige V15)

### Q7 — `backend/server.js`
- `helmet()` com `contentSecurityPolicy` restritiva (corrige V19)
- `cors({ origin: ALLOWED_ORIGIN, credentials: true })` — origem única, não `cors()` aberto (corrige V16)
- `express.json({ limit: '16kb' })` (corrige V17)
- `express-rate-limit`: limitador global (300/15min) + específico no `/api/login` (5/15min) (corrige V18)
- Error handler condicional a `NODE_ENV === 'production'`, nunca expõe `err.stack` (corrige V20)

**Evidência de que a correção funciona de fato:** ver [`../../tarefa1-sast-dast/TAREFA1-SAST-DAST.md`](../../tarefa1-sast-dast/TAREFA1-SAST-DAST.md) — os mesmos ataques (SQLi, roubo de token, IDOR, CORS, brute force, payload malformado) foram executados via HTTP real contra o servidor rodando, antes (9/9 vetores exploráveis) e depois (0/10) da correção.

---

## Parte 3 — Análise Arquitetural (Defense in Depth)

### Q8 — Diagrama de Sequência: Fluxo Completo Seguro

**1. Login**
```
SPA  -> API  : POST /api/login (HTTPS)                         [mitiga V11]
API  -> DB   : SELECT id, password_hash, role WHERE email=$1   [mitiga V2]
API  -> API  : bcrypt.compare(password, password_hash)         [mitiga V2]
API  -> API  : gera accessToken (15min) + refreshToken (7d)    [mitiga V3]
API  -> DB   : persiste hash do refreshToken (permite revogação)
API  -> SPA  : Set-Cookie accessToken/refreshToken HttpOnly     [mitiga V12, V13]
               corpo da resposta sem token/role                 [mitiga V4]
```

**2. Requisição autenticada**
```
SPA  -> API  : GET /api/orders/42 (cookie enviado automaticamente)
API  -> API  : jwt.verify(accessToken)                          [mitiga V5]
API  -> DB   : SELECT * FROM orders WHERE id = $1 (parametrizada) [mitiga V6]
API  -> API  : order.user_id === req.user.userId (ou role=admin) [mitiga V7, V10]
API  -> SPA  : 200 OK { order } | 403 Forbidden
```

**3. Refresh**
```
SPA  -> API  : GET /api/orders/42 com accessToken expirado -> 401
SPA  -> API  : POST /api/refresh (cookie refreshToken automático)
API  -> DB   : valida refreshToken (hash, revogado?, expirado?)
API  -> SPA  : Set-Cookie novo accessToken HttpOnly              [mitiga V3]
SPA  -> API  : repete GET /api/orders/42 original
```

### Q9 — Escalando a Segurança: Microserviços

**a) Proteção de dados em repouso**

- **TDE**: criptografa o arquivo físico do banco/backup em disco. Protege contra roubo de mídia física, mas os dados chegam descriptografados a qualquer query autorizada da aplicação — não ajuda contra SQL Injection.
- **Column Encryption**: criptografa colunas específicas com chave separada da aplicação/banco (KMS/HSM). Mesmo com SQLi, o atacante obtém só ciphertext, mas exige gestão de chaves e prejudica indexação.
- **Tokenização (Stripe)**: o número real do cartão nunca toca os servidores da GoFood — o frontend envia direto ao processador, que devolve um token opaco.

**Escolha para o cenário:** tokenização via um processador como Stripe. A GoFood processa pagamentos internacionais (compliance PCI-DSS em múltiplos países) e o exercício mostrou uma aplicação com múltiplas falhas de injection e configuração — dado esse histórico, a estratégia mais robusta é nunca deixar dados de cartão residirem nos servidores da GoFood, reduzindo drasticamente o escopo de auditoria PCI-DSS. TDE pode complementar para os dados que restam (PII), mas não substitui a tokenização para dados de cartão.

**b) Segurança na rede interna**

- **TLS Termination no API Gateway**: certificado público termina no Gateway, único ponto exposto à internet (mitiga V11).
- **mTLS via service mesh** (Istio/Linkerd) entre Gateway ↔ Auth/Orders/Products/Payments: certificados de identidade por serviço, rotacionados automaticamente, impedindo que um serviço comprometido se passe por outro.
- **Segmentação de rede**: Payments em subnet/security group isolada, aceitando tráfego só do Gateway via mTLS, sem rota direta à internet e egress restrito ao processador — reduz o blast radius de qualquer outro serviço comprometido.

**c) Observabilidade de segurança**

| Evento a logar/monitorar | O que detecta | V relacionada |
|---|---|---|
| Picos de tentativas de login falhas por IP/conta | Brute force / credential stuffing | V18, V7 |
| Chamadas a `/admin/*` e resultado (permitido/negado) por usuário | Tentativa de escalonamento de privilégio | V10, V13, V14 |
| Erros de sintaxe SQL ou padrões suspeitos nos parâmetros (aspas, `UNION`, `--`) | Tentativas de SQL Injection | V2, V6 |
| Falhas de verificação de JWT, tokens expirados reutilizados | Tokens forjados/roubados em uso | V1, V3, V12 |
| Requisições rejeitadas por CORS com Origin fora da allowlist | Acesso cross-origin não autorizado | V16 |
| Relatórios de violação de CSP (`report-uri` do helmet) | Execução de script não autorizado (indício de XSS ativo) | V15, V19 |

### Q10 — DevSecOps Pipeline

| Etapa | Ferramenta | O que detecta | Qual V1–V20 pegaria |
|---|---|---|---|
| Pre-commit | gitleaks / git-secrets (hook) | Segredos e chaves hardcoded commitados | V1 |
| Build | ESLint + `eslint-plugin-security`/`eslint-plugin-react` (regra contra `dangerouslySetInnerHTML`) | Padrões perigosos no código-fonte | V15 |
| Build | `npm audit` / Snyk / Dependabot (SCA) | Dependências com CVEs conhecidos | A06 (geral) |
| Test | SAST — Semgrep/SonarQube (ou o `sast_scan.js` deste repo) | Concatenação SQL, ausência de checagem de role/ownership | V2, V6, V7, V10 |
| Test | DAST — **OWASP ZAP** contra staging | XSS, CORS aberto, ausência de rate limiting, headers ausentes | V15, V16, V18, V19 |
| Deploy | Trivy (imagem/container) + checagem de variáveis de ambiente obrigatórias | Imagens base vulneráveis, secrets ausentes em manifests | V1 |
| Deploy | Smoke test de headers (helmet) e protocolo (força HTTPS) | Configuração insegura antes de liberar tráfego | V11, V19, V20 |
| Runtime | WAF + SIEM/central de logs com alertas | Padrões de ataque em tempo real | V2, V6, V10, V18 |

> O OWASP ZAP é a ferramenta DAST sugerida para a etapa de Test — varre a aplicação em execução simulando ataques reais, complementando o SAST (que só analisa código estático). Outras ferramentas de pentest úteis no ciclo de vida do GoFood: **Burp Suite** (interceptar/alterar requisições manualmente, ex. testar V9/V13), **SpiderFoot** (reconhecimento/mapeamento de superfície exposta, ex. detectar V1 vazado publicamente) e **SqlMap** (automatizar a exploração de V2/V6 identificada na Q3).

---

## Anexo — Tarefa 2 (do miniteste): SAST e DAST antes e depois

A comparação **real** (não hipotética) entre o estado vulnerável e o
corrigido está documentada e reproduzível em
[`../../tarefa1-sast-dast/TAREFA1-SAST-DAST.md`](../../tarefa1-sast-dast/TAREFA1-SAST-DAST.md):

- **SAST**: 11 achados no código vulnerável → 0 no corrigido.
- **DAST** (servidores rodando de verdade, atacados via HTTP): 9/9 vetores exploráveis → 0/10.
- Achado extra descoberto durante o DAST (não estava no enunciado original): falta de validação de input (V8) permite **derrubar o processo inteiro do servidor** com uma única requisição malformada — um DoS trivial, documentado como `V8-DoS`.
