// auth.js — versão CORRIGIDA. Cada bloco abaixo neutraliza a vulnerabilidade
// equivalente encontrada em ../vuln/auth.js (comentada como referência).
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const db = require('./db');
const router = express.Router();

// (corrige V1) nada de chave em texto no código: ela vem do ambiente, com um
// fallback só para desenvolvimento local (nunca aponta para produção).
const ACCESS_SECRET = process.env.JWT_ACCESS_SECRET || 'dev-only-change-me-access';
const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'dev-only-change-me-refresh';

const isProd = process.env.NODE_ENV === 'production';
const COOKIE_OPTS = { httpOnly: true, secure: isProd, sameSite: 'strict', path: '/' };

router.post('/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ error: 'Credenciais inválidas' });
  }

  // (corrige V2) a query usa placeholder ($1) — o email nunca é concatenado
  // na string SQL, então um valor como `' OR '1'='1` vira só um valor de busca.
  const { rows } = db.query(
    'SELECT id, email, password_hash, role FROM users WHERE email = $1',
    [email]
  );
  const user = rows[0];

  // bcrypt.compare roda mesmo quando o usuário não existe (contra um hash
  // "morto"), para o tempo de resposta não denunciar se o e-mail é válido.
  const validHash = user ? user.password_hash : '$2a$10$invalidinvalidinvalidinvalidinvalidinva';
  const passwordOk = await bcrypt.compare(password, validHash);
  if (!user || !passwordOk) {
    return res.status(401).json({ error: 'Credenciais inválidas' });
  }

  // (corrige V3) expiração curta e explícita — depois de 15 minutos o token
  // deixa de ser aceito mesmo que ninguém o revogue manualmente.
  const accessToken = jwt.sign({ userId: user.id, role: user.role }, ACCESS_SECRET, { expiresIn: '15m' });
  const refreshToken = jwt.sign({ userId: user.id, jti: crypto.randomUUID() }, REFRESH_SECRET, { expiresIn: '7d' });

  const tokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');
  db.query('INSERT INTO refresh_tokens (user_id, token_hash) VALUES ($1, $2)', [user.id, tokenHash]);

  res.cookie('accessToken', accessToken, { ...COOKIE_OPTS, maxAge: 15 * 60 * 1000 });
  res.cookie('refreshToken', refreshToken, { ...COOKIE_OPTS, maxAge: 7 * 24 * 3600 * 1000 });

  // (corrige V4) a resposta não carrega token nem role — o cliente só sabe
  // que autenticou; os dados de sessão ficam inteiramente nos cookies.
  res.json({ success: true });
});

router.post('/refresh', async (req, res) => {
  const token = req.cookies && req.cookies.refreshToken;
  if (!token) return res.status(401).json({ error: 'Não autenticado' });

  try {
    const decoded = jwt.verify(token, REFRESH_SECRET);
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const { rows } = db.query('SELECT id FROM refresh_tokens WHERE user_id = $1 AND token_hash = $2', [decoded.userId, tokenHash]);
    if (rows.length === 0) return res.status(401).json({ error: 'Refresh token inválido' });

    const { rows: userRows } = db.query('SELECT id, role FROM users WHERE id = $1', [decoded.userId]);
    const user = userRows[0];
    if (!user) return res.status(401).json({ error: 'Usuário não encontrado' });

    const accessToken = jwt.sign({ userId: user.id, role: user.role }, ACCESS_SECRET, { expiresIn: '15m' });
    res.cookie('accessToken', accessToken, { ...COOKIE_OPTS, maxAge: 15 * 60 * 1000 });
    res.json({ success: true });
  } catch (err) {
    return res.status(401).json({ error: 'Refresh token inválido ou expirado' });
  }
});

function authMiddleware(req, res, next) {
  // (corrige V5) lê o cookie HttpOnly, não um header que qualquer script
  // JS poderia inspecionar ou que um cliente mal-formado poderia omitir.
  const token = req.cookies && req.cookies.accessToken;
  if (!token) return res.status(401).json({ error: 'Não autenticado' });
  try {
    req.user = jwt.verify(token, ACCESS_SECRET);
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Token inválido ou expirado' });
  }
}

module.exports = { router, authMiddleware, ACCESS_SECRET };
