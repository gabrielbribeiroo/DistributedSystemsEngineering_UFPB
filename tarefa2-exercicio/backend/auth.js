// versao corrigida, comparar com ../vuln/auth.js pra ver a diferença
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const db = require('./db');
const router = express.Router();

// secret vem de env var agora (corrige V1). deixei um fallback só pra
// não quebrar quando roda local sem configurar nada
const ACCESS_SECRET = process.env.JWT_ACCESS_SECRET || 'dev-only-change-me-access';
const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'dev-only-change-me-refresh';

const isProd = process.env.NODE_ENV === 'production';
const COOKIE_OPTS = { httpOnly: true, secure: isProd, sameSite: 'strict', path: '/' };

router.post('/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ error: 'Credenciais inválidas' });
  }

  // query parametrizada, corrige o V2. o email nunca vira parte da string sql
  const { rows } = db.query(
    'SELECT id, email, password_hash, role FROM users WHERE email = $1',
    [email]
  );
  const user = rows[0];

  // roda o compare mesmo se o user não existir, pra não dar pra descobrir
  // por timing se o email tá cadastrado ou não
  const validHash = user ? user.password_hash : '$2a$10$invalidinvalidinvalidinvalidinvalidinva';
  const passwordOk = await bcrypt.compare(password, validHash);
  if (!user || !passwordOk) {
    return res.status(401).json({ error: 'Credenciais inválidas' });
  }

  // agora com expiresIn, 15min de access token (corrige o V3)
  const accessToken = jwt.sign({ userId: user.id, role: user.role }, ACCESS_SECRET, { expiresIn: '15m' });
  const refreshToken = jwt.sign({ userId: user.id, jti: crypto.randomUUID() }, REFRESH_SECRET, { expiresIn: '7d' });

  const tokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');
  db.query('INSERT INTO refresh_tokens (user_id, token_hash) VALUES ($1, $2)', [user.id, tokenHash]);

  res.cookie('accessToken', accessToken, { ...COOKIE_OPTS, maxAge: 15 * 60 * 1000 });
  res.cookie('refreshToken', refreshToken, { ...COOKIE_OPTS, maxAge: 7 * 24 * 3600 * 1000 });

  // não manda token nem role no body, tudo fica só no cookie (V4)
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
  // pega do cookie agora, não do header (corrige V5)
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
