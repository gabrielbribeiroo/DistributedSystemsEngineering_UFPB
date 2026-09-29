// auth.js — estado ORIGINAL do GoFood (deliberadamente inseguro), reproduzido
// a partir do enunciado do exercício para servir de alvo de SAST/DAST.
const express = require('express');
const jwt = require('jsonwebtoken');
const db = require('./db');
const router = express.Router();

// (V1) A chave de assinatura do JWT vive aqui, em texto puro, versionada junto
// com o resto do código. Qualquer leitura do repositório expõe a chave.
const JWT_SIGNING_KEY = 'gofood2024secret';

router.post('/login', async (req, res) => {
  const { email, password } = req.body;

  // (V2) email/password entram direto na string SQL — nenhum escaping,
  // nenhum bind de parâmetro. Um payload como `' OR '1'='1' --` altera
  // completamente a semântica da cláusula WHERE.
  const sql = `SELECT * FROM users WHERE email = '${email}' AND password = '${password}'`;
  const rows = db.query(sql);
  const account = rows[0];

  if (!account) {
    return res.status(401).json({ error: 'Credenciais inválidas' });
  }

  // (V3) jwt.sign sem `expiresIn`: o token emitido aqui nunca expira por
  // conta própria — só se torna inválido se a SECRET mudar.
  const token = jwt.sign(
    { userId: account.id, role: account.role, email: account.email },
    JWT_SIGNING_KEY
  );

  // (V4) O papel do usuário (role) e o próprio token voltam no corpo da
  // resposta. Isso empurra o frontend a tratar `role` como um dado confiável
  // vindo do cliente (é o que acontece em V13/V14 no App.jsx).
  res.json({ token, userId: account.id, role: account.role });
});

// (V5) Middleware "ingênuo": lê o cabeçalho Authorization como se fosse
// sempre um JWT puro, sem exigir o prefixo `Bearer `, sem checar se o
// cabeçalho sequer veio preenchido antes de tentar verificar.
function authMiddleware(req, res, next) {
  const token = req.headers.authorization;
  try {
    req.user = jwt.verify(token, JWT_SIGNING_KEY);
    next();
  } catch (err) {
    res.status(401).json({ error: 'Token inválido' });
  }
}

module.exports = { router, authMiddleware, JWT_SIGNING_KEY };
