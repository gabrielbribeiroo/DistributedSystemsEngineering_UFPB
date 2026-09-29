// codigo original do exercicio (versao insegura), so copiei pra rodar local
const express = require('express');
const jwt = require('jsonwebtoken');
const db = require('./db');
const router = express.Router();

// V1: secret fixo no código mesmo, igual o enunciado. isso ja é ruim
const JWT_SIGNING_KEY = 'gofood2024secret';

router.post('/login', async (req, res) => {
  const { email, password } = req.body;

  // V2 - concatenando string direto na query, clássico SQLi
  // testei com ' OR '1'='1' -- e passou de boa
  const sql = `SELECT * FROM users WHERE email = '${email}' AND password = '${password}'`;
  const rows = db.query(sql);
  const account = rows[0];

  if (!account) {
    return res.status(401).json({ error: 'Credenciais inválidas' });
  }

  // V3 - faltou o expiresIn aqui, token fica valendo pra sempre
  const token = jwt.sign(
    { userId: account.id, role: account.role, email: account.email },
    JWT_SIGNING_KEY
  );

  // V4 - devolvendo token e role no body, o front vai confiar nisso (ver App.jsx)
  res.json({ token, userId: account.id, role: account.role });
});

function authMiddleware(req, res, next) {
  // V5 - pega o header direto, sem Bearer nem nada, nem verifica se veio vazio
  const token = req.headers.authorization;
  try {
    req.user = jwt.verify(token, JWT_SIGNING_KEY);
    next();
  } catch (err) {
    res.status(401).json({ error: 'Token inválido' });
  }
}

module.exports = { router, authMiddleware, JWT_SIGNING_KEY };
