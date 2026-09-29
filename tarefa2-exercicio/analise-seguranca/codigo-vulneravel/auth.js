const express = require('express');
const jwt = require('jsonwebtoken');
const db = require('./db');
const router = express.Router();

const SECRET = "gofood2024secret"; // V1 — secret hardcoded no código-fonte

router.post('/login', async (req, res) => {
  const { email, password } = req.body;

  // V2 — query montada por concatenação de string (SQL Injection)
  const query = `SELECT * FROM users WHERE email = '${email}' AND password = '${password}'`;
  const rows = db.query(query);
  const user = rows[0];

  if (!user) {
    return res.status(401).json({ error: 'Credenciais inválidas' });
  }

  // V3 — token sem expiração
  const token = jwt.sign(
    { userId: user.id, role: user.role, email: user.email },
    SECRET
  );

  // V4 — expõe role/userId no corpo da resposta
  res.json({ token, userId: user.id, role: user.role });
});

function authMiddleware(req, res, next) {
  const token = req.headers.authorization; // V5 — sem validação de esquema (Bearer)
  try {
    const decoded = jwt.verify(token, SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Token inválido' });
  }
}

module.exports = { router, authMiddleware, SECRET };
