// orders.js — rotas de pedidos, versão original do exercício.
const express = require('express');
const db = require('./db');
const { authMiddleware } = require('./auth');
const router = express.Router();

router.get('/orders/:id', authMiddleware, async (req, res) => {
  // (V6) req.params.id entra direto na query. Basta enviar
  // `1 UNION SELECT id, email, password, role, NULL, NULL FROM users --`
  // no lugar de um ID numérico para vazar a tabela inteira de usuários.
  const found = db.query(`SELECT * FROM orders WHERE id = ${req.params.id}`);
  // (V7) Note que em momento algum comparamos found.user_id com
  // req.user.userId — qualquer usuário autenticado lê o pedido de qualquer outro.
  res.json(found);
});

router.post('/orders', authMiddleware, async (req, res) => {
  const { items, address } = req.body;

  // (V8) `items` pode vir undefined, vazio, com campos faltando — nada aqui
  // valida o formato antes de usar. Isso, sozinho, já derruba o processo
  // (ver Tarefa 1 / DAST: TypeError não tratada em handler async).
  const total = items.reduce((sum, item) => sum + item.price * item.qty, 0);

  // (V9) O total cobrado é function(items[].price enviado pelo cliente) —
  // o servidor nunca consulta um catálogo de preços real.
  db.query(
    `INSERT INTO orders (user_id, items, total, address) VALUES (${req.user.userId}, '${JSON.stringify(items)}', ${total}, '${address}')`
  );
  res.json({ success: true });
});

router.get('/admin/orders', authMiddleware, async (req, res) => {
  // (V10) authMiddleware garante só que existe UM token válido — não que o
  // dono desse token seja admin. Não há checagem de req.user.role aqui.
  const allOrders = db.query('SELECT * FROM orders WHERE 1=1 /* rota admin */');
  res.json(allOrders);
});

module.exports = router;
