const express = require('express');
const db = require('./db');
const { authMiddleware } = require('./auth');
const router = express.Router();

// Buscar pedido por ID
router.get('/orders/:id', authMiddleware, async (req, res) => {
  // V6 — query concatenada (SQL Injection / UNION SELECT)
  const order = db.query(`SELECT * FROM orders WHERE id = ${req.params.id}`);
  // V7 — sem verificar se o pedido pertence ao usuário autenticado (IDOR)
  res.json(order);
});

// Criar pedido
router.post('/orders', authMiddleware, async (req, res) => {
  const { items, address } = req.body;
  // V8 — sem validação de input
  const total = items.reduce((sum, item) => sum + item.price * item.qty, 0);
  // V9 — preço vem do cliente, não do banco
  db.query(`INSERT INTO orders (user_id, items, total, address) VALUES (${req.user.userId}, '${JSON.stringify(items)}', ${total}, '${address}')`);
  res.json({ success: true });
});

// Painel admin — listar todos os pedidos
router.get('/admin/orders', authMiddleware, async (req, res) => {
  // V10 — sem verificar se o usuário é admin
  const orders = db.query('SELECT * FROM orders WHERE 1=1 /*admin*/');
  res.json(orders);
});

module.exports = router;
