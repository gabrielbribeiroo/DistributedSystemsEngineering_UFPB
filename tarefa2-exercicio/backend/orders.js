// orders.js — versão CORRIGIDA das rotas de pedidos (ver ../vuln/orders.js
// para a forma original, com V6-V10).
const express = require('express');
const { z } = require('zod');
const db = require('./db');
const { authMiddleware } = require('./auth');
const router = express.Router();

// Formato mínimo que um pedido precisa ter para ser aceito — nada com essa
// forma passa sem productId/qty/address válidos.
const orderSchema = z.object({
  items: z.array(z.object({
    productId: z.number().int().positive(),
    qty: z.number().int().min(1).max(50),
  })).min(1).max(100),
  address: z.string().trim().min(5).max(300),
});

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Acesso negado' });
    }
    next();
  };
}

router.get('/orders/:id', authMiddleware, async (req, res) => {
  const orderId = Number(req.params.id);
  if (!Number.isInteger(orderId)) return res.status(400).json({ error: 'ID inválido' });

  // (corrige V6) placeholder $1 — orderId nunca vira parte literal da query.
  const { rows } = db.query('SELECT * FROM orders WHERE id = $1', [orderId]);
  const order = rows[0];
  if (!order) return res.status(404).json({ error: 'Pedido não encontrado' });

  // (corrige V7) só o dono do pedido (ou um admin) pode lê-lo — sem isso,
  // trocar o :id na URL bastaria para ver o pedido de qualquer pessoa.
  if (order.user_id !== req.user.userId && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Acesso negado' });
  }
  res.json(order);
});

router.post('/orders', authMiddleware, async (req, res) => {
  // (corrige V8) qualquer payload fora do formato esperado é rejeitado
  // aqui, antes de chegar perto de um items.reduce ou de uma query.
  const parsed = orderSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: 'Dados inválidos', details: parsed.error.flatten() });
  }
  const { items, address } = parsed.data;

  // (corrige V9) o preço é sempre lido do catálogo — o campo `price` que o
  // cliente eventualmente mande no corpo é simplesmente ignorado.
  const ids = items.map(i => i.productId);
  const { rows: catalog } = db.query('SELECT id, price FROM products WHERE id = ANY($1)', [ids]);
  const priceById = new Map(catalog.map(p => [p.id, p.price]));
  if (priceById.size !== new Set(ids).size) {
    return res.status(400).json({ error: 'Um ou mais produtos não existem' });
  }
  const total = items.reduce((sum, item) => sum + priceById.get(item.productId) * item.qty, 0);

  const { rows } = db.query(
    'INSERT INTO orders (user_id, items, total, address) VALUES ($1, $2, $3, $4)',
    [req.user.userId, JSON.stringify(items), total, address]
  );
  res.status(201).json({ success: true, orderId: rows[0] && rows[0].id });
});

// (corrige V10) requireRole('admin') roda antes do handler — sem o role
// certo no token, a requisição nem chega a tocar no banco.
router.get('/admin/orders', authMiddleware, requireRole('admin'), async (req, res) => {
  const { rows } = db.query('SELECT * FROM orders ORDER BY id DESC');
  res.json(rows);
});

module.exports = router;
