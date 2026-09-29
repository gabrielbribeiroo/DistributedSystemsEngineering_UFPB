const express = require('express');
const { z } = require('zod');
const db = require('./db');
const { authMiddleware } = require('./auth');
const router = express.Router();

// schema pra validar o pedido antes de fazer qualquer coisa com ele
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

  // corrige o V6, agora com placeholder
  const { rows } = db.query('SELECT * FROM orders WHERE id = $1', [orderId]);
  const order = rows[0];
  if (!order) return res.status(404).json({ error: 'Pedido não encontrado' });

  // e aqui o V7 - checa se é o dono do pedido ou admin antes de devolver
  if (order.user_id !== req.user.userId && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Acesso negado' });
  }
  res.json(order);
});

router.post('/orders', authMiddleware, async (req, res) => {
  // valida o body com zod, se não bater com o schema já corta aqui (V8)
  const parsed = orderSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: 'Dados inválidos', details: parsed.error.flatten() });
  }
  const { items, address } = parsed.data;

  // busca o preço real no catálogo, ignora qualquer price que vier do
  // cliente (era o V9, o preço não pode vir do front nunca)
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

// adicionei o requireRole('admin') no meio da rota, corrige o V10
router.get('/admin/orders', authMiddleware, requireRole('admin'), async (req, res) => {
  const { rows } = db.query('SELECT * FROM orders ORDER BY id DESC');
  res.json(rows);
});

module.exports = router;
