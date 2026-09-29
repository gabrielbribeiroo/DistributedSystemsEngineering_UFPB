const express = require('express');
const db = require('./db');
const { authMiddleware } = require('./auth');
const router = express.Router();

router.get('/orders/:id', authMiddleware, async (req, res) => {
  // V6 - id vai direto pra query, dá pra fazer UNION SELECT e puxar a
  // tabela de users inteira (testei, funciona)
  const found = db.query(`SELECT * FROM orders WHERE id = ${req.params.id}`);
  // V7 - faltou comparar found.user_id com req.user.userId, qualquer um
  // logado consegue ver pedido de outra pessoa só mudando o id na url
  res.json(found);
});

router.post('/orders', authMiddleware, async (req, res) => {
  const { items, address } = req.body;

  // V8 - sem validar nada do body. se mandar sem "items" o servidor cai
  // (unhandled rejection, ver DAST na tarefa1)
  const total = items.reduce((sum, item) => sum + item.price * item.qty, 0);

  // V9 - total calculado com o price que o CLIENTE mandou, nao tem
  // catálogo nem nada, só confia no que vier no body mesmo
  db.query(
    `INSERT INTO orders (user_id, items, total, address) VALUES (${req.user.userId}, '${JSON.stringify(items)}', ${total}, '${address}')`
  );
  res.json({ success: true });
});

router.get('/admin/orders', authMiddleware, async (req, res) => {
  // V10 - authMiddleware só olha se o token é válido, não olha o role.
  // então qualquer usuário comum acessa essa rota de admin também
  const allOrders = db.query('SELECT * FROM orders WHERE 1=1 /* rota admin */');
  res.json(allOrders);
});

module.exports = router;
