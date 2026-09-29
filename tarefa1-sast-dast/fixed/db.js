// Banco de dados em memória (mock) com API PARAMETRIZADA (text, params) — simula
// o driver `pg` real (db.query('...$1...', [valor])), eliminando concatenação de string.
const bcrypt = require('bcryptjs');

const users = [
  { id: 1, email: 'admin@gofood.com', password_hash: bcrypt.hashSync('admin123', 10), role: 'admin' },
  { id: 2, email: 'joao@gofood.com', password_hash: bcrypt.hashSync('senha123', 10), role: 'customer' },
];

const products = [
  { id: 1, name: 'Feijoada', price: 19.9 },
  { id: 2, name: 'Suco de Acerola', price: 8.5 },
];

let orders = [
  { id: 1, user_id: 2, items: '[{"productId":1,"qty":2}]', total: 39.8, address: 'Rua A, 123' },
];

let refreshTokens = []; // { userId, tokenHash, revoked, expiresAt }

// query(text, params) — nunca faz concatenação; params são usados apenas como
// dados, nunca interpolados na "query". Isso é o que torna SQL Injection impossível
// aqui: um valor como "' OR '1'='1" é tratado só como valor de comparação, não como SQL.
function query(text, params = []) {
  if (text.includes('SELECT id, email, password_hash, role FROM users WHERE email')) {
    const [email] = params;
    return { rows: users.filter(u => u.email === email) };
  }
  if (text.includes('SELECT id, role FROM users WHERE id')) {
    const [id] = params;
    return { rows: users.filter(u => u.id === id).map(u => ({ id: u.id, role: u.role })) };
  }
  if (text.includes('INSERT INTO refresh_tokens')) {
    const [userId, tokenHash] = params;
    refreshTokens.push({ userId, tokenHash, revoked: false, expiresAt: Date.now() + 7 * 24 * 3600 * 1000 });
    return { rows: [] };
  }
  if (text.includes('FROM refresh_tokens WHERE user_id')) {
    const [userId, tokenHash] = params;
    const valid = refreshTokens.filter(t => t.userId === userId && t.tokenHash === tokenHash && !t.revoked && t.expiresAt > Date.now());
    return { rows: valid.map((_, i) => ({ id: i })) };
  }
  if (text.includes('SELECT * FROM orders WHERE id')) {
    const [id] = params;
    return { rows: orders.filter(o => o.id === id) };
  }
  if (text.includes('SELECT id, price FROM products WHERE id = ANY')) {
    const [ids] = params;
    return { rows: products.filter(p => ids.includes(p.id)) };
  }
  if (text.startsWith('INSERT INTO orders')) {
    const [userId, itemsJson, total, address] = params;
    const id = orders.length + 1;
    orders.push({ id, user_id: userId, items: itemsJson, total, address });
    return { rows: [{ id }] };
  }
  if (text.includes('SELECT * FROM orders ORDER BY')) {
    return { rows: orders };
  }
  return { rows: [] };
}

module.exports = { query, users, products, orders };
