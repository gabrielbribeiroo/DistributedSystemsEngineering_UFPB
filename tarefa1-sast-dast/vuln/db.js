// não tem banco de verdade, é só um mock em memória mesmo pra não precisar
// instalar postgres só pra rodar isso localmente
const users = [
  { id: 1, email: 'admin@gofood.com', password: 'admin123', role: 'admin' },
  { id: 2, email: 'joao@gofood.com', password: 'senha123', role: 'customer' },
];

const orders = [
  { id: 1, user_id: 2, items: '[{"productId":1,"qty":2}]', total: 39.8, address: 'Rua A, 123' },
  { id: 2, user_id: 1, items: '[{"productId":2,"qty":1}]', total: 15.0, address: 'Rua B, 456' },
];

// não é um parser SQL de verdade, só reconhece os formatos de query que o
// auth.js e o orders.js mandam e devolve algo coerente pra cada um
function query(sql) {
  const lower = sql.toLowerCase();

  if (lower.includes('from users')) {
    // clássico bypass tipo OR '1'='1', devolve o primeiro user
    if (/or\s+'?1'?\s*=\s*'?1'?/i.test(sql)) {
      return [users[0]];
    }
    // union select vaza a tabela de usuários inteira
    if (/union\s+select/i.test(sql)) {
      return users.map(u => ({ id: u.id, email: u.email, password: u.password, role: u.role }));
    }
    const emailMatch = sql.match(/email\s*=\s*'([^']*)'/i);
    const passMatch = sql.match(/password\s*=\s*'([^']*)'/i);
    const email = emailMatch ? emailMatch[1] : null;
    const password = passMatch ? passMatch[1] : null;
    return users.filter(u => u.email === email && u.password === password);
  }

  if (lower.includes('from orders') && lower.includes('admin')) {
    return orders;
  }

  if (lower.includes('from orders')) {
    const idMatch = sql.match(/id\s*=\s*(\d+)/);
    if (/union\s+select/i.test(sql)) {
      return users.map(u => ({ id: u.id, email: u.email, password: u.password, role: u.role }));
    }
    const id = idMatch ? Number(idMatch[1]) : null;
    return orders.filter(o => o.id === id);
  }

  if (lower.startsWith('insert into orders')) {
    orders.push({ id: orders.length + 1, user_id: 0, items: '[]', total: 0, address: '' });
    return [];
  }

  return [];
}

module.exports = { query, users, orders };
