// Banco de dados em memória (mock) — usado só para permitir rodar o servidor localmente
// sem depender de Postgres/MySQL real. Simula uma tabela `users` e `orders`.
const users = [
  { id: 1, email: 'admin@gofood.com', password: 'admin123', role: 'admin' },
  { id: 2, email: 'joao@gofood.com', password: 'senha123', role: 'customer' },
];

const orders = [
  { id: 1, user_id: 2, items: '[{"productId":1,"qty":2}]', total: 39.8, address: 'Rua A, 123' },
  { id: 2, user_id: 1, items: '[{"productId":2,"qty":1}]', total: 15.0, address: 'Rua B, 456' },
];

// query() simula um driver SQL "cru": se receber uma string (concatenada) ela é
// interpretada de forma ingênua, o que é EXATAMENTE o comportamento vulnerável
// (equivalente ao que um driver real faria com uma query construída por concatenação).
function query(sql) {
  const lower = sql.toLowerCase();

  if (lower.includes('from users')) {
    // Simula injeção: se a cláusula WHERE contém "or '1'='1'" ou "or 1=1", retorna o primeiro usuário
    if (/or\s+'?1'?\s*=\s*'?1'?/i.test(sql)) {
      return [users[0]];
    }
    // Simula UNION SELECT vazando a tabela users inteira
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
