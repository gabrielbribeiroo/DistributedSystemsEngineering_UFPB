// Stand-in de banco de dados: não há Postgres/MySQL real aqui, só um array
// em memória com uma "interpretação" ingênua da string SQL recebida — o
// suficiente para reproduzir, sem infraestrutura extra, o comportamento que
// um driver real teria diante de uma query montada por concatenação.
const users = [
  { id: 1, email: 'admin@gofood.com', password: 'admin123', role: 'admin' },
  { id: 2, email: 'joao@gofood.com', password: 'senha123', role: 'customer' },
];

const orders = [
  { id: 1, user_id: 2, items: '[{"productId":1,"qty":2}]', total: 39.8, address: 'Rua A, 123' },
  { id: 2, user_id: 1, items: '[{"productId":2,"qty":1}]', total: 15.0, address: 'Rua B, 456' },
];

// A função abaixo não faz parsing SQL de verdade — ela só reconhece os
// padrões de query que auth.js/orders.js efetivamente emitem e devolve um
// resultado condizente, inclusive quando esse SQL foi manipulado por injeção.
function query(sql) {
  const lower = sql.toLowerCase();

  if (lower.includes('from users')) {
    // Tautologia clássica de bypass de login (`OR '1'='1'`): devolve o
    // primeiro registro, como uma query real faria com essa WHERE sempre-verdadeira.
    if (/or\s+'?1'?\s*=\s*'?1'?/i.test(sql)) {
      return [users[0]];
    }
    // UNION SELECT: expõe a tabela inteira, como aconteceria num banco real
    // se as colunas da query injetada baterem com as da query original.
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
