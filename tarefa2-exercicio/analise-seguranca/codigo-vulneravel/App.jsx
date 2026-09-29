import React, { useState } from 'react';

function App() {
  const [user, setUser] = useState(null);

  async function handleLogin(email, password) {
    const res = await fetch('http://localhost:3000/api/login', { // V11, tá em http mesmo, não https
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });
    const data = await res.json();
    localStorage.setItem('token', data.token); // V12
    localStorage.setItem('role', data.role); // V13
    setUser(data);
  }

  // decide se mostra o painel admin olhando o role do localStorage (V14)
  function AdminPanel() {
    if (localStorage.getItem('role') !== 'admin') return null;
    return <div>Painel Admin...</div>;
  }

  // renderiza o comentário como html puro, sem sanitizar nada (V15)
  function ProductComments({ comments }) {
    return (
      <div>
        {comments.map(c => (
          <div key={c.id} dangerouslySetInnerHTML={{ __html: c.text }} />
        ))}
      </div>
    );
  }

  return (/* ... */);
}

export default App;
