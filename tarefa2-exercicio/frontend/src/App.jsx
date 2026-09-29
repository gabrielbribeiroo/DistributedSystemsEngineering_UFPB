import React, { useState, useEffect } from 'react';
import DOMPurify from 'dompurify';

const API_BASE = import.meta.env.VITE_API_BASE || 'https://api.gofood.com';

function App() {
  const [user, setUser] = useState(null);
  const [isAdmin, setIsAdmin] = useState(false);

  async function handleLogin(email, password) {
    const res = await fetch(`${API_BASE}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include', // pra mandar/receber o cookie
      body: JSON.stringify({ email, password }),
    });
    if (!res.ok) throw new Error('Falha no login');
    // não guardo token nem role em lugar nenhum aqui, fica tudo no cookie
    await checkAdminAccess();
    setUser({ authenticated: true });
  }

  async function checkAdminAccess() {
    const res = await fetch(`${API_BASE}/api/me`, { credentials: 'include' });
    if (!res.ok) { setIsAdmin(false); return; }
    const data = await res.json();
    // pergunta pro servidor qual é o role, não decido isso no front
    setIsAdmin(data.role === 'admin');
  }

  useEffect(() => { checkAdminAccess(); }, []);

  function AdminPanel() {
    // isso aqui é só cosmético, quem realmente barra é o backend
    if (!isAdmin) return null;
    return <div>Painel Admin...</div>;
  }

  function ProductComments({ comments }) {
    return (
      <div>
        {comments.map(c => (
          <div
            key={c.id}
            dangerouslySetInnerHTML={{
              __html: DOMPurify.sanitize(c.text, { ALLOWED_TAGS: ['b', 'i', 'em', 'strong'] }),
            }}
          />
        ))}
      </div>
    );
  }

  return (/* ... */);
}

export default App;
