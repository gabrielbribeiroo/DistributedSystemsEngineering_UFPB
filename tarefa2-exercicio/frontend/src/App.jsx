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
      credentials: 'include', // envia/recebe o cookie HttpOnly
      body: JSON.stringify({ email, password }),
    });
    if (!res.ok) throw new Error('Falha no login');
    // Nenhum token ou role é armazenado no cliente — tudo vive no cookie HttpOnly
    await checkAdminAccess();
    setUser({ authenticated: true });
  }

  async function checkAdminAccess() {
    const res = await fetch(`${API_BASE}/api/me`, { credentials: 'include' });
    if (!res.ok) { setIsAdmin(false); return; }
    const data = await res.json();
    // role vem do servidor a cada checagem — nunca é decisão do cliente
    setIsAdmin(data.role === 'admin');
  }

  useEffect(() => { checkAdminAccess(); }, []);

  function AdminPanel() {
    // A UI só reflete o que o servidor autorizou; a rota /api/admin/* também
    // reforça a checagem no backend (defesa em profundidade).
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
