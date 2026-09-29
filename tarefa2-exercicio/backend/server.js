// server.js — versão CORRIGIDA do bootstrap (ver ../vuln/server.js para a
// forma original, sem nenhuma dessas camadas).
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const { router: authRouter } = require('./auth');
const ordersRouter = require('./orders');
const app = express();

const isProd = process.env.NODE_ENV === 'production';
const ALLOWED_ORIGIN = process.env.SPA_ORIGIN || 'http://localhost:5173';

// headers de segurança padrão + CSP restritiva
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:'],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
    },
  },
}));

// única origem permitida, com suporte a cookies cross-site
app.use(cors({ origin: ALLOWED_ORIGIN, credentials: true }));
// corpo JSON limitado a 16kb — nada de payloads gigantes esgotando o processo
app.use(express.json({ limit: '16kb' }));
app.use(cookieParser());

const globalLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 300 });
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5 });
app.use('/api', globalLimiter);
// limite mais apertado só para o login, onde brute force importa mais
app.use('/api/login', loginLimiter);

app.use('/api', authRouter);
app.use('/api', ordersRouter);

// resposta de erro genérica em produção — quem chama não recebe stack
// trace nem nada que revele detalhes internos do servidor.
app.use((err, req, res, next) => {
  console.error(err);
  res.status(err.status || 500).json({ error: isProd ? 'Erro interno do servidor' : err.message });
});

const PORT = process.env.PORT || 3002;
if (require.main === module) {
  app.listen(PORT, () => console.log(`[fixed] GoFood corrigido rodando em http://localhost:${PORT}`));
}

module.exports = app;
