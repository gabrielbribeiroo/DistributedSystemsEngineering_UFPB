// versao corrigida do bootstrap, comparar com ../vuln/server.js
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

// helmet com csp, resolve o V19
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

// só a origem da SPA pode chamar a api agora (V16)
app.use(cors({ origin: ALLOWED_ORIGIN, credentials: true }));
// limitei o tamanho do body em 16kb (V17)
app.use(express.json({ limit: '16kb' }));
app.use(cookieParser());

const globalLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 300 });
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5 });
app.use('/api', globalLimiter);
// esse aqui mais restrito, só pro login (era o V18)
app.use('/api/login', loginLimiter);

app.use('/api', authRouter);
app.use('/api', ordersRouter);

// não manda mais o stack no erro, só uma mensagem genérica se for prod (V20)
app.use((err, req, res, next) => {
  console.error(err);
  res.status(err.status || 500).json({ error: isProd ? 'Erro interno do servidor' : err.message });
});

const PORT = process.env.PORT || 3002;
if (require.main === module) {
  app.listen(PORT, () => console.log(`[fixed] rodando em http://localhost:${PORT}`));
}

module.exports = app;
