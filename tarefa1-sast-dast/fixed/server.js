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
})); // mitiga V19 (ausência de helmet)

app.use(cors({ origin: ALLOWED_ORIGIN, credentials: true })); // mitiga V16 (CORS aberto)
app.use(express.json({ limit: '16kb' })); // mitiga V17 (sem limite de tamanho)
app.use(cookieParser());

const globalLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 300 });
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5 });
app.use('/api', globalLimiter); // mitiga V18 (sem rate limiting)
app.use('/api/login', loginLimiter);

app.use('/api', authRouter);
app.use('/api', ordersRouter);

// V20 — error handler não expõe stack trace em produção
app.use((err, req, res, next) => {
  console.error(err);
  res.status(err.status || 500).json({ error: isProd ? 'Erro interno do servidor' : err.message });
});

const PORT = process.env.PORT || 3002;
if (require.main === module) {
  app.listen(PORT, () => console.log(`[fixed] GoFood corrigido rodando em http://localhost:${PORT}`));
}

module.exports = app;
