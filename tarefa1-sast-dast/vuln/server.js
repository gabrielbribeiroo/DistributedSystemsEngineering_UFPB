const express = require('express');
const cors = require('cors');
const { router: authRouter } = require('./auth');
const ordersRouter = require('./orders');
const app = express();

app.use(cors()); // V16 — aceita qualquer origem
app.use(express.json()); // V17 — sem limite de tamanho

// V18 — sem rate limiting
// V19 — sem helmet (headers de segurança)

app.use('/api', authRouter);
app.use('/api', ordersRouter);

// V20 — error handler expõe stack trace
app.use((err, req, res, next) => {
  res.status(500).json({
    error: err.message,
    stack: err.stack,
  });
});

const PORT = process.env.PORT || 3001;
if (require.main === module) {
  app.listen(PORT, () => console.log(`[vuln] GoFood inseguro rodando em http://localhost:${PORT}`));
}

module.exports = app;
