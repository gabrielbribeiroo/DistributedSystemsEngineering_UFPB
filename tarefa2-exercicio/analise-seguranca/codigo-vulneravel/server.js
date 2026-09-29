const express = require('express');
const cors = require('cors');
const { router: authRouter } = require('./auth');
const ordersRouter = require('./orders');
const app = express();

// V16 - sem passar opção nenhuma pro middleware de cors, aceita qualquer origem
app.use(cors());

// V17 - sem limit configurado, body gigante passa de boa
app.use(express.json());

// V18 - não tem rate limit em lugar nenhum, dá pra tentar login infinitas vezes
// V19 - também não tem helmet, faltam os headers de segurança padrão

app.use('/api', authRouter);
app.use('/api', ordersRouter);

// V20 - handler de erro devolvendo o stack trace pro cliente, bem ruim isso
app.use((err, req, res, next) => {
  res.status(500).json({
    error: err.message,
    stack: err.stack,
  });
});

const PORT = process.env.PORT || 3001;
if (require.main === module) {
  app.listen(PORT, () => console.log(`[vuln] rodando em http://localhost:${PORT}`));
}

module.exports = app;
