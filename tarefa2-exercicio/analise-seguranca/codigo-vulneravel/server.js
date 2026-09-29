// server.js — bootstrap do GoFood na sua forma original, sem nenhuma camada
// de proteção adicional. Cada omissão abaixo é intencional (parte do
// enunciado) e vira alvo de teste no relatório de SAST/DAST.
const express = require('express');
const cors = require('cors');
const { router: authRouter } = require('./auth');
const ordersRouter = require('./orders');
const app = express();

// (V16) Nenhuma allowlist de origem foi configurada — o middleware de CORS
// reflete o header Origin da requisição de volta, para qualquer domínio.
app.use(cors());

// (V17) Nenhum `limit` configurado — o parser aceita corpos JSON de
// qualquer tamanho, abrindo espaço para esgotamento de memória/CPU.
app.use(express.json());

// (V18) Sem express-rate-limit (ou equivalente): /api/login aceita quantas
// tentativas de login o cliente quiser mandar, sem qualquer bloqueio.
// (V19) Sem helmet(): faltam CSP, X-Frame-Options, HSTS e afins.

app.use('/api', authRouter);
app.use('/api', ordersRouter);

// (V20) O error handler devolve err.stack no corpo da resposta — em
// produção isso vaza caminhos de arquivo, versões de dependências e
// detalhes de implementação para qualquer cliente que provocar um erro.
app.use((err, req, res, next) => {
  res.status(500).json({
    error: err.message,
    stack: err.stack,
  });
});

const PORT = process.env.PORT || 3001;
if (require.main === module) {
  app.listen(PORT, () => console.log(`[vuln] servidor GoFood (estado original) ouvindo em http://localhost:${PORT}`));
}

module.exports = app;
