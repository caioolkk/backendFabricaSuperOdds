// server.js
const express = require('express');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');
const path = require('path');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

// Configura CORS para permitir requisições do seu frontend no Vercel
app.use(cors({
  origin: ['https://fabrica-superodss.vercel.app', 'http://localhost:3000'],
  credentials: true
}));

app.use(express.json());

// Servir frontend estático (opcional — você pode manter no Vercel)
// Se quiser tudo em um só lugar, descomente a linha abaixo e coloque seu index.html na raiz
// app.use(express.static(path.join(__dirname, 'public')));

// Conexão com PostgreSQL (Render fornece DATABASE_URL automaticamente)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

// Função para garantir que a tabela exista
async function ensureUsersTable() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        enabled BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);
    console.log('✅ Tabela "users" verificada/criada com sucesso.');
  } catch (err) {
    console.error('❌ Erro ao criar tabela:', err);
  } finally {
    client.release();
  }
}

// Registrar
app.post('/api/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ success: false, message: 'Email e senha obrigatórios.' });
  }
  try {
    const hashed = await bcrypt.hash(password, 10);
    await pool.query(
      'INSERT INTO users (email, password, enabled) VALUES ($1, $2, false) ON CONFLICT (email) DO NOTHING',
      [email, hashed]
    );
    res.json({ success: true, message: 'Conta criada! Aguarde liberação do administrador.' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ success: false, message: 'Erro interno.' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
  const user = result.rows[0];
  if (!user || !user.enabled || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ success: false, message: 'Credenciais inválidas ou conta não liberada.' });
  }
  res.json({ success: true, message: 'Login bem-sucedido!' });
});

// Listar usuários (admin)
app.get('/api/users', async (req, res) => {
  const result = await pool.query('SELECT email, enabled FROM users ORDER BY created_at DESC');
  res.json({ success: true, users: result.rows });
});

// Liberar/bloquear
app.patch('/api/users/:email', async (req, res) => {
  const { enabled } = req.body;
  const result = await pool.query(
    'UPDATE users SET enabled = $1 WHERE email = $2',
    [!!enabled, req.params.email]
  );
  if (result.rowCount === 0) {
    return res.status(404).json({ success: false, message: 'Usuário não encontrado.' });
  }
  res.json({ success: true });
});

// Apagar usuário
app.delete('/api/users/:email', async (req, res) => {
  const result = await pool.query('DELETE FROM users WHERE email = $1', [req.params.email]);
  if (result.rowCount === 0) {
    return res.status(404).json({ success: false, message: 'Usuário não encontrado.' });
  }
  res.json({ success: true, message: 'Usuário removido.' });
});

// Inicializa o servidor
(async () => {
  await ensureUsersTable();
  app.listen(PORT, () => {
    console.log(`✅ Backend rodando em: http://localhost:${PORT}`);
    console.log(`🌐 Aceitando requisições de: https://fabrica-superodss.vercel.app`);
  });
})();