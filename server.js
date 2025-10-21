// server.js
const express = require('express');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 10000;

// Verifica se a DATABASE_URL está definida
if (!process.env.DATABASE_URL) {
  console.error('❌ ERRO: DATABASE_URL não está definida.');
  process.exit(1);
}

// Pool de conexões com PostgreSQL (Render)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false // necessário para o Render
  },
  max: 10,        // máximo de conexões simultâneas
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000
});

// Middleware
app.use(cors({
  origin: ['https://fabrica-superodss.vercel.app', 'http://localhost:3000'],
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));

// Cria a tabela de usuários se não existir
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
    throw err;
  } finally {
    client.release();
  }
}

// ========== ROTAS ==========

// Registrar usuário
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
  if (!email || !password) {
    return res.status(400).json({ success: false, message: 'Email e senha obrigatórios.' });
  }

  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];
    if (!user || !user.enabled || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ success: false, message: 'Credenciais inválidas ou conta não liberada.' });
    }
    res.json({ success: true, message: 'Login bem-sucedido!' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ success: false, message: 'Erro interno.' });
  }
});

// Listar usuários (admin)
app.get('/api/users', async (req, res) => {
  try {
    const result = await pool.query('SELECT email, enabled FROM users ORDER BY created_at DESC');
    res.json({ success: true, users: result.rows });
  } catch (e) {
    console.error(e);
    res.status(500).json({ success: false, message: 'Erro ao carregar usuários.' });
  }
});

// Liberar/bloquear usuário
app.patch('/api/users/:email', async (req, res) => {
  const { enabled } = req.body;
  const email = req.params.email;

  try {
    const result = await pool.query(
      'UPDATE users SET enabled = $1 WHERE email = $2',
      [!!enabled, email]
    );
    if (result.rowCount === 0) {
      return res.status(404).json({ success: false, message: 'Usuário não encontrado.' });
    }
    res.json({ success: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ success: false, message: 'Erro ao atualizar usuário.' });
  }
});

// Apagar usuário
app.delete('/api/users/:email', async (req, res) => {
  const email = req.params.email;
  try {
    const result = await pool.query('DELETE FROM users WHERE email = $1', [email]);
    if (result.rowCount === 0) {
      return res.status(404).json({ success: false, message: 'Usuário não encontrado.' });
    }
    res.json({ success: true, message: 'Usuário removido.' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ success: false, message: 'Erro ao apagar usuário.' });
  }
});

// Health check (opcional, para Render)
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok', uptime: process.uptime() });
});

// Inicializa o servidor
(async () => {
  try {
    await ensureUsersTable();
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`✅ Backend rodando na porta ${PORT}`);
      console.log(`🌐 Aceitando requisições de: https://fabrica-superodss.vercel.app`);
    });
  } catch (err) {
    console.error('❌ Falha ao iniciar o servidor:', err);
    process.exit(1);
  }
})();