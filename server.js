// server.js
const express = require('express');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');
const path = require('path');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

// PostgreSQL no Render
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

app.use(cors());
app.use(express.json());
app.use(express.static('.')); // serve index.html

// Registrar
app.post('/api/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ success: false, message: 'Email e senha obrigatórios.' });
  }
  try {
    const hashed = await bcrypt.hash(password, 10);
    await pool.query(
      'INSERT INTO users (email, password, enabled) VALUES ($1, $2, false)',
      [email, hashed]
    );
    res.json({ success: true, message: 'Conta criada! Aguarde liberação do administrador.' });
  } catch (e) {
    if (e.code === '23505') {
      res.status(400).json({ success: false, message: 'Email já cadastrado.' });
    } else {
      console.error(e);
      res.status(500).json({ success: false, message: 'Erro interno.' });
    }
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
    'UPDATE users SET enabled = $1 WHERE email = $2 RETURNING *',
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

app.listen(PORT, () => {
  console.log(`✅ Servidor rodando na porta ${PORT}`);
});