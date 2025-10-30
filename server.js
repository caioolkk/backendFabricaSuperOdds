// server.js
const express = require('express');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 10000;

// Verifica se a DATABASE_URL está definida
if (!process.env.DATABASE_URL) {
  console.error('❌ ERRO: DATABASE_URL não está definida no ambiente.');
  process.exit(1);
}

// Pool de conexões com PostgreSQL (Render)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false // necessário para o Render
  },
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000
});

// ==============================
// 🚀 CORS TOTALMENTE LIBERADO
// ==============================
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));
app.use(express.json({ limit: '10mb' }));

// ==============================
// 🧱 CRIAÇÃO DAS TABELAS
// ==============================

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
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);
    console.log('✅ Tabela "users" verificada/criada com sucesso.');
  } catch (err) {
    console.error('❌ Erro ao criar tabela users:', err);
    throw err;
  } finally {
    client.release();
  }
}

// Cria a tabela de registros (planilha)
async function ensureRecordsTable() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS records (
        id SERIAL PRIMARY KEY,
        email TEXT NOT NULL,
        data DATE NOT NULL,
        casa TEXT,
        descricao TEXT,
        observacoes TEXT,
        mercado TEXT,
        situacao TEXT,
        lucro NUMERIC(10,2),
        qtd_contas INTEGER,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);
    console.log('✅ Tabela "records" verificada/criada com sucesso.');
  } catch (err) {
    console.error('❌ Erro ao criar tabela records:', err);
  } finally {
    client.release();
  }
}

// Middleware de validação
function validateEmail(email) {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(String(email).toLowerCase());
}

// ==============================
// 🔐 ROTAS DE AUTENTICAÇÃO
// ==============================

// Registrar usuário
app.post('/api/register', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ success: false, message: 'Email e senha são obrigatórios.' });
  }

  if (!validateEmail(email)) {
    return res.status(400).json({ success: false, message: 'Email inválido.' });
  }

  if (password.length < 6) {
    return res.status(400).json({ success: false, message: 'A senha deve ter pelo menos 6 caracteres.' });
  }

  try {
    const hashed = await bcrypt.hash(password, 12);
    const result = await pool.query(
      'INSERT INTO users (email, password, enabled) VALUES ($1, $2, false) ON CONFLICT (email) DO NOTHING RETURNING id',
      [email, hashed]
    );

    if (result.rows.length === 0) {
      return res.status(409).json({ success: false, message: 'Email já cadastrado.' });
    }

    console.log(`🆕 Novo usuário registrado: ${email}`);
    return res.json({ success: true, message: 'Conta criada! Aguarde liberação do administrador.' });
  } catch (e) {
    console.error('Erro ao registrar usuário:', e);
    return res.status(500).json({ success: false, message: 'Erro interno ao criar conta.' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ success: false, message: 'Email e senha são obrigatórios.' });
  }

  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];

    if (!user) {
      return res.status(401).json({ success: false, message: 'Credenciais inválidas.' });
    }

    if (!user.enabled) {
      return res.status(403).json({ success: false, message: 'Conta pendente de liberação pelo administrador.' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ success: false, message: 'Credenciais inválidas.' });
    }

    console.log(`✅ Login bem-sucedido: ${email}`);
    return res.json({ success: true, message: 'Login bem-sucedido!' });
  } catch (e) {
    console.error('Erro ao fazer login:', e);
    return res.status(500).json({ success: false, message: 'Erro interno ao autenticar.' });
  }
});

// Listar usuários (admin)
app.get('/api/users', async (req, res) => {
  try {
    const result = await pool.query('SELECT email, enabled FROM users ORDER BY created_at DESC');
    return res.json({ success: true, users: result.rows });
  } catch (e) {
    console.error('Erro ao listar usuários:', e);
    return res.status(500).json({ success: false, message: 'Erro ao carregar usuários.' });
  }
});

// Liberar/bloquear usuário
app.patch('/api/users/:email', async (req, res) => {
  const { enabled } = req.body;
  let email = req.params.email;

  try {
    email = decodeURIComponent(email);
  } catch (e) {
    return res.status(400).json({ success: false, message: 'Email inválido (falha na decodificação).' });
  }

  if (!validateEmail(email)) {
    return res.status(400).json({ success: false, message: 'Email inválido.' });
  }

  try {
    const result = await pool.query(
      'UPDATE users SET enabled = $1 WHERE email = $2',
      [!!enabled, email]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ success: false, message: 'Usuário não encontrado.' });
    }

    console.log(`🔄 Status atualizado: ${email} → ${enabled ? 'liberado' : 'bloqueado'}`);
    return res.json({ success: true });
  } catch (e) {
    console.error('Erro ao atualizar usuário:', e);
    return res.status(500).json({ success: false, message: 'Erro ao atualizar status do usuário.' });
  }
});

// Apagar usuário
app.delete('/api/users/:email', async (req, res) => {
  let email = req.params.email;

  try {
    email = decodeURIComponent(email);
  } catch (e) {
    return res.status(400).json({ success: false, message: 'Email inválido (falha na decodificação).' });
  }

  if (!validateEmail(email)) {
    return res.status(400).json({ success: false, message: 'Email inválido.' });
  }

  try {
    const result = await pool.query('DELETE FROM users WHERE email = $1', [email]);

    if (result.rowCount === 0) {
      return res.status(404).json({ success: false, message: 'Usuário não encontrado.' });
    }

    console.log(`🗑️ Usuário removido: ${email}`);
    return res.json({ success: true, message: 'Usuário removido com sucesso.' });
  } catch (e) {
    console.error('Erro ao apagar usuário:', e);
    return res.status(500).json({ success: false, message: 'Erro ao remover usuário.' });
  }
});

// ==============================
// 🧾 ROTAS DE REGISTROS (PLANILHA)
// ==============================

// Salvar registro da planilha
app.post('/api/records', async (req, res) => {
  const { email, data, casa, descricao, observacoes, mercado, situacao, lucro, qtdContas } = req.body;

  if (!email || !data) {
    return res.status(400).json({ success: false, message: 'Email e data são obrigatórios.' });
  }

  try {
    await pool.query(
      `INSERT INTO records (email, data, casa, descricao, observacoes, mercado, situacao, lucro, qtd_contas)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
      [email, data, casa, descricao, observacoes, mercado, situacao, lucro, qtdContas]
    );
    console.log(`📊 Registro salvo por ${email}: ${descricao}`);
    return res.json({ success: true, message: 'Registro salvo com sucesso!' });
  } catch (e) {
    console.error('Erro ao salvar registro:', e);
    return res.status(500).json({ success: false, message: 'Erro interno ao salvar registro.' });
  }
});

// Listar registros da planilha (somente do usuário)
app.get('/api/records', async (req, res) => {
  const email = req.query.email;
  if (!email) {
    return res.status(400).json({ success: false, message: 'Email não informado.' });
  }

  try {
    const result = await pool.query(
      'SELECT * FROM records WHERE email = $1 ORDER BY data DESC',
      [email]
    );
    return res.json({ success: true, records: result.rows });
  } catch (e) {
    console.error('Erro ao buscar registros:', e);
    return res.status(500).json({ success: false, message: 'Erro ao carregar registros.' });
  }
});

// ==============================
// 🩺 HEALTH CHECK
// ==============================
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok', uptime: Math.floor(process.uptime()) });
});

// Rota raiz
app.get('/', (req, res) => {
  res.json({ message: 'Backend Fábrica Super Odd — OK ✅' });
});

// Inicializa o servidor
(async () => {
  try {
    await ensureUsersTable();
    await ensureRecordsTable(); // ✅ nova tabela planilha
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`✅ Backend rodando na porta ${PORT}`);
      console.log(`🌐 CORS: totalmente liberado`);
    });
  } catch (err) {
    console.error('❌ Falha crítica ao iniciar o servidor:', err);
    process.exit(1);
  }
})();
