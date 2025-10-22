// =============================
//  BACKEND FÁBRICA SUPER ODDS
// =============================

const express = require('express');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 10000;

// =============================
//   CONEXÃO COM O BANCO
// =============================
if (!process.env.DATABASE_URL) {
  console.error('❌ ERRO: DATABASE_URL não está definida no ambiente.');
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000
});

// =============================
//   CONFIGURAÇÃO DE CORS
// =============================
const corsOptions = {
  origin: [
    'https://fabricasuperodds.vercel.app', // 🔹 painel principal
    'http://localhost:3000' // 🔹 modo de teste local
  ],
  methods: ['GET', 'POST', 'PATCH', 'DELETE'],
  credentials: true,
  optionsSuccessStatus: 200
};

app.use(cors(corsOptions));
app.use(express.json({ limit: '10mb' }));

// =============================
//   CRIAÇÃO AUTOMÁTICA DA TABELA
// =============================
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
    console.error('❌ Erro ao criar/verificar tabela:', err);
  } finally {
    client.release();
  }
}

// =============================
//   FUNÇÃO DE VALIDAÇÃO DE EMAIL
// =============================
function validateEmail(email) {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(String(email).toLowerCase());
}

// =============================
//   ROTAS PRINCIPAIS
// =============================

// 📌 Registrar usuário
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
    console.error('❌ Erro ao registrar usuário:', e);
    return res.status(500).json({ success: false, message: 'Erro interno ao criar conta.' });
  }
});

// 📌 Login
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
    console.error('❌ Erro ao fazer login:', e);
    return res.status(500).json({ success: false, message: 'Erro interno ao autenticar.' });
  }
});

// 📌 Listar usuários
app.get('/api/users', async (req, res) => {
  try {
    const result = await pool.query('SELECT email, enabled FROM users ORDER BY created_at DESC');
    return res.json(result.rows);
  } catch (e) {
    console.error('❌ Erro ao listar usuários:', e);
    return res.status(500).json({ success: false, message: 'Erro ao carregar usuários.' });
  }
});

// 📌 Liberar ou bloquear usuário
app.patch('/api/users/:email', async (req, res) => {
  const email = decodeURIComponent(req.params.email);
  const { enabled } = req.body;

  if (!validateEmail(email)) {
    return res.status(400).json({ success: false, message: 'Email inválido.' });
  }

  try {
    const result = await pool.query('UPDATE users SET enabled = $1 WHERE email = $2', [!!enabled, email]);
    if (result.rowCount === 0) {
      return res.status(404).json({ success: false, message: 'Usuário não encontrado.' });
    }

    console.log(`🔄 Status atualizado: ${email} → ${enabled ? 'LIBERADO' : 'BLOQUEADO'}`);
    return res.json({ success: true });
  } catch (e) {
    console.error('❌ Erro ao atualizar usuário:', e);
    return res.status(500).json({ success: false, message: 'Erro ao atualizar status.' });
  }
});

// 📌 Excluir usuário
app.delete('/api/users/:email', async (req, res) => {
  const email = decodeURIComponent(req.params.email);

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
    console.error('❌ Erro ao remover usuário:', e);
    return res.status(500).json({ success: false, message: 'Erro ao remover usuário.' });
  }
});

// 📌 Health check
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok', uptime: Math.floor(process.uptime()) });
});

// 📌 Rota raiz
app.get('/', (req, res) => {
  res.json({ message: 'Backend Fábrica Super Odds — OK ✅' });
});

// =============================
//   INICIALIZAÇÃO
// =============================
(async () => {
  try {
    await ensureUsersTable();
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`✅ Servidor online na porta ${PORT}`);
      console.log(`🌐 Aceitando requisições de: https://fabricasuperodds.vercel.app`);
    });
  } catch (err) {
    console.error('❌ Falha ao iniciar servidor:', err);
    process.exit(1);
  }
})();
