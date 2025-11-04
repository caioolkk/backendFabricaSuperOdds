// server.js - VERSÃO CORRIGIDA E SEGUURA
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
  methods: ['GET', 'POST', 'PATCH', 'DELETE', 'PUT', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));
app.use(express.json({ limit: '10mb' }));

// Middleware de validação de email
function validateEmail(email) {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(String(email).toLowerCase());
}

// Middleware de tratamento global de erros (garante que sempre retorne JSON)
app.use((err, req, res, next) => {
  console.error('❌ Erro global capturado:', err);
  res.status(500).json({
    success: false,
    message: 'Erro interno do servidor',
    error: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

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
    throw err;
  } finally {
    client.release();
  }
}

// Cria a tabela de anotações (notes)
async function ensureNotesTable() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS notes (
        id SERIAL PRIMARY KEY,
        email TEXT NOT NULL,
        content TEXT NOT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);
    console.log('✅ Tabela "notes" verificada/criada com sucesso.');
  } catch (err) {
    console.error('❌ Erro ao criar tabela notes:', err);
    throw err;
  } finally {
    client.release();
  }
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
    return res.status(500).json({ 
      success: false, 
      message: 'Erro interno ao criar conta.',
      error: process.env.NODE_ENV === 'development' ? e.message : undefined
    });
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
    return res.status(500).json({ 
      success: false, 
      message: 'Erro interno ao autenticar.',
      error: process.env.NODE_ENV === 'development' ? e.message : undefined
    });
  }
});

// Listar usuários (admin)
app.get('/api/users', async (req, res) => {
  try {
    const result = await pool.query('SELECT email, enabled FROM users ORDER BY created_at DESC');
    return res.json({ success: true, users: result.rows });
  } catch (e) {
    console.error('Erro ao listar usuários:', e);
    return res.status(500).json({ 
      success: false, 
      message: 'Erro ao carregar usuários.',
      error: process.env.NODE_ENV === 'development' ? e.message : undefined
    });
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
    return res.status(500).json({ 
      success: false, 
      message: 'Erro ao atualizar status do usuário.',
      error: process.env.NODE_ENV === 'development' ? e.message : undefined
    });
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
    return res.status(500).json({ 
      success: false, 
      message: 'Erro ao remover usuário.',
      error: process.env.NODE_ENV === 'development' ? e.message : undefined
    });
  }
});

// ==============================
// 🧾 ROTAS DE REGISTROS (PLANILHA)
// ==============================

// Criar novo registro
app.post('/api/records', async (req, res) => {
  const { email, data, casa, descricao, observacoes, mercado, situacao, lucro, qtdContas } = req.body;

  if (!email || !data) {
    return res.status(400).json({ success: false, message: 'Email e data são obrigatórios.' });
  }

  if (!validateEmail(email)) {
    return res.status(400).json({ success: false, message: 'Email inválido.' });
  }

  try {
    await pool.query(
      `INSERT INTO records (email, data, casa, descricao, observacoes, mercado, situacao, lucro, qtd_contas)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
      [email, data, casa || '', descricao || '', observacoes || '', mercado || 'DIRETO', situacao || 'CONCLUÍDO', 
       lucro || 0, qtdContas || 1]
    );
    console.log(`📊 Registro salvo por ${email}: ${descricao || 'sem descrição'}`);
    return res.json({ success: true, message: 'Registro salvo com sucesso!' });
  } catch (e) {
    console.error('Erro ao salvar registro:', e);
    return res.status(500).json({ 
      success: false, 
      message: 'Erro interno ao salvar registro.',
      error: process.env.NODE_ENV === 'development' ? e.message : undefined
    });
  }
});

// Atualizar registro existente
app.put('/api/records/:id', async (req, res) => {
  const { id } = req.params;
  const { email, data, casa, descricao, observacoes, mercado, situacao, lucro, qtdContas } = req.body;

  // Validação básica
  if (!id || isNaN(id)) {
    return res.status(400).json({ success: false, message: 'ID inválido.' });
  }
  if (!email || !data) {
    return res.status(400).json({ success: false, message: 'Email e data são obrigatórios.' });
  }
  if (!validateEmail(email)) {
    return res.status(400).json({ success: false, message: 'Email inválido.' });
  }

  try {
    // Primeiro verifica se o registro existe e pertence ao usuário
    const checkResult = await pool.query(
      'SELECT id FROM records WHERE id = $1 AND email = $2',
      [id, email]
    );

    if (checkResult.rows.length === 0) {
      console.log(`❌ Tentativa de atualizar registro inexistente ou de outro usuário. ID: ${id}, Email: ${email}`);
      return res.status(404).json({ 
        success: false, 
        message: 'Registro não encontrado ou você não tem permissão para editá-lo.'
      });
    }

    // Atualiza o registro
    const result = await pool.query(
      `UPDATE records 
       SET data = $1, casa = $2, descricao = $3, observacoes = $4, mercado = $5, 
           situacao = $6, lucro = $7, qtd_contas = $8, updated_at = NOW()
       WHERE id = $9 AND email = $10
       RETURNING *`,
      [data, casa || '', descricao || '', observacoes || '', mercado || 'DIRETO', situacao || 'CONCLUÍDO',
       lucro || 0, qtdContas || 1, id, email]
    );

    console.log(`✏️ Registro atualizado (ID: ${id}) por ${email}`);
    return res.json({ success: true, record: result.rows[0] });

  } catch (e) {
    console.error('❌ Erro ao atualizar registro:', e);
    return res.status(500).json({ 
      success: false, 
      message: 'Erro interno ao atualizar registro.',
      error: process.env.NODE_ENV === 'development' ? e.message : undefined
    });
  }
});

// Excluir registro por ID
app.delete('/api/records/:id', async (req, res) => {
  const { id } = req.params;
  const email = req.query.email; // Agora aceita o email como query param

  // Validação
  if (!id || isNaN(id)) {
    return res.status(400).json({ success: false, message: 'ID inválido.' });
  }
  if (!email) {
    return res.status(400).json({ success: false, message: 'Email é obrigatório.' });
  }
  if (!validateEmail(email)) {
    return res.status(400).json({ success: false, message: 'Email inválido.' });
  }

  try {
    // Verifica se o registro existe e pertence ao usuário
    const checkResult = await pool.query(
      'SELECT id FROM records WHERE id = $1 AND email = $2',
      [id, email]
    );

    if (checkResult.rows.length === 0) {
      console.log(`❌ Tentativa de excluir registro inexistente ou de outro usuário. ID: ${id}, Email: ${email}`);
      return res.status(404).json({ 
        success: false, 
        message: 'Registro não encontrado ou você não tem permissão para excluí-lo.'
      });
    }

    // Exclui o registro
    const result = await pool.query(
      'DELETE FROM records WHERE id = $1 AND email = $2',
      [id, email]
    );

    console.log(`🗑️ Registro excluído (ID: ${id}) por ${email}`);
    return res.json({ success: true, message: 'Registro excluído com sucesso.' });

  } catch (e) {
    console.error('❌ Erro ao excluir registro:', e);
    return res.status(500).json({ 
      success: false, 
      message: 'Erro ao excluir registro.',
      error: process.env.NODE_ENV === 'development' ? e.message : undefined
    });
  }
});

// Listar registros com filtros
app.get('/api/records', async (req, res) => {
  const email = req.query.email;
  if (!email) return res.status(400).json({ success: false, message: 'Email não informado.' });
  if (!validateEmail(email)) return res.status(400).json({ success: false, message: 'Email inválido.' });

  try {
    let query = 'SELECT * FROM records WHERE email = $1';
    const params = [email];
    let paramIndex = 2;

    if (req.query.day) {
      query += ` AND EXTRACT(DAY FROM data) = $${paramIndex++}`;
      params.push(req.query.day);
    }
    if (req.query.month) {
      const months = {
        'Janeiro': 1, 'Fevereiro': 2, 'Março': 3, 'Abril': 4, 'Maio': 5, 'Junho': 6,
        'Julho': 7, 'Agosto': 8, 'Setembro': 9, 'Outubro': 10, 'Novembro': 11, 'Dezembro': 12
      };
      const monthNum = months[req.query.month];
      if (monthNum) {
        query += ` AND EXTRACT(MONTH FROM data) = $${paramIndex++}`;
        params.push(monthNum);
      }
    }
    if (req.query.year) {
      query += ` AND EXTRACT(YEAR FROM data) = $${paramIndex++}`;
      params.push(req.query.year);
    }
    if (req.query.casa) {
      query += ` AND LOWER(casa) LIKE LOWER($${paramIndex++})`;
      params.push(`%${req.query.casa}%`);
    }
    if (req.query.mercado && req.query.mercado !== 'Todos') {
      query += ` AND mercado = $${paramIndex++}`;
      params.push(req.query.mercado);
    }
    if (req.query.situacao && req.query.situacao !== 'Todas') {
      query += ` AND situacao = $${paramIndex++}`;
      params.push(req.query.situacao);
    }
    if (req.query.freebets && req.query.freebets !== 'Todos') {
      if (req.query.freebets === 'UTILIZADA') query += ` AND lucro > 0`;
      else if (req.query.freebets === 'EM ABERTO') query += ` AND lucro <= 0`;
    }

    query += ' ORDER BY data DESC';

    const result = await pool.query(query, params);
    return res.json({ success: true, records: result.rows });
  } catch (e) {
    console.error('Erro ao buscar registros:', e);
    return res.status(500).json({ 
      success: false, 
      message: 'Erro ao carregar registros.',
      error: process.env.NODE_ENV === 'development' ? e.message : undefined
    });
  }
});

// ==============================
// 📝 ANOTAÇÕES
// ==============================

// Listar anotações
app.get('/api/notes', async (req, res) => {
  const email = req.query.email;
  if (!email) return res.status(400).json({ success: false, message: 'Email não informado.' });
  if (!validateEmail(email)) return res.status(400).json({ success: false, message: 'Email inválido.' });

  try {
    const result = await pool.query(
      'SELECT id, content, created_at FROM notes WHERE email = $1 ORDER BY created_at DESC',
      [email]
    );
    return res.json({ success: true, notes: result.rows });
  } catch (e) {
    console.error('Erro ao buscar anotações:', e);
    return res.status(500).json({ 
      success: false, 
      message: 'Erro ao carregar anotações.',
      error: process.env.NODE_ENV === 'development' ? e.message : undefined
    });
  }
});

// Criar anotação
app.post('/api/notes', async (req, res) => {
  const { email, content } = req.body;
  if (!email || !content || content.trim() === '') {
    return res.status(400).json({ success: false, message: 'Email e conteúdo são obrigatórios.' });
  }
  if (!validateEmail(email)) {
    return res.status(400).json({ success: false, message: 'Email inválido.' });
  }

  try {
    const result = await pool.query(
      'INSERT INTO notes (email, content) VALUES ($1, $2) RETURNING *',
      [email, content.trim()]
    );
    return res.json({ success: true, note: result.rows[0] });
  } catch (e) {
    console.error('Erro ao salvar anotação:', e);
    return res.status(500).json({ 
      success: false, 
      message: 'Erro ao salvar anotação.',
      error: process.env.NODE_ENV === 'development' ? e.message : undefined
    });
  }
});

// Excluir anotação
app.delete('/api/notes/:id', async (req, res) => {
  const { id } = req.params;
  const email = req.query.email;

  if (!email || !id) {
    return res.status(400).json({ success: false, message: 'Email e ID são obrigatórios.' });
  }
  if (!validateEmail(email)) {
    return res.status(400).json({ success: false, message: 'Email inválido.' });
  }
  if (isNaN(id)) {
    return res.status(400).json({ success: false, message: 'ID inválido.' });
  }

  try {
    // Verifica se a anotação pertence ao usuário
    const checkResult = await pool.query(
      'SELECT id FROM notes WHERE id = $1 AND email = $2',
      [id, email]
    );

    if (checkResult.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Anotação não encontrada ou acesso negado.' });
    }

    const result = await pool.query(
      'DELETE FROM notes WHERE id = $1 AND email = $2',
      [id, email]
    );

    return res.json({ success: true });
  } catch (e) {
    console.error('Erro ao excluir anotação:', e);
    return res.status(500).json({ 
      success: false, 
      message: 'Erro ao excluir anotação.',
      error: process.env.NODE_ENV === 'development' ? e.message : undefined
    });
  }
});

// ==============================
// 🩺 HEALTH CHECK
// ==============================
app.get('/health', (req, res) => {
  res.status(200).json({ 
    status: 'ok', 
    uptime: Math.floor(process.uptime()),
    timestamp: new Date().toISOString(),
    nodeVersion: process.version
  });
});

// Rota raiz
app.get('/', (req, res) => {
  res.json({ 
    message: 'Backend Fábrica Super Odd — OK ✅',
    version: '1.2.0',
    environment: process.env.NODE_ENV || 'development'
  });
});

// ==============================
// 🚀 INICIALIZAÇÃO
// ==============================
(async () => {
  try {
    console.log('🚀 Iniciando servidor...');
    console.log(`🔌 Conectando ao PostgreSQL: ${process.env.DATABASE_URL ? 'URL configurada' : 'URL NÃO CONFIGURADA'}`);
    
    await ensureUsersTable();
    await ensureRecordsTable();
    await ensureNotesTable();

    app.listen(PORT, '0.0.0.0', () => {
      console.log(`✅ Backend rodando na porta ${PORT}`);
      console.log(`🌐 CORS: totalmente liberado`);
      console.log(`🔍 Ambiente: ${process.env.NODE_ENV || 'development'}`);
      console.log(`🔗 URL base: ${process.env.BASE_URL || 'http://localhost:' + PORT}`);
    });
  } catch (err) {
    console.error('❌ Falha crítica ao iniciar o servidor:', err);
    process.exit(1);
  }
})();

// Tratamento de sinais para encerramento gracioso
process.on('SIGTERM', () => {
  console.log('🛑 Recebido SIGTERM. Encerrando...');
  pool.end().then(() => {
    console.log('🔌 Conexões com o banco encerradas');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('🛑 Recebido SIGINT. Encerrando...');
  pool.end().then(() => {
    console.log('🔌 Conexões com o banco encerradas');
    process.exit(0);
  });
});