import express from "express";
import cors from "cors";
import pkg from "pg";

const { Pool } = pkg;

const app = express();
const PORT = process.env.PORT || 10000;

// === Conexão com PostgreSQL ===
const pool = new Pool({
  connectionString: process.env.DATABASE_URL, // variável de ambiente do Render
  ssl: process.env.RENDER ? { rejectUnauthorized: false } : false
});

// === Middlewares ===
app.use(express.json());
app.use(cors());
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS");
  res.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
  next();
});

// === Rotas básicas ===
app.get("/health", (req, res) => {
  res.json({ status: "ok", uptime: process.uptime() });
});

// === Buscar todos os usuários ===
app.get("/api/users", async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM users ORDER BY id ASC");
    res.json(result.rows);
  } catch (error) {
    console.error("Erro ao buscar usuários:", error);
    res.status(500).json({ error: "Erro ao buscar usuários" });
  }
});

// === Criar novo usuário ===
app.post("/api/users", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: "Email é obrigatório" });

    const result = await pool.query(
      "INSERT INTO users (email, enabled) VALUES ($1, NULL) RETURNING *",
      [email]
    );
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error("Erro ao criar usuário:", error);
    res.status(500).json({ error: "Erro ao criar usuário" });
  }
});

// === Liberar usuário ===
app.patch("/api/users/liberar/:email", async (req, res) => {
  try {
    const { email } = req.params;
    const result = await pool.query(
      "UPDATE users SET enabled = TRUE WHERE email = $1 RETURNING *",
      [email]
    );
    if (result.rowCount === 0) return res.status(404).json({ error: "Usuário não encontrado" });
    res.json(result.rows[0]);
  } catch (error) {
    console.error("Erro ao liberar usuário:", error);
    res.status(500).json({ error: "Erro ao liberar usuário" });
  }
});

// === Bloquear usuário ===
app.patch("/api/users/bloquear/:email", async (req, res) => {
  try {
    const { email } = req.params;
    const result = await pool.query(
      "UPDATE users SET enabled = FALSE WHERE email = $1 RETURNING *",
      [email]
    );
    if (result.rowCount === 0) return res.status(404).json({ error: "Usuário não encontrado" });
    res.json(result.rows[0]);
  } catch (error) {
    console.error("Erro ao bloquear usuário:", error);
    res.status(500).json({ error: "Erro ao bloquear usuário" });
  }
});

// === Excluir usuário ===
app.delete("/api/users/:email", async (req, res) => {
  try {
    const { email } = req.params;
    const result = await pool.query("DELETE FROM users WHERE email = $1 RETURNING *", [email]);
    if (result.rowCount === 0) return res.status(404).json({ error: "Usuário não encontrado" });
    res.json({ success: true });
  } catch (error) {
    console.error("Erro ao excluir usuário:", error);
    res.status(500).json({ error: "Erro ao excluir usuário" });
  }
});

// === Inicialização ===
app.listen(PORT, () => {
  console.log(`🚀 Servidor rodando na porta ${PORT}`);
});
