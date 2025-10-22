import express from "express";
import cors from "cors";
import mongoose from "mongoose";

const app = express();
const PORT = process.env.PORT || 10000;

// ===== Middleware =====
app.use(express.json());

// === CORS TOTALMENTE LIBERADO ===
app.use(cors()); // permite qualquer origem
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*"); // permite qualquer site
  res.header("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS");
  res.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
  next();
});

// ===== Conexão com MongoDB =====
const MONGO_URI = process.env.MONGO_URI || "mongodb+srv://<USUARIO>:<SENHA>@<CLUSTER>/fabricasuperodds?retryWrites=true&w=majority";

mongoose.connect(MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log("✅ Conectado ao MongoDB"))
.catch(err => console.error("❌ Erro ao conectar ao MongoDB:", err));

// ===== Modelo =====
const userSchema = new mongoose.Schema({
  email: String,
  enabled: { type: Boolean, default: null }
});

const User = mongoose.model("User", userSchema);

// ===== Rotas =====

// health check
app.get("/health", (req, res) => {
  res.json({ status: "ok", uptime: process.uptime() });
});

// obter todos os usuários
app.get("/api/users", async (req, res) => {
  try {
    const users = await User.find();
    res.json(users);
  } catch (err) {
    console.error("Erro ao buscar usuários:", err);
    res.status(500).json({ error: "Erro ao buscar usuários" });
  }
});

// criar usuário
app.post("/api/users", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: "Email é obrigatório" });
    const user = new User({ email });
    await user.save();
    res.status(201).json(user);
  } catch (err) {
    console.error("Erro ao criar usuário:", err);
    res.status(500).json({ error: "Erro ao criar usuário" });
  }
});

// atualizar status de usuário (liberar/bloquear)
app.patch("/api/users/:email", async (req, res) => {
  try {
    const { email } = req.params;
    const { enabled } = req.body;
    const user = await User.findOneAndUpdate(
      { email },
      { enabled },
      { new: true }
    );
    if (!user) return res.status(404).json({ error: "Usuário não encontrado" });
    res.json(user);
  } catch (err) {
    console.error("Erro ao atualizar usuário:", err);
    res.status(500).json({ error: "Erro ao atualizar usuário" });
  }
});

// deletar usuário
app.delete("/api/users/:email", async (req, res) => {
  try {
    const { email } = req.params;
    const deleted = await User.findOneAndDelete({ email });
    if (!deleted) return res.status(404).json({ error: "Usuário não encontrado" });
    res.json({ success: true });
  } catch (err) {
    console.error("Erro ao deletar usuário:", err);
    res.status(500).json({ error: "Erro ao deletar usuário" });
  }
});

// ===== Inicialização =====
app.listen(PORT, () => {
  console.log(`🚀 Servidor rodando na porta ${PORT}`);
});
