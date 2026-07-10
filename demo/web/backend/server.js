import express from "express";
import cors from "cors";
import path from "path";
import { fileURLToPath } from "url";
import pg from "pg";

const app = express();
const port = process.env.PORT || 3000;

const filename = fileURLToPath(import.meta.url);
const dirname = path.dirname(filename);

const { Pool } = pg;

// DB 1: Clinica
const dbClinica = new Pool({
  user: process.env.DB_USER || "clara",
  password: process.env.DB_PASS || "password",
  host: process.env.DB_HOST || "127.0.0.1",
  database: process.env.DB_NAME || "clinica_db",
  port: process.env.DB_PORT || 8000,
  ssl: { rejectUnauthorized: false },
});

// DB 2: E-commerce
const dbEcommerce = new Pool({
  user: process.env.DB_USER || "clara",
  password: process.env.DB_PASS || "password",
  host: process.env.DB_ECOMMERCE_HOST || "127.0.0.1",
  database: process.env.DB_ECOMMERCE_NAME || "ecommerce_db",
  port: process.env.DB_ECOMMERCE_PORT || 8001,
  ssl: { rejectUnauthorized: false },
});

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(dirname, "../frontend")));

async function initTables() {
  try {
    await dbClinica.query(`
      CREATE TABLE IF NOT EXISTS patients (
        id SERIAL PRIMARY KEY,
        name TEXT,
        cpf TEXT,
        diagnosis VARCHAR(255)
      );
      ALTER TABLE patients ALTER COLUMN name TYPE TEXT;
      ALTER TABLE patients ALTER COLUMN cpf TYPE TEXT;
      COMMENT ON COLUMN patients.cpf IS 'middleware:encrypt, blind_index=true';
      COMMENT ON COLUMN patients.name IS 'middleware:encrypt, blind_index=true';
    `);
    
    await dbEcommerce.query(`
      CREATE TABLE IF NOT EXISTS pedidos (
        id SERIAL PRIMARY KEY,
        produto VARCHAR(255) NOT NULL,
        cartao TEXT NOT NULL,
        valor DECIMAL(10,2) NOT NULL
      );
      ALTER TABLE pedidos ALTER COLUMN cartao TYPE TEXT;
      COMMENT ON COLUMN pedidos.cartao IS 'middleware:encrypt';
    `);
  } catch (err) {
    console.log("Aviso ao inicializar tabelas: " + err.message);
  }
}
setTimeout(initTables, 5000);

app.get("/", (req, res) => {
  res.sendFile(path.join(dirname, "../frontend/index.html"));
});

app.get("/clinica", (req, res) => {
  res.sendFile(path.join(dirname, "../frontend/clinica.html"));
});

app.get("/ecommerce", (req, res) => {
  res.sendFile(path.join(dirname, "../frontend/ecommerce.html"));
});

// ==========================================
// CLÍNICA
// ==========================================
app.post("/cadastrar", async (req, res) => {
  const { name, cpf, diagnosis } = req.body;
  try {
    await dbClinica.query(
      `INSERT INTO patients (name, cpf, diagnosis) VALUES ($1, $2, $3)`,
      [name, cpf, diagnosis]
    );
    res.send(`
      <div style="background: #f0f4f8; min-height: 100vh; padding: 40px; font-family: sans-serif; display: flex; flex-direction: column; align-items: center; justify-content: center;">
        <div style="background: white; padding: 40px; border-radius: 12px; box-shadow: 0 10px 15px rgba(0,0,0,0.1); text-align: center; max-width: 400px;">
          <svg style="width: 64px; height: 64px; color: #3498db; margin: 0 auto 20px;" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
          <h2 style="color: #2c3e50; margin-top: 0;">Paciente Cadastrado!</h2>
          <p style="color: #64748b; margin-bottom: 24px;">O prontuário foi salvo com sucesso no sistema da clínica.</p>
          <a href="/clinica" style="display:inline-block; padding:10px 24px; background:#3498db; color:white; text-decoration:none; border-radius:6px; font-weight: 600; transition: background 0.2s;">Voltar para Clínica</a>
        </div>
      </div>
    `);
  } catch (error) {
    res.status(500).send("Erro: " + error.message);
  }
});

app.get("/buscar", async (req, res) => {
  const nomeBuscado = req.query.cpf;
  try {
    const query = "SELECT * FROM patients WHERE name ILIKE $1";
    const values = [`%${nomeBuscado}%`];
    const result = await dbClinica.query(query, values);
    
    if (result.rows.length) {
      let html = result.rows.map(r => `
        <div style="background: white; border-radius: 8px; padding: 15px; margin-bottom: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); font-family: sans-serif; color: #333;">
          <h3 style="margin-top: 0; color: #005c8a;">Paciente #${r.id}</h3>
          <p><strong>Nome:</strong> ${r.name}</p>
          <p><strong>CPF:</strong> <span style="background:#eee; padding:2px 4px; border-radius:4px; font-family:monospace; font-size:12px; word-break: break-all;">${r.cpf}</span></p>
          <p><strong>Diagnóstico:</strong> ${r.diagnosis}</p>
        </div>
      `).join("");
      res.send(`
        <div style="background: #f0f4f8; min-height: 100vh; padding: 40px; font-family: sans-serif;">
          <h2 style="color: #2c3e50;">${result.rows.length} Paciente(s) encontrado(s)!</h2>
          ${html}
          <a href="/clinica" style="display:inline-block; margin-top:20px; padding:10px 20px; background:#3498db; color:white; text-decoration:none; border-radius:5px;">Voltar para Clínica</a>
        </div>
      `);
    } else {
      res.send(`<p>Nenhum paciente encontrado.</p><a href="/clinica">Voltar</a>`);
    }
  } catch (error) {
    res.status(500).send("Erro na busca: " + error.message);
  }
});

// ==========================================
// E-COMMERCE
// ==========================================
app.post("/cadastrar_pedido", async (req, res) => {
  const { produto, cartao, valor } = req.body;
  try {
    await dbEcommerce.query(
      `INSERT INTO pedidos (produto, cartao, valor) VALUES ($1, $2, $3)`,
      [produto, cartao, valor]
    );
    res.send(`
      <div style="background: #f0fdf4; min-height: 100vh; padding: 40px; font-family: sans-serif; display: flex; flex-direction: column; align-items: center; justify-content: center;">
        <div style="background: white; padding: 40px; border-radius: 12px; box-shadow: 0 10px 15px rgba(0,0,0,0.1); text-align: center; max-width: 400px;">
          <svg style="width: 64px; height: 64px; color: #10b981; margin: 0 auto 20px;" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
          <h2 style="color: #065f46; margin-top: 0;">Venda Concluída!</h2>
          <p style="color: #64748b; margin-bottom: 24px;">O pedido foi registrado no sistema da loja com sucesso.</p>
          <a href="/ecommerce" style="display:inline-block; padding:10px 24px; background:#10b981; color:white; text-decoration:none; border-radius:6px; font-weight: 600; transition: background 0.2s;">Voltar para E-Commerce</a>
        </div>
      </div>
    `);
  } catch (error) {
    res.status(500).send("Erro: " + error.message);
  }
});

app.get("/buscar_pedido", async (req, res) => {
  const produtoBuscado = req.query.produto;
  try {
    const query = "SELECT * FROM pedidos WHERE produto ILIKE $1";
    const values = [`%${produtoBuscado}%`];
    const result = await dbEcommerce.query(query, values);
    
    if (result.rows.length) {
      let html = result.rows.map(r => `
        <div style="background: white; border-radius: 8px; padding: 15px; margin-bottom: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); font-family: sans-serif; color: #333;">
          <h3 style="margin-top: 0; color: #10b981;">Pedido #${r.id}</h3>
          <p><strong>Produto:</strong> ${r.produto}</p>
          <p><strong>Cartão:</strong> <span style="background:#eee; padding:2px 4px; border-radius:4px; font-family:monospace; font-size:12px; word-break: break-all;">${r.cartao}</span></p>
          <p><strong>Valor:</strong> R$ ${r.valor}</p>
        </div>
      `).join("");
      res.send(`
        <div style="background: #f0fdf4; min-height: 100vh; padding: 40px; font-family: sans-serif;">
          <h2 style="color: #065f46;">${result.rows.length} Pedido(s) encontrado(s)!</h2>
          ${html}
          <a href="/ecommerce" style="display:inline-block; margin-top:20px; padding:10px 20px; background:#10b981; color:white; text-decoration:none; border-radius:5px;">Voltar para E-Commerce</a>
        </div>
      `);
    } else {
      res.send(`<p>Nenhum pedido encontrado.</p><a href="/ecommerce">Voltar</a>`);
    }
  } catch (error) {
    res.status(500).send("Erro na busca: " + error.message);
  }
});

app.listen(port, () => {
  console.log(`Servidor rodando na porta ${port}`);
});
