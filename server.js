const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const session = require('express-session');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Configuração do banco PostgreSQL
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

// Middlewares
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(session({
    secret: process.env.SESSION_SECRET || 'academia-secret-2024',
    resave: false,
    saveUninitialized: false,
    cookie: { 
        maxAge: 24 * 60 * 60 * 1000,
        secure: process.env.NODE_ENV === 'production'
    }
}));

// Criar tabelas
async function inicializarBanco() {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS alunos (
                id SERIAL PRIMARY KEY,
                nome TEXT NOT NULL,
                cpf TEXT NOT NULL,
                email TEXT NOT NULL,
                telefone TEXT NOT NULL,
                data_nascimento TEXT NOT NULL,
                sexo TEXT NOT NULL,
                endereco TEXT,
                plano TEXT NOT NULL,
                data_matricula TEXT NOT NULL,
                objetivo TEXT,
                observacoes TEXT,
                data_cadastro TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS admins (
                id SERIAL PRIMARY KEY,
                usuario TEXT UNIQUE NOT NULL,
                senha TEXT NOT NULL
            )
        `);

        // Criar admin padrão
        const adminExiste = await pool.query('SELECT * FROM admins WHERE usuario = $1', ['admin']);
        if (adminExiste.rows.length === 0) {
            const senhaHash = await bcrypt.hash('admin123', 10);
            await pool.query('INSERT INTO admins (usuario, senha) VALUES ($1, $2)', ['admin', senhaHash]);
            console.log('✅ Admin criado - Usuário: admin | Senha: admin123');
        }

        console.log('✅ Banco de dados inicializado');
    } catch (erro) {
        console.error('❌ Erro ao inicializar banco:', erro);
    }
}

// Middleware de autenticação
function verificarLogin(req, res, next) {
    if (req.session.logado) {
        next();
    } else {
        res.status(401).json({ erro: 'Não autorizado' });
    }
}

// === ROTAS PÚBLICAS ===

app.post('/api/alunos/cadastrar', async (req, res) => {
    try {
        const { nome, cpf, email, telefone, dataNascimento, sexo, endereco, plano, dataMatricula, objetivo, observacoes } = req.body;
        
        await pool.query(
            `INSERT INTO alunos (nome, cpf, email, telefone, data_nascimento, sexo, endereco, plano, data_matricula, objetivo, observacoes)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
            [nome, cpf, email, telefone, dataNascimento, sexo, endereco, plano, dataMatricula, objetivo, observacoes]
        );
        
        res.json({ sucesso: true, mensagem: 'Aluno cadastrado com sucesso!' });
    } catch (erro) {
        console.error('Erro:', erro);
        res.status(500).json({ erro: 'Erro ao cadastrar aluno' });
    }
});

// === ROTAS DE AUTENTICAÇÃO ===

app.post('/api/login', async (req, res) => {
    try {
        const { usuario, senha } = req.body;
        const result = await pool.query('SELECT * FROM admins WHERE usuario = $1', [usuario]);
        
        if (result.rows.length > 0) {
            const admin = result.rows[0];
            const senhaCorreta = await bcrypt.compare(senha, admin.senha);
            
            if (senhaCorreta) {
                req.session.logado = true;
                req.session.usuario = usuario;
                return res.json({ sucesso: true });
            }
        }
        
        res.status(401).json({ erro: 'Usuário ou senha incorretos' });
    } catch (erro) {
        res.status(500).json({ erro: 'Erro no servidor' });
    }
});

app.post('/api/logout', (req, res) => {
    req.session.destroy();
    res.json({ sucesso: true });
});

app.get('/api/verificar-login', (req, res) => {
    res.json({ logado: req.session.logado || false });
});

// === ROTAS ADMINISTRATIVAS ===

app.get('/api/admin/alunos', verificarLogin, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM alunos ORDER BY data_cadastro DESC');
        res.json(result.rows);
    } catch (erro) {
        res.status(500).json({ erro: 'Erro ao buscar alunos' });
    }
});

app.delete('/api/admin/alunos/:id', verificarLogin, async (req, res) => {
    try {
        await pool.query('DELETE FROM alunos WHERE id = $1', [req.params.id]);
        res.json({ sucesso: true });
    } catch (erro) {
        res.status(500).json({ erro: 'Erro ao excluir aluno' });
    }
});

// Inicializar servidor
inicializarBanco().then(() => {
    app.listen(PORT, () => {
        console.log(`
╔════════════════════════════════════════════╗
║   🏋️  SISTEMA ACADEMIA ONLINE!            ║
╚════════════════════════════════════════════╝

🌐 Servidor rodando na porta ${PORT}
👤 Login admin: admin / admin123
        `);
    });
});
