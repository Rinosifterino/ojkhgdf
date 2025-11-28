const express = require('express');
const session = require('express-session');
const { createClient } = require('redis');
const RedisStore = require('connect-redis').default;
const { Client } = require('pg');
const bcrypt = require('bcrypt');
const os = require('os');

// --- Configurações ---
const APP_PORT = 3000;
const HOSTNAME = os.hostname();
const DB_CONFIG = {
    user: process.env.POSTGRES_USER || 'user',
    host: process.env.POSTGRES_HOST || 'db',
    database: process.env.POSTGRES_DB || 'trabalho_db',
    password: process.env.POSTGRES_PASSWORD || 'password',
    port: 5432,
};

// --- Inicialização do Redis (Sessão Centralizada) ---
const redisClient = createClient({
    url: `redis://${process.env.REDIS_HOST || 'redis'}:6379`
});

redisClient.on('error', (err) => console.error('Redis Client Error', err));

async function connectRedis() {
    try {
        await redisClient.connect();
        console.log('Conectado ao Redis com sucesso.');
    } catch (err) {
        console.error('Falha ao conectar ao Redis:', err);
        // Em um ambiente de produção, você pode querer tentar novamente ou sair
    }
}
connectRedis();

const redisStore = new RedisStore({
    client: redisClient,
    prefix: 'myapp:',
});

// --- Inicialização do PostgreSQL (Banco de Dados) ---
const dbClient = new Client(DB_CONFIG);

async function connectDB() {
    try {
        await dbClient.connect();
        console.log('Conectado ao PostgreSQL com sucesso.');
        await setupDB();
    } catch (err) {
        console.error('Falha ao conectar ao PostgreSQL:', err);
    }
}

async function setupDB() {
    // Cria a tabela de usuários se não existir
    await dbClient.query(`
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(50) UNIQUE NOT NULL,
            password_hash VARCHAR(100) NOT NULL,
            full_name VARCHAR(100) NOT NULL
        );
    `);

    // Insere usuários de teste (se não existirem)
    const users = [
        { username: 'aluno1', password: 'senha1', full_name: 'João da Silva' },
        { username: 'aluno2', password: 'senha2', full_name: 'Maria Souza' },
    ];

    for (const user of users) {
        const existingUser = await dbClient.query('SELECT * FROM users WHERE username = $1', [user.username]);
        if (existingUser.rows.length === 0) {
            const saltRounds = 10;
            const password_hash = await bcrypt.hash(user.password, saltRounds);
            await dbClient.query(
                'INSERT INTO users (username, password_hash, full_name) VALUES ($1, $2, $3)',
                [user.username, password_hash, user.full_name]
            );
            console.log(`Usuário ${user.username} inserido.`);
        }
    }
}

connectDB();

// --- Configuração do Express ---
const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Configuração da Sessão
app.use(session({
    store: redisStore,
    secret: 'um-segredo-muito-secreto', // Chave secreta para assinar o cookie de sessão
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 1000 * 60 * 60 * 24, // 1 dia
        httpOnly: true,
        secure: false // Deve ser true em produção com HTTPS
    }
}));

// Middleware para verificar autenticação
function requireLogin(req, res, next) {
    if (req.session.userId) {
        next();
    } else {
        res.status(401).send('Não autorizado. Faça login primeiro.');
    }
}

// --- Rotas ---

// Rota de Login
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ success: false, message: 'Usuário e senha são obrigatórios.' });
    }

    try {
        const result = await dbClient.query('SELECT * FROM users WHERE username = $1', [username]);
        const user = result.rows[0];

        if (user && await bcrypt.compare(password, user.password_hash)) {
            // Autenticação bem-sucedida
            req.session.userId = user.id;
            req.session.username = user.username;
            req.session.fullName = user.full_name;
            req.session.loginTime = new Date().toISOString();
            
            // O ID da sessão é gerado pelo express-session e armazenado no cookie
            const sessionId = req.sessionID; 

            return res.json({
                success: true,
                message: 'Login bem-sucedido',
                redirect: '/meu-perfil',
                sessionId: sessionId
            });
        } else {
            return res.status(401).json({ success: false, message: 'Credenciais inválidas.' });
        }
    } catch (error) {
        console.error('Erro no login:', error);
        return res.status(500).json({ success: false, message: 'Erro interno do servidor.' });
    }
});

// Rota de Perfil Protegida
app.get('/meu-perfil', requireLogin, (req, res) => {
    // Esta rota demonstra que a sessão é mantida e os dados do usuário são acessíveis
    // O hostname é crucial para a avaliação do Round Robin DNS
    res.json({
        success: true,
        message: 'Dados do Perfil',
        serverHostname: HOSTNAME,
        userInfo: {
            username: req.session.username,
            fullName: req.session.fullName,
            loginTime: req.session.loginTime,
            sessionId: req.sessionID // ID da sessão para avaliação
        }
    });
});

// Rota de Logout
app.post('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).json({ success: false, message: 'Erro ao fazer logout.' });
        }
        res.clearCookie('connect.sid'); // Limpa o cookie de sessão
        res.json({ success: true, message: 'Logout bem-sucedido.' });
    });
});

// Rota de Status (para o PONTO EXTRA)
app.get('/status', (req, res) => {
    res.json({
        status: 'ok',
        hostname: HOSTNAME,
        time: new Date().toISOString()
    });
});

// Rota de Health Check (para o PONTO EXTRA)
app.get('/health', (req, res) => {
    // Em um cenário real, você checaria a conexão com o DB e Redis aqui
    res.status(200).send('OK');
});

// Rota padrão para servir o frontend (simulação)
app.get('/', (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html lang="pt-BR">
        <head>
            <meta charset="UTF-8">
            <title>Trabalho de Engenharia - Login</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 50px; }
                .container { max-width: 400px; margin: auto; padding: 20px; border: 1px solid #ccc; border-radius: 5px; }
                input[type="text"], input[type="password"] { width: 100%; padding: 10px; margin: 8px 0; display: inline-block; border: 1px solid #ccc; box-sizing: border-box; }
                button { background-color: #4CAF50; color: white; padding: 14px 20px; margin: 8px 0; border: none; cursor: pointer; width: 100%; }
                button:hover { opacity: 0.8; }
                #message { margin-top: 10px; padding: 10px; border-radius: 5px; }
                #profile-info { margin-top: 20px; border-top: 1px solid #eee; padding-top: 10px; }
            </style>
        </head>
        <body>
            <div class="container">
                <h2>Login</h2>
                <form id="login-form">
                    <label for="username"><b>Usuário</b></label>
                    <input type="text" placeholder="aluno1 ou aluno2" name="username" required>

                    <label for="password"><b>Senha</b></label>
                    <input type="password" placeholder="senha1 ou senha2" name="password" required>

                    <button type="submit">Entrar</button>
                </form>
                <div id="message"></div>
                
                <div id="profile-info" style="display:none;">
                    <h3>Meu Perfil</h3>
                    <p><strong>Servidor Atual:</strong> <span id="server-hostname"></span></p>
                    <p><strong>Usuário:</strong> <span id="user-full-name"></span> (<span id="user-username"></span>)</p>
                    <p><strong>Logado em:</strong> <span id="login-time"></span></p>
                    <p><strong>ID da Sessão:</strong> <span id="session-id"></span></p>
                    <button id="refresh-button">Atualizar Perfil (Testar RR DNS)</button>
                    <button id="logout-button" style="background-color: #f44336;">Sair</button>
                </div>
            </div>

            <script>
                const form = document.getElementById('login-form');
                const messageDiv = document.getElementById('message');
                const profileInfoDiv = document.getElementById('profile-info');
                const refreshButton = document.getElementById('refresh-button');
                const logoutButton = document.getElementById('logout-button');

                // Função para exibir o formulário de login e esconder o perfil
                function showLogin() {
                    form.style.display = 'block';
                    profileInfoDiv.style.display = 'none';
                    messageDiv.textContent = '';
                }

                // Função para exibir as informações do perfil e esconder o login
                function showProfile(data) {
                    form.style.display = 'none';
                    profileInfoDiv.style.display = 'block';
                    document.getElementById('server-hostname').textContent = data.serverHostname;
                    document.getElementById('user-full-name').textContent = data.userInfo.fullName;
                    document.getElementById('user-username').textContent = data.userInfo.username;
                    document.getElementById('login-time').textContent = new Date(data.userInfo.loginTime).toLocaleString();
                    document.getElementById('session-id').textContent = data.userInfo.sessionId;
                    messageDiv.textContent = 'Logado com sucesso!';
                    messageDiv.style.backgroundColor = '#d4edda';
                    messageDiv.style.color = '#155724';
                }

                // Função para buscar os dados do perfil
                async function fetchProfile() {
                    try {
                        const response = await fetch('/meu-perfil');
                        if (response.ok) {
                            const data = await response.json();
                            showProfile(data);
                        } else {
                            // Se não estiver logado, mostra o login
                            showLogin();
                        }
                    } catch (error) {
                        console.error('Erro ao buscar perfil:', error);
                        showLogin();
                    }
                }

                // Tenta buscar o perfil ao carregar a página
                fetchProfile();

                // Listener para o formulário de login
                form.addEventListener('submit', async (e) => {
                    e.preventDefault();
                    const formData = new FormData(form);
                    const data = Object.fromEntries(formData.entries());

                    try {
                        const response = await fetch('/login', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify(data)
                        });

                        const result = await response.json();

                        if (response.ok && result.success) {
                            // Redireciona ou busca o perfil após o login
                            fetchProfile();
                        } else {
                            messageDiv.textContent = result.message || 'Erro desconhecido no login.';
                            messageDiv.style.backgroundColor = '#f8d7da';
                            messageDiv.style.color = '#721c24';
                        }
                    } catch (error) {
                        messageDiv.textContent = 'Erro de conexão com o servidor.';
                        messageDiv.style.backgroundColor = '#f8d7da';
                        messageDiv.style.color = '#721c24';
                        console.error('Erro:', error);
                    }
                });

                // Listener para o botão de atualizar perfil
                refreshButton.addEventListener('click', fetchProfile);

                // Listener para o botão de logout
                logoutButton.addEventListener('click', async () => {
                    try {
                        const response = await fetch('/logout', { method: 'POST' });
                        const result = await response.json();
                        if (response.ok && result.success) {
                            showLogin();
                            messageDiv.textContent = 'Você foi desconectado.';
                            messageDiv.style.backgroundColor = '#fff3cd';
                            messageDiv.style.color = '#856404';
                        } else {
                            messageDiv.textContent = result.message || 'Erro ao fazer logout.';
                            messageDiv.style.backgroundColor = '#f8d7da';
                            messageDiv.style.color = '#721c24';
                        }
                    } catch (error) {
                        messageDiv.textContent = 'Erro de conexão com o servidor.';
                        messageDiv.style.backgroundColor = '#f8d7da';
                        messageDiv.style.color = '#721c24';
                        console.error('Erro:', error);
                    }
                });
            </script>
        </body>
        </html>
    `);
});

app.listen(APP_PORT, () => {
    console.log(`Servidor de Aplicação (${HOSTNAME}) rodando na porta ${APP_PORT}`);
});
