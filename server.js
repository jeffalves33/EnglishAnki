const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const path = require('path');
const app = express();  // Certifique-se de que o app está definido aqui
const port = 3000;
const secretKey = 'secretkey'; // Use uma chave secreta mais segura em produção

// Configurar o body-parser para parsear requisições JSON
app.use(bodyParser.json());

// Servir arquivos estáticos da pasta 'public'
app.use(express.static(path.join(__dirname, 'public')));

// Configurar o banco de dados SQLite
let db = new sqlite3.Database(':memory:', (err) => {
  if (err) {
    return console.error(err.message);
  }
  console.log('Conectado ao banco de dados SQLite em memória.');
});

// Criar tabela de usuários
db.run(`CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  password TEXT NOT NULL
)`);

// Criar tabela de palavras
db.run(`CREATE TABLE words (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL,
  word TEXT NOT NULL,
  translation TEXT NOT NULL
)`);


// Middleware para verificar o token JWT
const authenticateJWT = (req, res, next) => {
  const token = req.headers.authorization;
  console.log('Token recebido pelo servidor:', token);  // Log para verificar se o token está sendo recebido pelo servidor

  if (token) {
    jwt.verify(token.split(' ')[1], secretKey, (err, user) => {  // Split para remover o "Bearer "
      if (err) {
        return res.sendStatus(403);
      }
      req.user = user;
      next();
    });
  } else {
    res.sendStatus(401);
  }
};

// Rota para registro de usuário
app.post('/register', (req, res) => {
  const { username, password } = req.body;
  const saltRounds = 10;

  bcrypt.hash(password, saltRounds, (err, hash) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }

    const query = `INSERT INTO users (username, password) VALUES (?, ?)`;
    db.run(query, [username, hash], function(err) {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.status(201).json({ message: 'Usuário registrado com sucesso!' });
    });
  });
});

// Rota para login de usuário
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  const query = `SELECT * FROM users WHERE username = ?`;
  db.get(query, [username], (err, row) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (!row) {
      return res.status(401).json({ message: 'Credenciais inválidas!' });
    }

    bcrypt.compare(password, row.password, (err, result) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      if (result) {
        // Gerar token JWT
        const token = jwt.sign({ username: row.username }, secretKey, { expiresIn: '1h' });
        console.log('Token gerado:', token);  // Log para verificar se o token está sendo gerado
        res.status(200).json({ message: 'Login bem-sucedido!', token });
      } else {
        res.status(401).json({ message: 'Credenciais inválidas!' });
      }
    });
  });
});

// Rota protegida
app.get('/protected', authenticateJWT, (req, res) => {
  res.status(200).json({ message: 'Você está visualizando uma página protegida!', user: req.user });
});

// Rota para adicionar uma nova palavra
app.post('/add-word', authenticateJWT, (req, res) => {
  const { word, translation } = req.body;
  const username = req.user.username;

  const query = `INSERT INTO words (username, word, translation) VALUES (?, ?, ?)`;
  db.run(query, [username, word, translation], function(err) {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.status(200).json({ message: 'Palavra adicionada com sucesso!' });
  });
});

// Rota para buscar uma palavra aleatória
app.get('/get-word', authenticateJWT, (req, res) => {
  const username = req.user.username;

  const query = `SELECT * FROM words WHERE username = ? ORDER BY RANDOM() LIMIT 1`;
  db.get(query, [username], (err, row) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (!row) {
      return res.status(404).json({ message: 'Nenhuma palavra encontrada.' });
    }
    res.status(200).json(row);
  });
});

app.listen(port, () => {
  console.log(`Servidor rodando na porta ${port}`);
});
