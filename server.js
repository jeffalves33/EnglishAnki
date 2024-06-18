const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const mysql = require('mysql2');
const jwt = require('jsonwebtoken');
const path = require('path');
const app = express();
const port = 3000;
const secretKey = 'secretkey'; // Use uma chave secreta mais segura em produção

// Configurar o body-parser para parsear requisições JSON
app.use(bodyParser.json());

// Servir arquivos estáticos da pasta 'public'
app.use(express.static(path.join(__dirname, 'public')));

// Configurar o banco de dados MySQL
const db = mysql.createConnection({
  host: 'viaduct.proxy.rlwy.net',
  user: 'root',
  password: 'XhvrFkOLxdiXvXYuHgWKxzaSrohMuJVa',
  port: 51790,
  database: 'railway'
});

db.connect((err) => {
  if (err) {
    return console.error('error connecting: ' + err.stack);
  }
  console.log('Conectado ao banco de dados MySQL.');

  // Criar tabelas se elas não existirem
  const createUsersTable = `CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL
  )`;

  const createWordsTable = `CREATE TABLE IF NOT EXISTS words (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    word VARCHAR(255) NOT NULL,
    translation VARCHAR(255) NOT NULL
  )`;

  db.query(createUsersTable, (err, results) => {
    if (err) throw err;
    console.log('Tabela users pronta.');
  });

  db.query(createWordsTable, (err, results) => {
    if (err) throw err;
    console.log('Tabela words pronta.');
  });
});

// Middleware para verificar o token JWT
const authenticateJWT = (req, res, next) => {
  const token = req.headers.authorization;

  if (token) {
    jwt.verify(token.split(' ')[1], secretKey, (err, user) => {
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
    db.query(query, [username, hash], (err, results) => {
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
  db.query(query, [username], (err, results) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (results.length === 0) {
      return res.status(401).json({ message: 'Credenciais inválidas!' });
    }

    const row = results[0];
    bcrypt.compare(password, row.password, (err, result) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      if (result) {
        // Gerar token JWT
        const token = jwt.sign({ username: row.username }, secretKey, { expiresIn: '1h' });
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
  db.query(query, [username, word, translation], (err, results) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.status(200).json({ message: 'Palavra adicionada com sucesso!' });
  });
});

// Rota para buscar uma palavra aleatória
app.get('/get-word', authenticateJWT, (req, res) => {
  const username = req.user.username;

  const query = `SELECT * FROM words WHERE username = ? ORDER BY RAND() LIMIT 1`;
  db.query(query, [username], (err, results) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (results.length === 0) {
      return res.status(404).json({ message: 'Nenhuma palavra encontrada.' });
    }
    res.status(200).json(results[0]);
  });
});

app.listen(port, () => {
  console.log(`Servidor rodando na porta ${port}`);
});
