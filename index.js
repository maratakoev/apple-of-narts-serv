import express from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';

const app = express();
app.use(express.json());

const users = []; // временное хранилище пользователей
const SECRET_KEY = 'secret123'; // храни в .env

// Регистрация
app.post('/register', async (req, res) => {
  const { username, email, password, confirmPassword } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  users.push({ username, email, password: hashedPassword, confirmPassword });
  res.send('Пользователь зарегистрирован');
});

// Вход
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username);
  if (!user) return res.status(401).send('Неверный логин');

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(401).send('Неверный пароль');

  const token = jwt.sign({ username }, SECRET_KEY, { expiresIn: '1h' });
  res.json({ token });
});

// Middleware проверки токена
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.sendStatus(401);

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    req.user = decoded;
    next();
  } catch {
    res.sendStatus(403);
  }
}

// Пример защищённого маршрута
app.get('/dashboard', authMiddleware, (req, res) => {
  res.send(`Добро пожаловать, ${req.user.username}`);
});

app.listen(3000, () => console.log('Сервер на 3000'));
