import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { getDatabaseHealth, migrateDatabase, pool, waitForDatabase } from './db.js';

const app = express();
const PORT = process.env.PORT || 4001;
const JWT_SECRET = process.env.JWT_SECRET || 'local-secret';

app.use(helmet());
app.use(cors({ origin: '*' }));
app.use(express.json());
app.use(morgan('combined'));

app.get('/', (_req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head><meta charset="UTF-8"><title>Auth Service</title>
    <style>body{font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}.card{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:2rem 3rem;text-align:center}.badge{display:inline-block;background:#22c55e22;color:#4ade80;border:1px solid #4ade8044;border-radius:20px;padding:4px 16px;font-size:.85rem;margin:.5rem 0 1.5rem}a{color:#818cf8}</style>
    </head>
    <body><div class="card">
      <h1>🔐 Auth Service</h1>
      <div class="badge">● UP</div>
      <p>Port <strong>${PORT}</strong></p>
      <p><a href="/health">/health</a> — Health check (JSON)</p>
    </div></body></html>
  `);
});

app.get('/health', async (_req, res) => {
  try {
    const db = await getDatabaseHealth();
    res.json({
      service: 'auth-service',
      status: 'UP',
      database: db,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(503).json({
      service: 'auth-service',
      status: 'DOWN',
      database: { status: 'DOWN', error: error.message },
      timestamp: new Date().toISOString()
    });
  }
});

app.post('/auth/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ message: 'name, email and password are required' });
    }

    if (password.length < 6) {
      return res.status(400).json({ message: 'password must be at least 6 characters' });
    }

    const normalizedEmail = email.toLowerCase().trim();
    const passwordHash = await bcrypt.hash(password, 10);

    const result = await pool.query(
      `
        INSERT INTO users (name, email, password_hash)
        VALUES ($1, $2, $3)
        RETURNING id, name, email, created_at
      `,
      [name.trim(), normalizedEmail, passwordHash]
    );

    const user = result.rows[0];

    return res.status(201).json({
      message: 'Signup successful',
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        createdAt: user.created_at
      }
    });
  } catch (error) {
    if (error.code === '23505') {
      return res.status(409).json({ message: 'User already exists' });
    }

    console.error('Signup failed:', error);
    return res.status(500).json({ message: 'Signup failed' });
  }
});

app.post('/auth/signin', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: 'email and password are required' });
    }

    const normalizedEmail = email.toLowerCase().trim();

    const result = await pool.query(
      `
        SELECT id, name, email, password_hash
        FROM users
        WHERE email = $1
        LIMIT 1
      `,
      [normalizedEmail]
    );

    const user = result.rows[0];

    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password_hash);

    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { sub: user.id, email: user.email, name: user.name },
      JWT_SECRET,
      { expiresIn: '1h' }
    );

    return res.json({
      message: 'Signin successful',
      token,
      user: { id: user.id, name: user.name, email: user.email }
    });
  } catch (error) {
    console.error('Signin failed:', error);
    return res.status(500).json({ message: 'Signin failed' });
  }
});

function getBearerToken(req) {
  const header = req.headers.authorization || '';
  if (!header.startsWith('Bearer ')) return null;
  return header.slice(7);
}

function requireAuth(req, res, next) {
  try {
    const token = getBearerToken(req);

    if (!token) {
      return res.status(401).json({ message: 'Authorization token is required' });
    }

    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ message: 'Invalid or expired token' });
  }
}

function publicUser(row) {
  return {
    id: row.id,
    name: row.name,
    email: row.email,
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

app.get('/users', requireAuth, async (req, res) => {
  const result = await pool.query(`
    SELECT id, name, email, created_at, updated_at
    FROM users
    ORDER BY created_at DESC
  `);

  res.json({
    users: result.rows.map(publicUser)
  });
});

app.put('/users/:id', requireAuth, async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email) {
      return res.status(400).json({ message: 'name and email are required' });
    }

    let query, params;

    if (password) {
      if (password.length < 6) {
        return res.status(400).json({ message: 'Password must be at least 6 characters' });
      }
      const passwordHash = await bcrypt.hash(password, 10);
      query = `
        UPDATE users
        SET name = $1, email = $2, password_hash = $3
        WHERE id = $4
        RETURNING id, name, email, created_at, updated_at
      `;
      params = [name.trim(), email.toLowerCase().trim(), passwordHash, req.params.id];
    } else {
      query = `
        UPDATE users
        SET name = $1, email = $2
        WHERE id = $3
        RETURNING id, name, email, created_at, updated_at
      `;
      params = [name.trim(), email.toLowerCase().trim(), req.params.id];
    }

    const result = await pool.query(query, params);

    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({
      message: 'User updated successfully',
      user: publicUser(result.rows[0])
    });
  } catch (error) {
    console.error('Update user failed:', error);
    return res.status(500).json({ message: 'Failed to update user' });
  }
});

app.delete('/users/:id', requireAuth, async (req, res) => {
  if (req.params.id === req.user.sub) {
    return res.status(400).json({
      message: 'Logged in user cannot be deleted'
    });
  }

  const result = await pool.query(
    'DELETE FROM users WHERE id = $1 RETURNING id',
    [req.params.id]
  );

  if (result.rowCount === 0) {
    return res.status(404).json({ message: 'User not found' });
  }

  res.json({ message: 'User deleted successfully' });
});

async function startServer() {
  try {
    await waitForDatabase();
    await migrateDatabase();

    app.listen(PORT, () => {
      console.log(`Auth service running on port ${PORT}`);
    });
  } catch (error) {
    console.error('Auth service failed to start:', error);
    process.exit(1);
  }
}

startServer();
