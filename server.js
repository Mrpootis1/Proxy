import 'dotenv/config';
import express from 'express';
import axios from 'axios';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import jwt from 'jsonwebtoken';
import { z } from 'zod';

const app = express();
app.use(express.json({ limit: '100kb' }));
app.use(helmet({ contentSecurityPolicy: false }));
app.disable('x-powered-by');

// CORS: si NO tenés web, dejá vacío (bloquea orígenes de navegador).
const allowedOrigins = [];
app.use(cors({
  origin: (origin, cb) => {
    if (!origin || allowedOrigins.includes(origin)) return cb(null, true);
    return cb(new Error('CORS blocked'), false);
  }
}));

// Rate limit: 60 req/min por IP a /v1
app.use('/v1', rateLimit({ windowMs: 60_000, max: 60 }));

const {
  KEYAUTH_OWNER_ID,
  KEYAUTH_APP_NAME,
  KEYAUTH_SECRET,
  PROXY_JWT_SECRET,
  TOKEN_TTL_SECONDS = 3600,
} = process.env;

if (!KEYAUTH_OWNER_ID || !KEYAUTH_APP_NAME || !KEYAUTH_SECRET || !PROXY_JWT_SECRET) {
  console.error('Faltan variables de entorno KEYAUTH_* o PROXY_JWT_SECRET');
  process.exit(1);
}

// ⚠️ Cambiá si tu KeyAuth usa otra base/rutas
const KEYAUTH_BASE = 'https://keyauth.win/api/1.2/';

async function callKeyAuth(path, payload) {
  const body = {
    ownerid: KEYAUTH_OWNER_ID,
    appname: KEYAUTH_APP_NAME,
    secret: KEYAUTH_SECRET,
    ...payload,
  };
  const { data } = await axios.post(KEYAUTH_BASE + path, body, {
    timeout: 10000,
    headers: { 'Content-Type': 'application/json' },
  });
  return data;
}

const LoginSchema = z.object({
  license: z.string().min(4).max(128),
  hwid: z.string().min(2).max(128),
});

const ValidateSchema = z.object({
  token: z.string().min(10),
});

function issueProxyToken(session) {
  return jwt.sign(
    {
      sub: session.user_id,
      plan: session.plan ?? 'free',
      exp: Math.floor(Date.now() / 1000) + Number(TOKEN_TTL_SECONDS),
    },
    PROXY_JWT_SECRET
  );
}

function authProxy(req, res, next) {
  const hdr = req.headers.authorization || '';
  const token = hdr.startsWith('Bearer ') ? hdr.slice(7) : null;
  if (!token) return res.status(401).json({ ok: false, msg: 'missing token' });
  try {
    req.user = jwt.verify(token, PROXY_JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ ok: false, msg: 'invalid token' });
  }
}

// Home de prueba
app.get('/', (_req, res) => res.json({ ok: true, msg: 'Proxy funcionando!' }));

// Login por license+hwid → Proxy llama a KeyAuth y emite token del proxy
app.post('/v1/login', async (req, res) => {
  const parsed = LoginSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ ok: false, msg: 'invalid input' });

  const { license, hwid } = parsed.data;

  try {
    // ⚠️ Cambiá 'license/activate' si tu KeyAuth usa otra ruta
    const ka = await callKeyAuth('license/activate', { license, hwid });

    if (!ka || ka.success !== true) {
      return res.status(401).json({ ok: false, msg: ka?.message || 'auth failed' });
    }

    const session = {
      user_id: ka.user_id || ka.username || 'unknown',
      plan: ka.subscription || ka.sub || 'free',
      expires_at: ka.expires || null,
    };

    const token = issueProxyToken(session);
    return res.json({ ok: true, token, session });
  } catch (e) {
    return res.status(502).json({ ok: false, msg: 'upstream error' });
  }
});

// Validar token del proxy
app.post('/v1/validate', (req, res) => {
  const parsed = ValidateSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ ok: false, msg: 'invalid input' });
  try {
    const decoded = jwt.verify(parsed.data.token, PROXY_JWT_SECRET);
    return res.json({ ok: true, user: decoded });
  } catch {
    return res.status(401).json({ ok: false, msg: 'invalid or expired' });
  }
});

// Ruta protegida de ejemplo
app.post('/v1/heartbeat', authProxy, async (_req, res) => {
  return res.json({ ok: true, serverTime: Date.now() });
});

// Render te pasa PORT por variable de entorno
const port = process.env.PORT || 8080;
app.listen(port, () => console.log('Proxy listening on :' + port));
