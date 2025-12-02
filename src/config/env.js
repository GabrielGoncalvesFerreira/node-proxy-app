import dotenv from 'dotenv';
dotenv.config();

const sanitizeUrl = (url) => (url ? url.replace(/\/$/, '') : '');

const API_BASE = sanitizeUrl(process.env.API_BASE);       // Backend Cotação
const SSO_API_URL = sanitizeUrl(process.env.SSO_API_URL); // BFF SSO
const CORS_ORIGINS = (process.env.CORS_ORIGINS || '')
  .split(',')
  .map(o => o.trim())
  .filter(Boolean);

if (!API_BASE) throw new Error('FATAL: API_BASE é obrigatória.');
if (!SSO_API_URL) throw new Error('FATAL: SSO_API_URL é obrigatória.');

if (!process.env.OAUTH_CLIENT_ID || !process.env.OAUTH_CLIENT_SECRET) {
  throw new Error('FATAL: Credenciais OAUTH são obrigatórias.');
}

export const config = {
  app: {
    port: process.env.PORT || 5181,
    isDev: process.env.NODE_ENV === 'development',
  },
  api: {
    baseUrl: API_BASE,
    ssoUrl: SSO_API_URL,
    
    endpoints: {
      erpToken: `${API_BASE}/api/v1/auth/token/erp`, 
      erpTokenUser: `${API_BASE}/api/v1/auth/token/erp/user`, 
      clientToken: `${API_BASE}/api/v1/auth/token`, 
    },
    timeout: 15000,
  },
  security: {
    clientId: process.env.OAUTH_CLIENT_ID,
    clientSecret: process.env.OAUTH_CLIENT_SECRET,
    get basicAuthHeader() {
      const credentials = `${this.clientId}:${this.clientSecret}`;
      return Buffer.from(credentials, 'utf8').toString('base64');
    },
  },
  redis: {
    url: process.env.REDIS_URL,
  },
  session: {
    cookieName: process.env.SESSION_COOKIE_NAME || 'cotacao_session',
    domain: process.env.SESSION_COOKIE_DOMAIN,
    secure: process.env.SESSION_COOKIE_SECURE !== 'false',
    sameSite: 'lax',
    ttlSeconds: Number(process.env.SESSION_TTL_SECONDS) || 86400,
  },
};