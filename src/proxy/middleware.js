import { sessionService } from '../services/session.service.js';
import { config } from '../config/env.js';

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function getBearerToken(headers = {}) {
  const raw = headers.authorization || headers.Authorization;
  if (!raw || typeof raw !== 'string') return null;
  const [scheme, value] = raw.split(' ');
  if (!scheme || scheme.toLowerCase() !== 'bearer') return null;
  return value ? value.trim() : null;
}

function extractSessionIdFromHeader(headers = {}) {
  const bearer = getBearerToken(headers);
  if (!bearer) return null;
  return UUID_REGEX.test(bearer) ? bearer : null;
}

function getPolicy(path, method) {
  if (path === '/health' || path.startsWith('/api/v1/public/')) {
    return { type: 'passthrough' };
  }

  if (path === '/api/v1/auth/sso/callback') {
    return { type: 'passthrough' };
  }

  // Inject Basic auth only for ERP token endpoint. Keep the regular
  // client token flow (/api/v1/auth/token) untouched so SSO validation
  // or other BFF-handled flows are not forced to use Basic auth.
  if (method === 'POST' && path === '/api/v1/auth/token/erp') {
    return { type: 'inject_basic_auth' };
  }

  return { type: 'user_session' };
}

export async function proxyPreHandler(req, reply) {
  // URL já normalizada no server.js
  const currentPath = req.raw.url.split('?')[0];



  const getHeaderValue = (headers, name) => headers[name.toLowerCase()];
  const setHeaderValue = (headers, name, value) => { headers[name.toLowerCase()] = value; };

  const clientIp = req.ip;
  const bffIp = req.socket?.localAddress || req.ip;

  setHeaderValue(req.headers, 'x-client-ip', clientIp);
  setHeaderValue(req.headers, 'x-bff-ip', bffIp);


  req.log.debug({ path: currentPath, clientIp }, 'Proxy pre-handler IP normalization');

  // Garante User-Agent mínimo
  if (!getHeaderValue(req.headers, 'user-agent')) {
    setHeaderValue(req.headers, 'user-agent', 'Unknown-Client/1.0');
  }

  // Preenche X-Client-Version com User-Agent apenas se estiver ausente
  if (!getHeaderValue(req.headers, 'x-client-version')) {
    const ua = getHeaderValue(req.headers, 'user-agent');
    if (ua) setHeaderValue(req.headers, 'x-client-version', ua);
  }

  const policy = getPolicy(currentPath, req.method);

  if (policy.type === 'passthrough') return;

  if (policy.type === 'inject_basic_auth') {
    if (!req.headers.authorization) {
      req.headers.authorization = `Basic ${config.security.basicAuthHeader}`;
    }
    return;
  }

  if (policy.type === 'user_session') {
    const bearerSessionId = extractSessionIdFromHeader(req.headers);
    if (!bearerSessionId) {
      return reply.code(401).send({ message: 'Bearer obrigatório.' });
    }

    const session = await sessionService.getSession(bearerSessionId);
    if (!session) {
      return reply.code(401).send({ message: 'Sessão inválida ou expirada.' });
    }
    if (session.ip && session.ip !== req.ip) {
      return reply.code(401).send({ message: 'Sessão inválida para este IP.' });
    }

    req.headers.authorization = `Bearer ${session.token}`;
    return;
  }
}
