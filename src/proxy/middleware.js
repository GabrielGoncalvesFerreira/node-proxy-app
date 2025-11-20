import { sessionService } from '../services/session.service.js';
import { config } from '../config/env.js';

function getPolicy(path, method) {
  if (path === '/health' || path.startsWith('/api/v1/public/')) {
    return { type: 'passthrough' };
  }

  if (path === '/api/v1/auth/sso/callback') {
    return { type: 'passthrough' }; 
  }

  if (method === 'POST' && path === '/api/v1/auth/token') {
    return { type: 'inject_basic_auth' };
  }

  return { type: 'user_session' };
}

export async function proxyPreHandler(req, reply) {
  // URL já normalizada no server.js
  const currentPath = req.raw.url.split('?')[0]; 
  const policy = getPolicy(currentPath, req.method);

  if (policy.type === 'passthrough') return;

  if (policy.type === 'inject_basic_auth') {
    if (!req.headers.authorization) {
      req.headers.authorization = `Basic ${config.security.basicAuthHeader}`;
    }
    return;
  }

  if (policy.type === 'user_session') {
    const sessionId = req.cookies[config.session.cookieName];
    
    if (!sessionId) {
      return reply.code(401).send({ message: 'Sessão expirada ou não encontrada.' });
    }

    const session = await sessionService.getSession(sessionId);
    if (!session) {
      reply.clearCookie(config.session.cookieName, { path: '/', domain: config.session.domain });
      return reply.code(401).send({ message: 'Sessão inválida.' });
    }

    req.headers.authorization = `Bearer ${session.token}`;
    return;
  }
}