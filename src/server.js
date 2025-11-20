import Fastify from 'fastify';
import cors from '@fastify/cors';
import cookie from '@fastify/cookie';
import formbody from '@fastify/formbody';
import proxy from '@fastify/http-proxy';
import { setGlobalDispatcher, Agent } from 'undici';
import crypto from 'node:crypto';

import { config } from './config/env.js';
import { registerRoutes } from './routes.js';
import { proxyPreHandler } from './proxy/middleware.js';

setGlobalDispatcher(new Agent({
  keepAliveTimeout: 10_000,
  keepAliveMaxTimeout: 60_000
}));

const app = Fastify({ 
  logger: true,
  trustProxy: true 
});

app.addHook('onRequest', async (req, reply) => {
  // Normalização de URL
  let currentUrl = req.raw.url;
  const [rawPath, query] = currentUrl.split('?');
  
  let newPath = rawPath;
  if (!newPath.startsWith('/api')) {
    newPath = newPath.startsWith('/') ? `/api${newPath}` : `/api/${newPath}`;
  }
  newPath = newPath.replace(/^\/api\/api/, '/api');

  const finalUrl = query ? `${newPath}?${query}` : newPath;

  if (currentUrl !== finalUrl) {
    req.raw.url = finalUrl; 
  }

  // Auditoria Básica (IP Real)
  req.headers['x-request-id'] ||= crypto.randomUUID();
  req.headers['x-bff'] = 'true';
  req.headers['x-forwarded-for'] = req.ip;
  req.headers['x-real-ip'] = req.ip;
});

await app.register(formbody);
await app.register(cookie);

await app.register(cors, {
  origin: true, 
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']
});

await registerRoutes(app);

await app.register(proxy, {
  upstream: config.api.baseUrl,
  prefix: '/',
  httpMethods: ['DELETE', 'GET', 'HEAD', 'PATCH', 'POST', 'PUT'],
  preHandler: proxyPreHandler, 
  
  replyOptions: {
    onResponse: (req, reply, res) => {
      if (reply.statusCode >= 400) {
        req.log.warn(`[Proxy Status] ${reply.statusCode} para ${req.url}`);
      }
      reply.send(res);
    }
  }
});

const start = async () => {
  try {
    await app.listen({ 
      host: '0.0.0.0',
      port: Number(config.app.port) 
    });
    console.log(`🚀 BFF Cotação rodando na porta ${config.app.port}`);
    console.log(`👉 Backend Alvo: ${config.api.baseUrl}`);
    console.log(`👉 Validador SSO: ${config.api.ssoUrl}`);
  } catch (err) {
    app.log.error(err);
    process.exit(1);
  }
};

start();