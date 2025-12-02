import Fastify from 'fastify';
import cors from '@fastify/cors';
import formbody from '@fastify/formbody';
import proxy from '@fastify/http-proxy';
import { setGlobalDispatcher, Agent } from 'undici';
import crypto from 'node:crypto';

import { config } from './config/env.js';
import { registerRoutes } from './routes.js';
import { proxyPreHandler } from './proxy/middleware.js';

const CORS_ORIGINS = (process.env.CORS_ORIGINS || '')
  .split(',')
  .map(o => o.trim())
  .filter(Boolean);

setGlobalDispatcher(new Agent({
  keepAliveTimeout: 10_000,
  keepAliveMaxTimeout: 60_000
}));

const app = Fastify({
  logger: true,
  trustProxy: ['127.0.0.1', '::1', '172.27.0.0/24'],
});

// CORS configurável por env (registra uma vez para todas as rotas/proxy)
await app.register(cors, {
  origin: CORS_ORIGINS.length ? CORS_ORIGINS : false, // false bloqueia tudo
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
});

app.addHook('onRequest', async (req, reply) => {
  // Helper simples para acessar/definir headers (Node lower-cases header names)
  const getHeaderValue = (headers, name) => headers[name.toLowerCase()];
  const setHeaderValue = (headers, name, value) => { headers[name.toLowerCase()] = value; };

  const clientIp = req.ip; // em vez de req.ips?.[0] || req.ip
  setHeaderValue(req.headers, 'x-client-ip', clientIp);


  // Garante User-Agent mínimo
  if (!getHeaderValue(req.headers, 'user-agent')) {
    setHeaderValue(req.headers, 'user-agent', 'Unknown-Client/1.0');
  }

  // Preenche X-Client-Version com User-Agent apenas se estiver ausente
  if (!getHeaderValue(req.headers, 'x-client-version')) {
    const ua = getHeaderValue(req.headers, 'user-agent');
    if (ua) setHeaderValue(req.headers, 'x-client-version', ua);
  }
});

await app.register(formbody);

await app.register(registerRoutes, { prefix: '/auth' });

await app.register(proxy, {
  upstream: config.api.baseUrl,
  prefix: '/auth',            // só intercepta caminhos que começam com /auth
  rewritePrefix: '/',
  httpMethods: ['DELETE', 'GET', 'HEAD', 'PATCH', 'POST', 'PUT'],
  preHandler: proxyPreHandler,

  replyOptions: {
    onResponse: (req, reply, res) => {
      if (reply.statusCode >= 400) {
        req.log.warn(`[Proxy Status] ${reply.statusCode} para ${req.url}`);
      }

      // Após validação bem-sucedida do endpoint de token do cliente,
      // disparamos uma chamada ao endpoint ERP que exige Basic auth
      try {
        const path = req.raw.url.split('?')[0];
        if (req.method === 'POST' && path === '/api/v1/auth/token' && reply.statusCode < 400) {
          const contentType = req.headers['content-type'] || 'application/json';
          let bodyToSend;
          if (contentType.includes('application/x-www-form-urlencoded')) {
            bodyToSend = new URLSearchParams(req.body).toString();
          } else {
            bodyToSend = JSON.stringify(req.body || {});
          }

          (async () => {
            try {
              const fetchRes = await fetch(config.api.endpoints.erpToken, {
                method: 'POST',
                headers: {
                  authorization: `Basic ${config.security.basicAuthHeader}`,
                  'content-type': contentType
                },
                body: bodyToSend
              });

              if (!fetchRes.ok) {
                req.log.warn(`[ERP Token] falha ${fetchRes.status} ao chamar ${config.api.endpoints.erpToken}`);
              } else {
                req.log.info(`[ERP Token] chamado com sucesso ${fetchRes.status}`);
              }
            } catch (err) {
              req.log.error(`[ERP Token] erro ao chamar endpoint: ${err?.message || err}`);
            }
          })();
        }
      } catch (err) {
        req.log.error(`[Proxy onResponse] erro: ${err?.message || err}`);
      }

      reply.send(res.stream);
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
