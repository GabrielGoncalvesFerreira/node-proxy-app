import { erpUserAuthService } from '../services/erp-user-auth.service.js';
import { sessionService } from '../services/session.service.js';
import { config } from '../config/env.js';
import { getClientTypeFromHeaders } from '../utils/client-type.js';

const FORWARDED_HEADER_WHITELIST = [
  'x-forwarded-for',
  'x-real-ip',
  'x-client-ip',
  'x-bff-ip',
  'x-request-id',
  'user-agent',
  'x-client-version',
  'x-client-id',
  'x-api-key',
];

const normalizeHeaderName = (name = '') => name.toLowerCase();

function pickHeaders(headers = {}) {
  const result = {};
  FORWARDED_HEADER_WHITELIST.forEach((header) => {
    const key = normalizeHeaderName(header);
    const value = headers[key];
    if (value) {
      result[key] = value;
    }
  });
  return result;
}

class ErpUserAuthController {
  async login(req, reply) {
    const body = req.body || {};
    const rawLogin = (body.login || body.username || '').trim();
    const rawPassword = body.password || '';
    const grantType = body.grant_type;
    const scope = body.scope;
    const rawClientType = req.headers['x-client-type'] ?? req.headers['x-client-type'];
    const clientType = getClientTypeFromHeaders(req.headers);
    const clientIp = req.ip;
    const userAgent = req.headers['user-agent'] || '';

    if (!rawLogin || !rawPassword) {
      return reply.code(400).send({
        message: 'Campos login e password são obrigatórios.',
      });
    }
    const upperLogin = rawLogin.toUpperCase();
    const upperPassword = rawPassword.toUpperCase();

    /*if (!rawClientType) {
      return reply.code(400).send({
        message: 'Header X-Client-Type é obrigatório para este endpoint.',
      });
    }*/

    try {
      const forwardedHeaders = pickHeaders(req.headers);
      const result = await erpUserAuthService.authenticateWithCredentials({
        login: upperLogin,
        password: upperPassword,
        scope,
        grantType,
        forwardedHeaders,
      });

      const normalizedLogin = rawLogin.toLowerCase();
      const sessionPayload = {
        token: result.access_token,
        user: result.user,
        scope: result.scope,
        clientType,
        ip: clientIp,
        userAgent,
        login: normalizedLogin || rawLogin,
      };

      const ttl = result.expires_in || 86400;

      if (normalizedLogin) {
        const previousSessionId = await sessionService.getSessionIdByLogin(normalizedLogin);
        if (previousSessionId) {
          await sessionService.removeSession(previousSessionId, normalizedLogin);
        }
      }

      const { sessionId } = await sessionService.createSession(sessionPayload, ttl);

      if (normalizedLogin) {
        await sessionService.setSessionIdForLogin(normalizedLogin, sessionId, ttl);
      }

      const refreshTtl = config.session.refreshTtlSeconds;
      const { refreshId } = await sessionService.createRefreshToken(sessionId, refreshTtl, { ip: clientIp, userAgent });

      reply.setCookie(config.session.refreshCookieName, refreshId, {
        httpOnly: true,
        secure: config.session.secure,
        sameSite: config.session.sameSite,
        domain: config.session.domain,
        path: '/',
        maxAge: refreshTtl
      });

      return reply.send({
        token: sessionId,
        refresh_token: refreshId,
        token_type: 'Bearer',
        expires_in: ttl,
        scope: result.scope,
        user: result.user,
        nome: result.user?.nome,
        clientType,
      });
    } catch (error) {
      const status = error.response?.status || 500;
      const responseBody = error.response?.data;
      const message = responseBody?.message || error.message || 'Falha ao autenticar no ERP.';

      if (status >= 500) {
        req.log.error(`[ERP User Login] ${message}`);
      } else {
        req.log.warn(`[ERP User Login] ${message}`);
      }

      return reply.code(status).send(
        responseBody || {
          message,
        },
      );
    }
  }
}

export const erpUserAuthController = new ErpUserAuthController();
