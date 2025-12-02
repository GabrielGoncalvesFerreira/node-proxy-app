import { erpUserAuthService } from '../services/erp-user-auth.service.js';
import { sessionService } from '../services/session.service.js';
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
    const login = (body.login || body.username || '').trim();
    const password = body.password || '';
    const grantType = body.grant_type;
    const scope = body.scope;
    const rawClientType = req.headers['x-client-type'] ?? req.headers['x-client-typ'];
    const clientType = getClientTypeFromHeaders(req.headers);
    const clientIp = req.ip;

    if (!login || !password) {
      return reply.code(400).send({
        message: 'Campos login e password são obrigatórios.',
      });
    }

    if (!rawClientType) {
      return reply.code(400).send({
        message: 'Header X-Client-Type é obrigatório para este endpoint.',
      });
    }

    try {
      const forwardedHeaders = pickHeaders(req.headers);
      const result = await erpUserAuthService.authenticateWithCredentials({
        login,
        password,
        scope,
        grantType,
        forwardedHeaders,
      });

      const sessionPayload = {
        token: result.access_token,
        user: result.user,
        scope: result.scope,
        clientType,
        ip: clientIp,
        login,
      };

      const ttl = result.expires_in || 86400;
      const { sessionId } = await sessionService.createSession(sessionPayload, ttl);

      return reply.send({
        token: sessionId,
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
