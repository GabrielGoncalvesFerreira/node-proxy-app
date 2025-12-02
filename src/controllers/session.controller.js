import { sessionService } from '../services/session.service.js';
import { config } from '../config/env.js';

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function extractBearerSessionId(req) {
  const raw = req.headers?.authorization || req.headers?.Authorization;
  if (!raw || typeof raw !== 'string') return null;
  const [scheme, value] = raw.split(' ');
  if (!scheme || scheme.toLowerCase() !== 'bearer' || !value) return null;
  const trimmed = value.trim();
  return UUID_REGEX.test(trimmed) ? trimmed : null;
}

class SessionController {
  
  /**
   * GET /bff/session
   * Verifica se o bearer é válido e retorna quem está logado.
   */
  async getSessionStatus(req, reply) {
    const bearerSessionId = extractBearerSessionId(req);
    if (!bearerSessionId) {
      return reply.code(401).send({ authenticated: false });
    }

    const session = await sessionService.getSession(bearerSessionId);
    if (!session) {
      return reply.code(401).send({ authenticated: false });
    }

    // Se for sessão pendente (ainda no meio do login MFA), não consideramos autenticado full
    if (session.isPendingMfa) {
        return reply.code(403).send({ 
            authenticated: false, 
            message: 'MFA Pending',
            tempUser: session.tempUser 
        });
    }

    return reply.send({
      authenticated: true,
      user: session.user,
      scope: session.scope,
      clientId: session.clientId,
      clientType: session.clientType
    });
  }

  /**
   * POST /bff/refresh
   * Usa refresh token em cookie httpOnly para emitir novo bearer.
   */
  async refresh(req, reply) {
    const refreshToken = req.cookies?.[config.session.refreshCookieName];
    if (!refreshToken) {
      return reply.code(401).send({ message: 'Refresh token ausente.' });
    }

    const refreshData = await sessionService.getSessionIdByRefresh(refreshToken);
    if (!refreshData?.sessionId) {
      return reply.code(401).send({ message: 'Refresh inválido ou expirado.' });
    }

    // Recupera sessão original
    const session = await sessionService.getSession(refreshData.sessionId);
    if (!session) {
      await sessionService.removeRefreshToken(refreshToken);
      return reply.code(401).send({ message: 'Sessão expirada.' });
    }

    // Validação opcional de IP atrelado ao refresh
    if (session.ip && session.ip !== req.ip) {
      await sessionService.removeRefreshToken(refreshToken);
      return reply.code(401).send({ message: 'Sessão inválida para este IP.' });
    }

    // Invalida sessão anterior e cria nova
    await sessionService.removeSession(refreshData.sessionId);
    const { meta, ...payload } = session;
    const accessTtl = meta?.ttlSeconds || config.session.ttlSeconds;
    const { sessionId, ttl } = await sessionService.createSession(payload, accessTtl);

    // Rotaciona refresh token
    const refreshTtl = config.session.refreshTtlSeconds;
    const { refreshId } = await sessionService.createRefreshToken(sessionId, refreshTtl, { ip: session.ip });
    await sessionService.removeRefreshToken(refreshToken);
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
      token_type: 'Bearer',
      expires_in: ttl,
      user: payload.user,
      scope: payload.scope,
      clientType: payload.clientType
    });
  }

  /**
   * POST /bff/logout
   */
  async logout(req, reply) {
    const bearerSessionId = extractBearerSessionId(req);
    if (bearerSessionId) {
      await sessionService.removeSession(bearerSessionId);
    }

    const refreshToken = req.cookies?.[config.session.refreshCookieName];
    if (refreshToken) {
      await sessionService.removeRefreshToken(refreshToken);
      reply.clearCookie(config.session.refreshCookieName, {
        path: '/',
        domain: config.session.domain
      });
    }

    return reply.send({ authenticated: false });
  }
}

export const sessionController = new SessionController();
