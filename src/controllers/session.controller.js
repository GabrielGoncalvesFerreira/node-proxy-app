import { sessionService } from '../services/session.service.js';

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
   * POST /bff/logout
   */
  async logout(req, reply) {
    const bearerSessionId = extractBearerSessionId(req);
    if (bearerSessionId) {
      await sessionService.removeSession(bearerSessionId);
    }
    return reply.send({ authenticated: false });
  }
}

export const sessionController = new SessionController();
