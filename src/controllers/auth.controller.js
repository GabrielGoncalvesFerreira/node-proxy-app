import { authService } from '../services/auth.service.js';
import { config } from '../config/env.js';

class AuthController {

  async loginSsoCallback(req, reply) {
    const { ticket, email } = req.body || {};

    if (!ticket) {
      return reply.code(400).send({ message: 'Ticket é obrigatório.' });
    }

    const userIp = req.ip;
    const forwardedHeaders = {};
    ['x-forwarded-for', 'x-real-ip', 'x-client-ip', 'x-bff-ip', 'x-request-id', 'user-agent', 'x-client-version'].forEach((header) => {
      const value = req.headers[header];
      if (value) forwardedHeaders[header] = value;
    });

    try {
      // Passamos opcionalmente o email recebido para o service. Se for fornecido,
      // será usado ao chamar o endpoint ERP; caso contrário, será usado o email
      // retornado pela validação no SSO.
      const result = await authService.exchangeTicketWithSSO(ticket, userIp, email, forwardedHeaders);

      this._setCookie(reply, result.sessionId, result.ttl);

      // Retorna ticket e email (email preferencialmente o que foi usado)
      return reply.send({
        message: 'Login realizado com sucesso',
        ticket,
        email: email || result.user?.email,
        user: result.user
      });

    } catch (error) {
      req.log.warn(`[Login Falha] ${error.message}`);
      return reply.code(401).send({ message: error.message });
    }
  }

  _setCookie(reply, sessionId, ttl) {
    reply.setCookie(config.session.cookieName, sessionId, {
      path: '/',
      httpOnly: true,
      secure: config.session.secure,
      sameSite: config.session.sameSite,
      domain: config.session.domain,
      maxAge: ttl
    });
  }
}

export const authController = new AuthController();
