import { authService } from '../services/auth.service.js';
import { config } from '../config/env.js';

class AuthController {

  async loginSsoCallback(req, reply) {
    const { ticket } = req.body || {};

    if (!ticket) {
      return reply.code(400).send({ message: 'Ticket é obrigatório.' });
    }

    const userIp = req.ip; 

    try {
      const result = await authService.exchangeTicketWithSSO(ticket, userIp);
      
      this._setCookie(reply, result.sessionId, result.ttl);
      
      return reply.send({ 
        message: 'Login realizado com sucesso', 
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