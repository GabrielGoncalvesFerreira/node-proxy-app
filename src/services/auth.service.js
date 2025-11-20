import axios from 'axios';
import { httpClient } from './http.service.js';
import { sessionService } from './session.service.js';
import { config } from '../config/env.js';

class AuthService {
  
  async exchangeTicketWithSSO(ticket, userIp) {
    let ssoData;

    try {
      // 1. Valida no SSO
      const response = await axios.post(`${config.api.ssoUrl}/api/v1/auth/sso/validate`, {
        ticket: ticket,
        client_ip: userIp 
      });
      ssoData = response.data;
    } catch (error) {
      console.error('[AuthService] Recusa do SSO:', error.response?.data?.message || error.message);
      throw new Error('Ticket SSO inválido ou expirado.');
    }

    try {
      // 2. Troca no Laravel Cotação
      const params = new URLSearchParams({
        grant_type: 'sso_exchange', 
        scope: 'cotacao',           
        email: ssoData.user.email,
        sso_token: ssoData.original_token
      });

      const { data: localData } = await httpClient.post(config.api.endpoints.erpToken, params, {
        headers: { 
          'Authorization': `Basic ${config.security.basicAuthHeader}`, 
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      });

      // 3. Cria Sessão Local
      const sessionPayload = {
        token: localData.access_token,
        user: localData.user || ssoData.user,
        scope: localData.scope,
        isPendingMfa: false
      };

      const ttl = localData.expires_in || 86400;
      const { sessionId } = await sessionService.createSession(sessionPayload, ttl);

      return { sessionId, ttl, user: sessionPayload.user };

    } catch (error) {
      console.error('[AuthService] Recusa do Laravel:', error.response?.data || error.message);
      throw new Error('Acesso negado pelo sistema Cotação.');
    }
  }

  async logout(sessionId) {
    return sessionService.removeSession(sessionId);
  }
}

export const authService = new AuthService();