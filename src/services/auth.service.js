import axios from 'axios';
import fs from 'node:fs';
import https from 'node:https';
import { httpClient } from './http.service.js';
import { sessionService } from './session.service.js';
import { config } from '../config/env.js';

class AuthService {
  
  async exchangeTicketWithSSO(ticket, userIp, overrideEmail, forwardedHeaders = {}) {
    let ssoData;

    try {
      // 1. Valida no SSO
      // Suporta CA customizada via env `SSO_CA_PATH` (apontando para ca.pem)
      // se presente a CA será usada; caso contrário, em desenvolvimento
      // faremos fallback para aceitar certificados não validados.
      const axiosOptions = {};
      const caPath = process.env.SSO_CA_PATH;
      if (caPath && fs.existsSync(caPath)) {
        const ca = fs.readFileSync(caPath);
        axiosOptions.httpsAgent = new https.Agent({ ca });
      } else if (config.app.isDev) {
        // ambiente de desenvolvimento: permitir certificados autoassinados
        axiosOptions.httpsAgent = new https.Agent({ rejectUnauthorized: false });
        console.warn('[AuthService] Ambiente dev: desabilitando verificação TLS para SSO (rejectUnauthorized: false)');
      }

      const response = await axios.post(`${config.api.ssoUrl}/api/v1/auth/sso/validate`, {
        ticket: ticket,
        client_ip: userIp
      }, axiosOptions);
      ssoData = response.data;
    } catch (error) {
      console.error('[AuthService] Recusa do SSO:', error.response?.data?.message || error.message);
      throw new Error('Ticket SSO inválido ou expirado.');
    }

    try {
      // 2. Troca no Laravel Cotação
      // Se o caller forneceu um email (overrideEmail), use-o. Caso contrário,
      // use o email retornado pela validação SSO.
      const emailToUse = overrideEmail || ssoData.user?.email;
      const normalizedEmail = emailToUse?.trim().toLowerCase();

      const params = new URLSearchParams({
        grant_type: 'sso_exchange',
        scope: 'cotacao',
        email: emailToUse,
      });

      const ipHeaders = {};
      ['x-forwarded-for', 'x-real-ip', 'x-client-ip', 'x-bff-ip', 'x-request-id', 'user-agent', 'x-client-version'].forEach((header) => {
        const value = forwardedHeaders[header];
        if (value) ipHeaders[header] = value;
      });

      const userAgent = forwardedHeaders['user-agent'];

      const { data: localData } = await httpClient.post(config.api.endpoints.erpToken, params, {
        headers: {
          'Authorization': `Basic ${config.security.basicAuthHeader}`,
          'Content-Type': 'application/x-www-form-urlencoded',
          ...ipHeaders
        }
      });

      // 3. Cria Sessão Local
      if (normalizedEmail) {
        const previousSessionId = await sessionService.getSessionIdByLogin(normalizedEmail);
        if (previousSessionId) {
          await sessionService.removeSession(previousSessionId, normalizedEmail);
        }
      }

      const sessionPayload = {
        token: localData.access_token,
        user: localData.user || ssoData.user,
        scope: localData.scope,
        isPendingMfa: false, 
        ip: userIp,
        userAgent,
        login: normalizedEmail || emailToUse,
      };

      const ttl = localData.expires_in;
      const { sessionId } = await sessionService.createSession(sessionPayload, ttl);
      if (normalizedEmail) {
        await sessionService.setSessionIdForLogin(normalizedEmail, sessionId, ttl);
      }

      return { sessionId, ttl, user: sessionPayload.user, login: normalizedEmail || emailToUse };

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
