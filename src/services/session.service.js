import crypto from 'node:crypto';
import redisClient from '../infra/redis-client.js';
import { config } from '../config/env.js';

const LOGIN_INDEX_PREFIX = 'sessao_login:';
const loginKey = login => `${LOGIN_INDEX_PREFIX}${login}`;
const refreshSessionKey = sessionId => `refresh_by_session:${sessionId}`;


class SessionService {

  /**
   * Gera um ID de sessão e salva os dados no Redis.
   * @param {Object} payload - Dados do usuário/token para salvar.
   * @param {number} ttlSeconds - Tempo de vida em segundos.
   * @returns {Promise<{sessionId: string, ttl: number}>}
   */
  async createSession(payload, ttlSeconds) {
    const sessionId = crypto.randomUUID();
    const key = this._getKey(sessionId);
    const ttl = ttlSeconds || config.session.ttlSeconds;
    const now = Date.now();
    const expiresAt = now + ttl * 1000;

    const toStore = {
      ...payload,          // inclua aqui um campo ip vindo do caller
      meta: {
        createdAt: now,
        expiresAt,
        ttlSeconds: ttl,
      }
    };

    await redisClient.set(key, JSON.stringify(toStore), { EX: ttl });
    return { sessionId, ttl, expiresAt };
  }

  /**
   * Recupera os dados da sessão pelo ID.
   */
  async getSession(sessionId) {
    if (!sessionId) return null;
    const data = await redisClient.get(this._getKey(sessionId));
    if (!data) return null;
    const parsed = JSON.parse(data);
    if (parsed.meta?.expiresAt && Date.now() > parsed.meta.expiresAt) {
      await this.removeSession(sessionId, parsed.login);
      return null;
    }
    return parsed;
  }


  /**
   * Atualiza dados de uma sessão existente mantendo o ID (útil para MFA).
   */
  async updateSession(sessionId, newPayload, ttlSeconds) {
    const key = this._getKey(sessionId);
    const ttl = ttlSeconds || config.session.ttlSeconds;

    await redisClient.set(key, JSON.stringify(newPayload), {
      EX: ttl // Reseta o TTL ou mantém o original se calcularmos a diferença (aqui reseta)
    });
  }

  /**
   * Remove a sessão (Logout).
   */
  async removeSession(sessionId, login) {
    if (!sessionId) return;
    if (!login) {
      const snapshot = await redisClient.get(this._getKey(sessionId));
      if (snapshot) {
        try {
          const parsed = JSON.parse(snapshot);
          login = parsed?.login;
        } catch {
          login = undefined;
        }
      }
    }
    const key = this._getKey(sessionId);
    await redisClient.del(key);
    await this.removeRefreshBySession(sessionId);
    if (login) await this.removeSessionIndex(login);
  }

  /**
   * Cria refresh token vinculado a uma sessão.
   */
  async createRefreshToken(sessionId, ttlSeconds, meta = {}) {
    const refreshId = crypto.randomUUID();
    const key = `refresh:${refreshId}`;
    const ttl = ttlSeconds || config.session.refreshTtlSeconds;
    const toStore = { sessionId, ...meta };
    await redisClient.set(key, JSON.stringify(toStore), { EX: ttl });
    await this.setRefreshForSession(sessionId, refreshId, ttl);
    return { refreshId, ttl };
  }

  async getSessionIdByRefresh(refreshId) {
    if (!refreshId) return null;
    const data = await redisClient.get(`refresh:${refreshId}`);
    return data ? JSON.parse(data) : null;
  }

  async removeRefreshToken(refreshId) {
    if (!refreshId) return;
    await redisClient.del(`refresh:${refreshId}`);
  }

  // Helper privado para padronizar a chave no Redis
  _getKey(id) {
    return `sessao:${id}`; // Mantive o prefixo 'sessao:' do seu código original
  }

  async getSessionIdByLogin(login) {
    if (!login) return null;
    return redisClient.get(loginKey(login));
  }

  async setSessionIdForLogin(login, sessionId, ttlSeconds) {
    if (!login || !sessionId) return;
    const ttl = ttlSeconds || config.session.ttlSeconds;
    await redisClient.set(loginKey(login), sessionId, { EX: ttl });
  }

  async removeSessionIndex(login) {
    if (!login) return;
    await redisClient.del(loginKey(login));
  }

  async setRefreshForSession(sessionId, refreshId, ttlSeconds) {
    if (!sessionId || !refreshId) return;
    const ttl = ttlSeconds || config.session.refreshTtlSeconds;
    await redisClient.set(refreshSessionKey(sessionId), refreshId, { EX: ttl });
  }

  async getRefreshBySession(sessionId) {
    if (!sessionId) return null;
    return redisClient.get(refreshSessionKey(sessionId));
  }

  async removeRefreshBySession(sessionId) {
    if (!sessionId) return;
    await redisClient.del(refreshSessionKey(sessionId));
  }

}

export const sessionService = new SessionService();
