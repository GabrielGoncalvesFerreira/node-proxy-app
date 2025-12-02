import crypto from 'node:crypto';
import redisClient from '../infra/redis-client.js';
import { config } from '../config/env.js';

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
      await this.removeSession(sessionId);
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
  async removeSession(sessionId) {
    if (!sessionId) return;
    const key = this._getKey(sessionId);
    await redisClient.del(key);
  }

  // Helper privado para padronizar a chave no Redis
  _getKey(id) {
    return `sessao:${id}`; // Mantive o prefixo 'sessao:' do seu código original
  }
}

export const sessionService = new SessionService();