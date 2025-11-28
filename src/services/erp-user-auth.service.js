import { httpClient } from './http.service.js';
import { config } from '../config/env.js';

const DEFAULT_SCOPE = 'default';

class ErpUserAuthService {
  /**
   * Executa o fluxo password grant diretamente no ERP retornando o access_token.
   */
  async authenticateWithCredentials({ login, password, scope, grantType, forwardedHeaders = {} }) {
    const params = new URLSearchParams({
      grant_type: grantType || 'password',
      scope: scope || DEFAULT_SCOPE,
      login,
      username: login,
      password,
    });

    const { data } = await httpClient.post(config.api.endpoints.erpTokenUser, params, {
      headers: {
        Authorization: `Basic ${config.security.basicAuthHeader}`,
        ...forwardedHeaders,
      },
    });

    return data;
  }
}

export const erpUserAuthService = new ErpUserAuthService();
