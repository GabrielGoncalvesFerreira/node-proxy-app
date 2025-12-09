# Migração: do `access_token` local → sessão em memória + refresh cookie

O BFF agora protege o token ERP no Redis. O cliente recebe apenas um **ID de sessão (UUID)** e um **refresh token** em cookie HTTP-only. O header `Authorization` enviado pelo front contém o id de sessão; o BFF troca por `Bearer <token ERP>` antes de chamar o backend. Nada precisa ser salvo em `localStorage/AsyncStorage`.

## 1. Cenário anterior

- `POST /api/v1/auth/token/erp` devolvia `access_token` no corpo.
- O front armazenava o token ERP em `localStorage`/AsyncStorage.
- Cada request anexava manualmente `Authorization: Bearer <token ERP>`.

## 2. Novo fluxo

- Login (SSO ou usuário ERP) devolve `{ token, refresh_token, expires_in, user }` e seta `Set-Cookie: <REFRESH_COOKIE_NAME>=<uuid>` (HTTP-only, Secure, SameSite=Lax por padrão).
- O front guarda apenas `token` (sessão) em memória e envia `Authorization: Bearer <sessionId>`.
- O BFF valida a sessão (e o IP vinculado) e injeta o token ERP real no proxy.
- `POST /api/bff/refresh` usa o cookie (ou `refresh_token` no body) para rotacionar sessão + refresh.
- `GET /api/bff/session` informa quem está autenticado. `POST /api/bff/logout` apaga sessão e cookie.

## 3. Ajustes no front-end (axios)

```ts
import axios from 'axios';
import { getToken, setToken, clearToken } from './tokenStore';

const api = axios.create({
  baseURL: process.env.REACT_APP_BFF_URL, // inclua o prefixo /auth se o gateway não fizer rewrite
  withCredentials: true,
});

api.interceptors.request.use((config) => {
  const t = getToken();
  if (t) config.headers.Authorization = `Bearer ${t}`;
  return config;
});

api.interceptors.response.use(resp => resp, async (error) => {
  if (error.response?.status === 401 && !error.config?.url?.includes('/api/bff/refresh')) {
    try {
      const { data } = await api.post('/api/bff/refresh');
      setToken(data.token);
      error.config.headers.Authorization = `Bearer ${data.token}`;
      return api.request(error.config);
    } catch {
      clearToken();
    }
  }
  return Promise.reject(error);
});

export async function loginSso(ticket, email) {
  const { data } = await api.post('/api/v1/auth/sso/callback', { ticket, email });
  setToken(data.token);
  return data;
}

export async function loginErp(login, password) {
  const { data } = await api.post('/api/v1/auth/token/erp/user', { login, password });
  setToken(data.token);
  return data;
}

export const refresh = async () => {
  const { data } = await api.post('/api/bff/refresh');
  setToken(data.token);
  return data;
};

export const logout = async () => {
  await api.post('/api/bff/logout');
  clearToken();
};
```

## 4. Checklist

- [ ] Remover gravação/leitura de `access_token` em `localStorage`/AsyncStorage.
- [ ] Enviar sempre `Authorization: Bearer <sessionId>` (token da resposta de login/refresh).
- [ ] Habilitar `withCredentials` e garantir CORS liberando credenciais no ambiente.
- [ ] Validar domínio/flag Secure do cookie (`SESSION_COOKIE_DOMAIN`, `SESSION_COOKIE_SECURE`).
- [ ] Considerar IP binding: refresh falha se o IP mudar (VPN, troca de rede).
- [ ] Tratar `403` com mensagem `MFA Pending` (sessões pendentes de MFA não são consideradas autenticadas).

## 5. Observações

- O refresh token também é devolvido no body para cenários onde o cookie não é persistido; preferencialmente use o cookie.
- O nome do cookie é configurável (`REFRESH_COOKIE_NAME`, default `cotacao_refresh`).
- Logs de 401/403 vêm do BFF quando a sessão/refresh não é encontrada ou o IP diverge. Use `/api/bff/session` para diagnosticar.
- Em dispositivos móveis, o cookie é enviado automaticamente quando `withCredentials=true`; o token ERP nunca fica exposto no app.
