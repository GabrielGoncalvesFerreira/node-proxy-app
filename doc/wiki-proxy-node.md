| Proxy Node | Versão 1.0.0 |
| --- | --- |
| Documentação técnica | Data: 07/02/2025 |
| Revisão: 2 | |

---

## 1. Visão geral

O `proxy-node` é o BFF da Cotação. Ele roda em Fastify 5, aplica CORS, normaliza cabeçalhos de rastreabilidade e faz proxy para a API Laravel. Todas as rotas locais e proxied são expostas sob o prefixo `/auth` (o plugin `@fastify/http-proxy` reescreve removendo esse prefixo antes de atingir o backend). As credenciais sensíveis (`client_id`/`client_secret`) ficam no BFF; clientes recebem apenas um id de sessão e um refresh cookie HTTP-only salvo no Redis.

Principais responsabilidades:
- Login SSO (troca de ticket) e login por credenciais ERP.
- Emissão/rotação de sessão (UUID) + refresh token em cookie.
- Validação de sessão e injeção do `Authorization` correto antes de encaminhar ao Laravel.
- Normalização de headers (`x-client-ip`, `x-bff-ip`, `user-agent`, `x-client-version`) e keep-alive via `undici`.

## 2. Componentes principais (src/)

- `server.js`: cria o Fastify, registra CORS (configurável via `CORS_ORIGINS`), `formbody` e `cookie`. Hook `onRequest` grava IP do cliente, garante `user-agent`/`x-client-version` e loga URL/IP. Registra rotas locais com prefixo `/auth` e o proxy para `API_BASE`, com `proxyPreHandler` e `replyOptions.onResponse`.
- `routes.js`: mapeia endpoints locais:
  - `GET /auth/health`
  - `POST /auth/api/v1/auth/sso/callback`
  - `POST /auth/api/v1/auth/token/erp/user`
  - `GET /auth/api/bff/session`
  - `POST /auth/api/bff/refresh`
  - `POST /auth/api/bff/logout`
- Controllers
  - `auth.controller.js`: recebe `ticket` (e opcional `email`), valida no SSO (`SSO_API_URL/api/v1/auth/sso/validate`), troca por token ERP usando Basic Auth, cria sessão atrelada ao IP e grava refresh cookie.
  - `erp-user-auth.controller.js`: fluxo password grant com `login`/`password` (normalizados para upper), aplica `getClientTypeFromHeaders`, envia headers whitelisted e cria sessão + refresh cookie.
  - `session.controller.js`: status da sessão (401 se inválida, 403 se `isPendingMfa`), refresh rotaciona sessão e refresh token (cookie + body) e logout remove sessão/refresh/índice de login.
- Services
  - `auth.service.js`: valida SSO (suporta CA customizada `SSO_CA_PATH` ou `rejectUnauthorized=false` em dev), troca pelo token ERP em `config.api.endpoints.erpToken` com Basic Auth, cria sessão e índice por login.
  - `erp-user-auth.service.js`: password grant direto no ERP (`/api/v1/auth/token/erp/user`) com Basic Auth.
  - `session.service.js`: CRUD de sessões no Redis (`sessao:{id}`), índice por login (`sessao_login:{login}`), refresh tokens (`refresh:{id}`) e vínculo sessão→refresh (`refresh_by_session:{id}`). Sessions carregam `token` ERP, `user`, `scope`, `clientType`, `ip`, `login` e `meta` (TTL, datas).
  - `http.service.js`: axios configurado com `API_BASE` e timeout (15000 ms) para chamadas internas ao backend.
- `proxy/middleware.js`: define política por rota: `passthrough` (`/health`, `/api/v1/public/**`, `/api/v1/auth/sso/callback`), `inject_basic_auth` (POST `/api/v1/auth/token/erp`) ou `user_session` (demais rotas). Valida bearer de sessão (UUID), checa IP, troca o header `Authorization` para o `token` ERP da sessão e injeta headers de IP/versão.
- `infra/redis-client.js`: client Redis obrigatório (`REDIS_URL`), com logs de conexão e `connect()` em top-level await.
- `utils/client-type.js`: infere `web`/`mobile` a partir de `x-client-type`.

## 3. Fluxos principais

### 3.1 Login SSO (`POST /auth/api/v1/auth/sso/callback`)
1. Recebe `ticket` (obrigatório) e opcional `email`.
2. Valida ticket no SSO (pode usar CA customizada).
3. Troca por token ERP no backend (`/api/v1/auth/token/erp`) com Basic Auth, propagando headers de IP/UA.
4. Cria sessão (UUID) contendo token ERP + usuário + IP + login normalizado.
5. Grava refresh cookie (`config.session.refreshCookieName`, default `cotacao_refresh`) e retorna body com `token` (sessionId), `refresh_token`, `expires_in`, `user`.

### 3.2 Login ERP por credenciais (`POST /auth/api/v1/auth/token/erp/user`)
1. Recebe `login`/`password`, ambos uppercased antes de enviar ao ERP.
2. Envia headers permitidos (`x-forwarded-for`, `x-real-ip`, `x-client-ip`, `x-bff-ip`, `x-request-id`, `user-agent`, `x-client-version`, `x-client-id`, `x-api-key`).
3. Cria sessão com token ERP, indexa pelo login normalizado, guarda IP, clientType e TTL retornado.
4. Devolve `token` (sessionId), `refresh_token`, `expires_in`, `scope`, `user` e `clientType`.

### 3.3 Sessão, refresh e logout
- `GET /auth/api/bff/session`: exige `Authorization: Bearer <sessionId>`. Retorna `{ authenticated: true, user, scope, clientId, clientType }` ou `403` com `MFA Pending` caso `session.isPendingMfa`.
- `POST /auth/api/bff/refresh`: usa refresh token do cookie (ou `refresh_token` no body) para emitir nova sessão e novo refresh, vinculados ao mesmo IP; limpa refresh antigo.
- `POST /auth/api/bff/logout`: remove sessão (pelo bearer, se enviado), apaga refresh token e limpa cookie.

### 3.4 Proxy das rotas de API
- Todas as rotas que não caem em `passthrough` ou `inject_basic_auth` exigem bearer de sessão válido. O proxy troca esse bearer pelo `token` ERP salvo na sessão antes de encaminhar ao `API_BASE`.
- POST `/api/v1/auth/token/erp` recebe Basic Auth automático quando o cliente não enviou `Authorization`.
- `replyOptions.onResponse`: se a requisição original foi `POST /api/v1/auth/token` e retornou sucesso, dispara em segundo plano um `POST` para `${API_BASE}/api/v1/auth/token/erp` com Basic Auth, apenas para registrar/validar o endpoint ERP.

## 4. Armazenamento e segurança

- Sessions e refresh tokens ficam no Redis com TTL configurável. Cada sessão guarda `meta.expiresAt` e é removida se expirada durante o acesso.
- Indexação por login garante uma sessão ativa por login (nova sessão remove a anterior).
- Validação de IP no refresh e no proxy: se a sessão tiver `ip` definido e o IP do request divergir, a sessão é invalidada.
- Headers normalizados garantem `user-agent` mínimo e propagação de `x-client-version`. `trustProxy` aceita `127.0.0.1`, `::1` e `172.27.0.1/24`.

## 5. Configuração (.env)

| Variável | Descrição | Default |
| --- | --- | --- |
| `PORT` | Porta do BFF | `5181` |
| `API_BASE` | URL base do backend Laravel (obrigatório) | — |
| `SSO_API_URL` | URL do BFF SSO (obrigatório) | — |
| `OAUTH_CLIENT_ID` / `OAUTH_CLIENT_SECRET` | Credenciais usadas para Basic Auth nos endpoints ERP | — |
| `REDIS_URL` | Conexão Redis (obrigatório) | — |
| `CORS_ORIGINS` | Lista separada por vírgula; vazio bloqueia CORS | `''` (bloqueado) |
| `SESSION_COOKIE_DOMAIN` | Domínio do cookie de refresh | — |
| `SESSION_COOKIE_SECURE` | `true/false` para flag Secure | `true` |
| `SESSION_TTL_SECONDS` | TTL das sessões (segundos) | `86400` |
| `REFRESH_COOKIE_NAME` | Nome do cookie HTTP-only | `cotacao_refresh` |
| `REFRESH_TTL_SECONDS` | TTL dos refresh tokens (segundos) | `604800` |
| `SSO_CA_PATH` | Caminho opcional para CA customizada do SSO | — |
| `NODE_ENV` | `development` permite `rejectUnauthorized=false` para SSO | — |

**Base path:** o container expõe as rotas em `/auth`. Se o gateway externo já fizer rewrite, ajuste o `baseURL` do cliente para refletir o caminho efetivo.

## 6. Execução

```bash
cd proxy-node
npm install
npm start        # node src/server.js, porta configurada em PORT
# ou	npm run dev   # node --watch --inspect=0.0.0.0:9229 src/server.js
```

Dockerfile (prod) usa Node 20-alpine, `npm ci --only=production`, usuário `node` e expõe 5180; sobreponha a porta via `PORT` em runtime.

## 7. Operação e monitoramento

- Logger Fastify habilitado (`logger: true`); hooks `onRequest` logam IP/URL e `onResponse` avisa status >= 400.
- Redis é obrigatório para sessões/refresh; monitore conectividade, TTL e memória. Falhas aparecem com prefixo `[Redis]`.
- CORS precisa liberar `credentials` para que o cookie de refresh seja enviado.
- Headers `x-client-ip` e `x-bff-ip` são sempre preenchidos (IP real e IP do BFF), preservando `user-agent` e `x-client-version`.
- Erros HTTP em dev são logados pelo `http.service` (axios interceptor) para ajudar debugging.

## 8. Evoluções sugeridas

1. Métricas/telemetria para contagem de refresh, invalidação por IP e cache hits.
2. Ajustar política do proxy para remover o prefixo `/auth` do path antes da decisão (hoje depende do rewrite do gateway).
3. Testes automatizados para `session.service` (rotações de refresh, binding por IP) e para o `proxyPreHandler`.
4. Circuit breaker/retry configurável nas chamadas ao backend.
