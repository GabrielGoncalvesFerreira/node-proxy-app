import { authController } from './controllers/auth.controller.js';
import { sessionController } from './controllers/session.controller.js';
import { erpUserAuthController } from './controllers/erp-user-auth.controller.js';

export async function registerRoutes(app) {
  app.get('/health', async () => ({ status: 'ok', service: 'bff-cotacao' }));

  app.post('/api/v1/auth/sso/callback', authController.loginSsoCallback.bind(authController));
  app.post('/api/v1/auth/token/erp/user', erpUserAuthController.login.bind(erpUserAuthController));

  app.get('/api/bff/session', sessionController.getSessionStatus.bind(sessionController));
  app.post('/api/bff/refresh', sessionController.refresh.bind(sessionController));
  app.post('/api/bff/logout', sessionController.logout.bind(sessionController));
}
