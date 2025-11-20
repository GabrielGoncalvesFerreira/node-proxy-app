import { authController } from './controllers/auth.controller.js';
import { sessionController } from './controllers/session.controller.js';

export async function registerRoutes(app) {
  app.get('/health', async () => ({ status: 'ok', service: 'bff-cotacao' }));

  app.post('/api/v1/auth/sso/callback', authController.loginSsoCallback.bind(authController));

  app.get('/bff/session', sessionController.getSessionStatus.bind(sessionController));
  app.post('/bff/logout', sessionController.logout.bind(sessionController));
}