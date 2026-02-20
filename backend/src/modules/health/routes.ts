import type { FastifyPluginAsync } from 'fastify';

const healthRoutes: FastifyPluginAsync = async (app) => {
  app.get('/live', async () => ({ status: 'ok' }));

  app.get('/ready', async () => ({
    status: 'ready',
    service: 'iam-news-api',
    time: new Date().toISOString()
  }));
};

export default healthRoutes;
