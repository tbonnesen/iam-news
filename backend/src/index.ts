import { buildApp } from './app.js';
import { loadConfig } from './config.js';

const config = loadConfig();
const app = buildApp({ config });

async function main(): Promise<void> {
  try {
    await app.listen({
      host: '0.0.0.0',
      port: config.port
    });
    app.log.info({ port: config.port }, 'iam-news api listening');
  } catch (error) {
    app.log.fatal({ err: error }, 'failed to start server');
    process.exit(1);
  }
}

void main();
