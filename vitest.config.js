// War Chat - Vitest config for unit tests
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    include: ['internal/server/web/js/**/*.test.js', 'test/**/*.test.js'],
    globals: true,
  },
});
