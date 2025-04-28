import { jest } from '@jest/globals';

// Store original environment
const originalEnv = { ...process.env };

beforeAll(() => {
  // Modify environment safely for testing
  Object.assign(process.env, {
    NODE_ENV: 'test',
    MYSQL_HOST: 'localhost',
    MYSQL_USER: 'test',
    MYSQL_PASSWORD: 'test',
    MYSQL_DATABASE: 'test_db',
    SESSION_SECRET: 'test-secret'
  });
});

afterEach(() => {
  jest.clearAllMocks(); // Clears mocks after each test
});

afterAll(() => {
  // Restore the original environment after all tests
  process.env = originalEnv;
});
