import { jest } from '@jest/globals'; // 👈 add this
jest.mock('mysql2/promise'); // this will pull from __mocks__/mysql2/promise.js
import request from 'supertest';
import app from '../app'; // Import the app

describe('Health Check', () => {
  it('should return 200 OK for /health', async () => {
    const response = await request(app).get('/health');
    expect(response.status).toBe(200);
    expect(response.text).toBe('OK');
  });
});
