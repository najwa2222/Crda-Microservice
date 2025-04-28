// __mocks__/mysql2/promise.js
import { jest } from '@jest/globals';

export const createConnection = jest.fn().mockResolvedValue({
  query: jest.fn().mockResolvedValue([[{ result: 1 }], []]),
  end: jest.fn().mockResolvedValue(),
});

export const createPool = jest.fn(() => ({
  getConnection: jest.fn(() => ({
    release: jest.fn(),
    query: jest.fn().mockResolvedValue([[{ result: 1 }], []]),
  })),
  query: jest.fn().mockResolvedValue([[{ result: 1 }], []]),
}));


