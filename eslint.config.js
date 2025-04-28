import js from '@eslint/js';
import eslintPluginJest from 'eslint-plugin-jest';

export default [
  // ESLint recommended rules
  js.configs.recommended,

  // ✅ CommonJS (Node.js) specific config for files like app.js
  {
    languageOptions: {
      sourceType: 'script', // CommonJS
      globals: {
        require: 'readonly',
        module: 'readonly',
        process: 'readonly',
        console: 'readonly',
        setTimeout: 'readonly',
        connection: 'readonly', // Treat as global to suppress no-undef for now
        pp: 'readonly',
        registry: 'readonly',
      },
    },
    files: ['app.js', '**/*.cjs'], // Explicitly match app.js
    rules: {
      'no-undef': 'off', // Disable for these files
      'no-unused-vars': 'warn',
      'no-console': 'off',
    },
  },

  {
    languageOptions: {
      sourceType: 'module',
      globals: {
        node: 'readonly',
        process: 'readonly',
        console: 'readonly',
        setTimeout: 'readonly',
        pp: 'readonly',
        registry: 'readonly',
      },
    },
    files: [
      '**/*.js',
      'utils/**/*.js',
      '__tests__/**/*.js',
      '__mocks__/**/*.js',
      'jest/**/*.js',
      'jest-resolver.js',
    ],
    rules: {
      'no-unused-vars': 'warn',
      'no-console': 'off',
    },
    ignores: [
      '**/node_modules/',
      'coverage/',
      'public/',
      '**/*.config.js',
    ],
  },

  {
    languageOptions: {
      globals: {
        module: 'readonly',
        require: 'readonly',
        jest: 'readonly',
        describe: 'readonly',
        beforeEach: 'readonly',
        afterEach: 'readonly',
        beforeAll: 'readonly',
        afterAll: 'readonly',
        it: 'readonly',
        expect: 'readonly',
      },
    },
    files: ['**/__tests__/**/*.js', '**/*.test.js', '**/jest/**/*.js', 'jest-junit.config.js'],
    plugins: {
      jest: eslintPluginJest,
    },
    rules: {
      // Add any Jest rules here if needed
    },
  },

  {
    languageOptions: {
      globals: {
        jest: 'readonly',
      },
    },
    files: ['**/__mocks__/**/*.js'],
    rules: {
      'no-undef': 'off',
    },
  },
];
