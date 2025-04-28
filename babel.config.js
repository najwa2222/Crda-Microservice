// babel.config.js
export default {
    presets: [
      [
        '@babel/preset-env',
        {
          targets: {
            node: 'current', // Ensures compatibility with the current Node version
          },
        },
      ],
    ],
    plugins: ['@babel/plugin-transform-modules-commonjs'], // Ensures that ESM imports are converted to CommonJS for Jest
  };
  