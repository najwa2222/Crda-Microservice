// jest-resolver.js
/**
 * This file helps Jest resolve ES modules
 */
export function resolve(path, options) {
  return options.defaultResolver(path, {
    ...options,
    packageFilter: pkg => {
      if (pkg.type === 'module') {
        return {
          ...pkg,
          main: pkg.module || pkg.main
        };
      }
      return pkg;
    }
  });
}

// Export both sync and async methods for Jest
export const sync = resolve;
export const async = resolve;