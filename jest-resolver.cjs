// jest-resolver.cjs
// CommonJS adapter for ES Module resolver

// Use dynamic import to load the ES Module resolver
const resolverPromise = import('./jest-resolver.js');

// Export CommonJS compatible function that proxies to the ES Module
module.exports = async function(request, options) {
  const resolver = await resolverPromise;
  return resolver.resolve(request, options);
};

// Export sync method (required by Jest)
module.exports.sync = function(request, options) {
  // This is a workaround since we can't synchronously import ES modules
  // We'll throw a specific error to help debugging
  throw new Error(
    'Jest is trying to use the sync resolver from CommonJS, but our resolver is an ES Module. ' +
    'Please ensure all tests use dynamic imports or configure Jest to avoid sync resolution.'
  );
};

// Export async method
module.exports.async = async function(request, options) {
  const resolver = await resolverPromise;
  return resolver.async ? resolver.async(request, options) : resolver.resolve(request, options);
};