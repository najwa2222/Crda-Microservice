import prometheus from 'prom-client';

// Create a Registry which registers the metrics
const registry = new prometheus.Registry();

// Add a default label which is added to all metrics
registry.setDefaultLabels({
  app: 'crda-app'
});

// Enable collection of default metrics
prometheus.collectDefaultMetrics({ register: registry });

// Create custom metrics

// HTTP request counter
const httpRequestsTotal = new prometheus.Counter({
  name: 'http_requests_total',
  help: 'Total number of HTTP requests',
  labelNames: ['method', 'route', 'status_code'],
  registers: [registry]
});

// HTTP request duration
const httpRequestDurationSeconds = new prometheus.Histogram({
  name: 'http_request_duration_seconds',
  help: 'Duration of HTTP requests in seconds',
  labelNames: ['method', 'route', 'status_code'],
  buckets: [0.1, 0.3, 0.5, 0.7, 1, 3, 5, 7, 10],
  registers: [registry]
});

// Database query counter
const dbQueryTotal = new prometheus.Counter({
  name: 'db_query_total',
  help: 'Total number of database queries',
  labelNames: ['operation', 'success'],
  registers: [registry]
});

// Database query duration
const dbQueryDurationSeconds = new prometheus.Histogram({
  name: 'db_query_duration_seconds',
  help: 'Duration of database queries in seconds',
  labelNames: ['operation'],
  buckets: [0.01, 0.05, 0.1, 0.5, 1, 3, 5],
  registers: [registry]
});

// Active sessions gauge
const activeSessionsGauge = new prometheus.Gauge({
  name: 'active_sessions',
  help: 'Number of active sessions',
  registers: [registry]
});

// Export the metrics
export {
  registry,
  httpRequestsTotal,
  httpRequestDurationSeconds,
  dbQueryTotal,
  dbQueryDurationSeconds,
  activeSessionsGauge
};