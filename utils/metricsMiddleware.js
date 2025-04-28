import { httpRequestsTotal, httpRequestDurationSeconds } from './metrics.js';

export const metricsMiddleware = (req, res, next) => {
  // Record start time
  const start = Date.now();
  
  // Add a listener for the response finish event
  res.on('finish', () => {
    // Calculate request duration
    const duration = (Date.now() - start) / 1000;
    
    // Record request
    httpRequestsTotal.inc({
      method: req.method, 
      route: req.originalUrl, 
      status_code: res.statusCode
    });
    
    // Record request duration
    httpRequestDurationSeconds.observe({
      method: req.method, 
      route: req.originalUrl, 
      status_code: res.statusCode
    }, duration);
  });
  
  next();
};