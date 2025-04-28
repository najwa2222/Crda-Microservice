# Use a lightweight Node.js LTS base image
FROM node:20-alpine

# Set working directory
WORKDIR /app

# Copy only package manifests first (leverages Docker layer caching)
COPY package*.json ./

# Install only production dependencies
RUN npm ci --omit=dev

# Copy the rest of your app, excluding files in .dockerignore
COPY . .

# Ensure NODE_ENV is production
ENV NODE_ENV=production

# Expose the port from your .env (default 3002)
EXPOSE 3002

# (Optional) Install curl for healthchecks
RUN apk add --no-cache curl

# Kubernetes-style healthcheck against your /health endpoint
HEALTHCHECK --interval=30s --timeout=5s \
  CMD curl -f http://localhost:3002/health-pod || exit 1

# Start your service
CMD ["node", "app.js"]
