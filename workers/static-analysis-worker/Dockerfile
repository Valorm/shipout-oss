# Static Analysis Worker - Fly.io Machine Image
FROM node:20-slim

WORKDIR /app

# Install git for repo cloning
RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*

# Copy package files first to leverage caching
COPY package*.json ./

# Install only production dependencies
RUN npm ci --omit=dev

# Copy all source code (respects .dockerignore)
COPY . .

# Environment variables
ENV NODE_ENV=production

# The worker entrypoint
CMD ["npx", "tsx", "workers/static-analysis-worker/entrypoint.ts"]
