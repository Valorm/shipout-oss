# Run from monorepo root to include all shared files and package.json
FROM node:20-alpine

WORKDIR /app

# Copy the monorepo package files
COPY package*.json ./
RUN npm ci --omit=dev

# Copy all monorepo files (job-queue needs shared/ and database/ dependencies)
COPY . .

# Run consumer directly using tsx (better ESM support)
CMD ["npx", "tsx", "services/job-queue/consumer.ts"]
