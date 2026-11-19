# Elrond Web Frontend Dockerfile
# Multi-stage build for optimized production image

# Stage 1: Build stage
FROM node:22-alpine AS build

LABEL maintainer="Elrond Team"
LABEL description="Elrond Web Frontend"
LABEL version="2.1.0"

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies (Vite, which builds it, is a dev dependency)
RUN npm ci && \
    npm cache clean --force

# Copy application code
COPY . .

# Build for production
RUN npm run build

# Stage 2: Production stage
FROM node:22-alpine AS production

WORKDIR /app

# Install serve to run the production build
RUN npm install -g serve

# Copy built assets from build stage
COPY --from=build /app/build /app/build

# Create non-root user
RUN addgroup -g 1000 elrond && \
    adduser -D -u 1000 -G elrond elrond && \
    chown -R elrond:elrond /app

USER elrond

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:3000/ || exit 1

# Serve the production build
CMD ["serve", "-s", "build", "-l", "3000"]

# Stage 3: Development stage
FROM node:22-alpine AS development

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install all dependencies (including dev). Offline, npm can exit 0 with empty packages:
# fail instead, so that layer is never cached
RUN npm ci && test -x node_modules/.bin/vite

# Copy application code
COPY . .

# Expose port
EXPOSE 3000

# Start the development server (Vite, on 0.0.0.0:3000: vite.config.js)
CMD ["npm", "start"]
