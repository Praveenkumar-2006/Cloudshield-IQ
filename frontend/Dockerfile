# ============================================================
# Stage 1: Build static React SPA bundle
# ============================================================
FROM node:20-alpine AS builder

WORKDIR /app

# Copy dependency specifications
COPY package.json package-lock.json ./

# Clean install dependencies
RUN npm ci

# Copy full frontend source
COPY . .

# Compile TypeScript and bundle with Vite
RUN npm run build

# ============================================================
# Stage 2: Serve static files with lightweight Nginx
# ============================================================
FROM nginx:1.27-alpine AS runtime

LABEL maintainer="CloudShield IQ Project"
LABEL description="CloudShield IQ Frontend — Production"

# Remove default nginx static html
RUN rm -rf /usr/share/nginx/html/*

# Copy built static artifacts from builder stage
COPY --from=builder /app/dist /usr/share/nginx/html

# Copy tailored SPA Nginx configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -qO- http://localhost:80/ || exit 1

CMD ["nginx", "-g", "daemon off;"]
