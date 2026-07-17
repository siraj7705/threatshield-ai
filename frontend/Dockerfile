# ===============================================
# LOCATION: threatshield-ai/frontend/Dockerfile
# ===============================================

FROM node:20-alpine AS builder

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy source code
COPY . .

# In Docker, nginx proxies /api -> backend, so the SPA should call
# relative paths. Override with --build-arg VITE_API_URL=... if needed.
ARG VITE_API_URL=""
ENV VITE_API_URL=${VITE_API_URL}

# Build for production
RUN npm run build

# --- Production Stage ---
FROM nginx:alpine

# Copy built files to nginx
COPY --from=builder /app/dist /usr/share/nginx/html

# Copy nginx config
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]