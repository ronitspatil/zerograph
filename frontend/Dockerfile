FROM node:22-alpine AS dependencies
WORKDIR /app
COPY package.json package-lock.json .npmrc ./
RUN npm ci --no-audit --no-fund

FROM node:22-alpine AS builder
WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1
COPY --from=dependencies /app/node_modules ./node_modules
COPY . .
RUN npm run build

FROM node:22-alpine
WORKDIR /app
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1 PORT=3100 HOSTNAME=0.0.0.0
RUN addgroup -S -g 10001 zerograph && adduser -S -u 10001 -G zerograph zerograph
COPY --from=builder --chown=zerograph:zerograph /app/.next/standalone ./
COPY --from=builder --chown=zerograph:zerograph /app/.next/static ./.next/static
COPY --from=builder --chown=zerograph:zerograph /app/public ./public
USER 10001:10001
EXPOSE 3100
CMD ["node", "server.js"]
