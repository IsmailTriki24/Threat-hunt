FROM node:22-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund

FROM node:22-alpine AS build
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
# rewrites are baked at build time
ARG BACKEND_INTERNAL_URL=http://backend:8000
ENV BACKEND_INTERNAL_URL=$BACKEND_INTERNAL_URL
ENV NEXT_TELEMETRY_DISABLED=1
RUN npm run build

FROM node:22-alpine AS run
WORKDIR /app
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1 PORT=3000 HOSTNAME=0.0.0.0
RUN addgroup -S hunt && adduser -S hunt -G hunt
COPY --from=build --chown=hunt:hunt /app/.next/standalone ./
COPY --from=build --chown=hunt:hunt /app/.next/static ./.next/static
USER hunt
EXPOSE 3000
CMD ["node", "server.js"]
