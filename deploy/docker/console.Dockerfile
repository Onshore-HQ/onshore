FROM node:24-alpine AS build
WORKDIR /app
COPY console/package.json console/package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY console/ .
ENV NEXT_TELEMETRY_DISABLED=1
RUN npx next build

FROM node:24-alpine
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1 PORT=3000 HOSTNAME=0.0.0.0
WORKDIR /app
COPY --from=build /app/.next/standalone ./
COPY --from=build /app/.next/static ./.next/static
COPY --from=build /app/tls-server.mjs ./tls-server.mjs
USER node
CMD ["node", "tls-server.mjs"]
