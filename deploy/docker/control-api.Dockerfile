FROM node:24-alpine AS build
WORKDIR /app
COPY control-api/package.json control-api/package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY control-api/ .
RUN npx tsc -p tsconfig.json
RUN npm prune --omit=dev --ignore-scripts --no-audit --no-fund

FROM node:24-alpine
ENV NODE_ENV=production
WORKDIR /app
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY --from=build /app/config ./config
COPY --from=build /app/package.json ./
USER node
CMD ["node", "dist/server.js"]
