# build stage
FROM node:20-alpine AS builder

WORKDIR /app
COPY package.json package-lock.json* bun.lock* tsconfig.json ./
COPY src ./src
COPY migrations ./migrations

RUN npm ci --production=false
RUN npm run build

# production stage
FROM node:20-alpine
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=builder /app/package.json ./
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/migrations ./migrations

EXPOSE 8080
ENV NODE_ENV=production
CMD ["node", "./dist/index.js"]