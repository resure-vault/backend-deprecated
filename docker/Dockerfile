FROM oven/bun:1-alpine

WORKDIR /usr/src/app

COPY package.json ./
COPY bun.lock* ./
RUN bun install

COPY . .

EXPOSE 8080

CMD ["bun", "run", "app/main.ts"]
