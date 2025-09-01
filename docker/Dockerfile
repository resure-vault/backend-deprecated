# /*
#  * resure — the best way to store your secrets instead of forgetting them.
#  *
#  * Copyright (c) 2025-present
#  * Shubham Yadav (bas3line), Nandha (almightynan)
#  * License: MIT
#  *
#  * Permission is hereby granted, free of charge, to any person obtaining a
#  * copy of this software and associated documentation files (the "Software"),
#  * to deal in the Software without restriction, including without limitation
#  * the rights to use, copy, modify, merge, publish, distribute, sublicense,
#  * and/or sell copies of the Software, and to permit persons to whom the
#  * Software is furnished to do so, subject to the following conditions:
#  *
#  * The above copyright notice and this permission notice shall be included in
#  * all copies or substantial portions of the Software.
#  *
#  * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
#  * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#  * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#  * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#  * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
#  * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
#  * DEALINGS IN THE SOFTWARE.
#  */

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