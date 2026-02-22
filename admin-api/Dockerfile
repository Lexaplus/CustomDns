FROM node:20-alpine AS builder

WORKDIR /app

COPY package.json ./
RUN npm install --frozen-lockfile

COPY tsconfig.json ./
COPY src ./src

RUN npm run build

# ── Production image ──────────────────────────────────────────
FROM node:20-alpine

RUN apk add --no-cache sudo

WORKDIR /app

COPY package.json ./
RUN npm install --omit=dev --frozen-lockfile

COPY --from=builder /app/dist ./dist

# Allow the node user to call firewall_apply.sh as root without a password
RUN echo "node ALL=(root) NOPASSWD: /deploy/firewall_apply.sh" \
    > /etc/sudoers.d/node-firewall \
    && chmod 0440 /etc/sudoers.d/node-firewall

USER node

EXPOSE 8080

CMD ["node", "dist/main.js"]
