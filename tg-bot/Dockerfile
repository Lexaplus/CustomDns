FROM node:20-alpine

WORKDIR /app

COPY package.json ./
RUN npm install --frozen-lockfile

COPY src ./src

USER node

CMD ["node", "src/index.js"]
