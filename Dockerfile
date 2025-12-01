FROM node:20-alpine

WORKDIR /app
ENV NODE_ENV=production

COPY src/package*.json .
RUN npm ci

RUN apk add --no-cache docker-cli

COPY src/*.js .
COPY src/whitelist.csv .
COPY src/keys.json .

EXPOSE 8080

CMD ["node", "server.js"]
