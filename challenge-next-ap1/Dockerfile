FROM node:20.18.1-alpine3.20@sha256:fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293 AS build

WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1

COPY package.json package-lock.json ./
RUN npm ci

COPY next.config.js middleware.js ./
COPY pages ./pages
RUN npm run build

FROM node:20.18.1-alpine3.20@sha256:fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293 AS runtime

WORKDIR /app
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1

COPY --from=build --chown=node:node /app/package.json /app/package-lock.json ./
COPY --from=build --chown=node:node /app/node_modules ./node_modules
COPY --from=build --chown=node:node /app/.next ./.next
COPY --from=build --chown=node:node /app/next.config.js /app/middleware.js ./
COPY --from=build --chown=node:node /app/pages ./pages

USER node
EXPOSE 3000
CMD ["npm", "run", "start"]
