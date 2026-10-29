FROM node:22-bookworm-slim

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends ffmpeg python3 make g++ \
    && rm -rf /var/lib/apt/lists/*

COPY backend/package.json ./backend/
RUN cd backend && npm install --omit=dev

COPY backend/server.js ./backend/server.js
COPY frontend/public ./frontend/public

ENV NODE_ENV=production
CMD ["node", "backend/server.js"]
