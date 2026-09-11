FROM node:20-bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 make g++ poppler-utils tesseract-ocr ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package.json ./
RUN npm install --omit=dev

COPY . .

ENV NODE_ENV=production PORT=3000 PYTHON=/usr/bin/python3

RUN mkdir -p /app/storage/materials

EXPOSE 3000

VOLUME ["/app/storage", "/app/data"]
