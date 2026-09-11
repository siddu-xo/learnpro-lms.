# LearnPro LMS v26

Deployment-ready packaging milestone.

Includes:
- v25 LMS functionality and QA suite
- `.env` loading without an extra runtime package
- Docker image with Node 20 + Poppler + Tesseract OCR
- Docker Compose with persistent database/material volumes
- Container healthcheck
- Graceful SIGTERM/SIGINT shutdown
- Production deployment guide

Run locally: `npm install && npm start`
Run QA: `npm test`
Docker: `docker compose up -d --build`
