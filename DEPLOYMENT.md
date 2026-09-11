# LearnPro LMS v26 — Production Deployment

## Recommended setup

Internet -> Nginx/Caddy (HTTPS) -> 127.0.0.1:3000 -> LearnPro container

Keep the Node port private. Persist `./data` and `./storage` and back them up.

## 1. Configure environment

Copy `.env.example` to `.env` and set production values. Never commit `.env`.

Required before launch:
- `NODE_ENV=production`
- `JWT_SECRET` (32+ random characters)
- `ADMIN_EMAIL` and `ADMIN_PASSWORD`
- Razorpay live credentials and webhook secret
- SMTP credentials for real OTP email
- `APP_BASE_URL` using HTTPS

## 2. Docker deployment

```bash
docker compose build
docker compose up -d
```

Check:

```bash
curl http://127.0.0.1:3000/health
```

The response should indicate the application is healthy.

## 3. Reverse proxy

Point your domain to the server and proxy HTTPS traffic to `127.0.0.1:3000`. Set `TRUST_PROXY=1` when using a single trusted reverse proxy so rate limiting sees the client IP correctly.

## 4. Persistent data

Back up:
- `./data` (SQLite database)
- `./storage` (uploaded course materials)

Test restoration before launch. For a large production LMS, plan a future migration from SQLite to PostgreSQL.

## 5. OCR requirements

The Docker image installs Poppler and Tesseract so scanned-PDF OCR can work in the container.

## 6. Launch checklist

- HTTPS works
- Student registration + email OTP works
- Forgot password works
- Two-device rule works
- Guest sees demo content but not premium content
- Razorpay payment is verified server-side
- `payment.captured` webhook is verified
- Enrollment is created only after verified/captured payment
- Premium materials remain protected
- Secure video provider is configured for signed playback/DRM
- Admin can manage students/courses/materials/MCQs
- Database + uploads are backed up
- Restore test completed
- `npm test` passes
