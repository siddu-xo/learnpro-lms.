# v25 QA Smoke Test

Automated checks cover:
- Required project files
- Node syntax validation for `server.js`
- Health/public course/auth/payment/progress/test/material/admin routes
- Security headers and request rate limiting
- MCQ CSV/PDF import routes
- Password recovery/verification routes
- Absence of a Marks field in the MCQ schema/server

Run `npm test` and `npm run check` after `npm install`.

Browser-level E2E testing and third-party Razorpay/SMTP/DRM integration must be performed with real configured services before production launch.
