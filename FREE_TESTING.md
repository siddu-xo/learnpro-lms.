# LearnPro LMS v28 — Free Testing Deployment

This release is prepared for a **free browser-based test deployment on Render**.

## What is free

Render currently provides a free web-service tier. A free web service gets a free `onrender.com` address, so **you do not need to use or connect the purchased `learnprolms.com` domain for this test**.

Example address after deployment:

`https://learnpro-lms-free-test.onrender.com`

Render's free web service has important testing limitations: it spins down after 15 minutes without traffic and can take about a minute to wake up. Its local filesystem is ephemeral, so local SQLite data and uploaded files can be lost on restart/spin-down/redeploy. This is for testing only, not production.

## Recommended free-test workflow

1. Create a free Render account.
2. Put this project in a GitHub repository.
3. In Render, create a **New Web Service** from that repository.
4. Render can read `render.yaml`, or you can use:
   - Build command: `npm install`
   - Start command: `npm start`
   - Plan: `Free`
   - Health check path: `/health`
5. Add these environment variables in Render:
   - `NODE_ENV=development`
   - `JWT_SECRET=` a long random value
   - `ADMIN_EMAIL=` your chosen admin email
   - `ADMIN_PASSWORD=` a strong test password
   - `RAZORPAY_KEY_ID=` leave blank for UI-only testing
   - `RAZORPAY_KEY_SECRET=` leave blank for UI-only testing
   - `RAZORPAY_WEBHOOK_SECRET=` leave blank for UI-only testing
   - `SMTP_HOST=` leave blank for UI-only testing; OTPs will be logged in Render server logs
   - `SMTP_USER=` leave blank
   - `SMTP_PASS=` leave blank
   - `SMTP_FROM=` leave blank
6. Deploy.
7. Open the free `onrender.com` URL Render gives you.
8. Test registration, login, admin, courses, MCQs, tests and the materials interface.

## Important about materials on the free test

v28 still uses the application's local filesystem/SQLite database for its current testing setup. On Render Free, that storage is not durable. Do **not** treat uploaded student records or real course materials on this environment as permanent.

For the real launch, we will move the database and materials to persistent production services before accepting real students.

## Important about payments

Do not use live Razorpay credentials on the free test environment. Keep payment testing in Razorpay Test Mode until production infrastructure is ready.

## Free domain

You do not need to buy a domain for this phase. Render supplies the free `onrender.com` service URL. We will leave `learnprolms.com` completely disconnected for now.

## Next phase

After the browser test is successful, move the same application to a paid/persistent production stack and optionally connect `learnprolms.com` later.
