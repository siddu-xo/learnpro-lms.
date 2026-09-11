# v22 Smoke Test

1. Start server and open `/health`; expect `ok: true`.
2. Register a student, verify OTP, then log in.
3. Open a published course while logged out; confirm public preview works.
4. Login from the preview; confirm demo content is visible and premium content is locked.
5. Configure Razorpay test keys; Buy Now; complete test checkout; confirm payment verification unlocks the course.
6. Open a class and mark it complete; confirm dashboard progress changes.
7. Open MCQ Tests; confirm questions come from the server test-start endpoint; submit and confirm result/history.
8. Login on two devices; on a third login confirm the oldest session is revoked.
9. Login as admin; confirm dashboard, students, courses, materials, MCQs and analytics load.
