# LearnPro LMS v27 — Phase 1 Launch

Phase 1 is intentionally focused on launching with **MCQs + study materials first**. Video classes remain supported by the backend/course builder and can be added later without rebuilding the course or asking existing students to purchase again.

## Phase 1 student experience
- Published courses and demo preview
- Student registration/login + OTP/password recovery
- Razorpay payment verification and automatic enrollment
- Study materials with Demo/Premium access control
- MCQ bank, demo/full tests, timer, results and explanations
- Student dashboard and progress foundation
- Notifications
- 2-device session limit
- Admin course/material/MCQ/student/payment/analytics management

## Classes later
Admins can continue using the course builder to add chapters/classes and secure video references later. The student course page currently presents classes as **Coming Soon** so the Phase 1 launch stays focused on materials and MCQs.

## Production note
This remains a deployment-ready development package. Before taking real payments, configure production secrets, HTTPS, database/storage backups, Razorpay live credentials/webhooks, SMTP, and secure video/DRM when classes are introduced.
