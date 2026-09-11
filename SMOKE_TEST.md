# LearnPro LMS v12 smoke test

1. Start the server and open the site.
2. Confirm `/health` returns `{ ok: true }`.
3. Log in as admin with a valid admin account/token.
4. Create or open a course.
5. In Course Builder choose **+ Upload** under Study Materials.
6. Upload a PDF under 50MB, set Demo or Premium, and confirm it appears in the builder.
7. Download the material as an enrolled student; confirm access works.
8. Try a Premium material as a non-enrolled student; confirm it returns 403.
9. Delete the material from the builder; confirm the database record and stored file are removed.
10. Confirm existing course, MCQ PDF/OCR, notifications, payment and progress APIs still start normally.
