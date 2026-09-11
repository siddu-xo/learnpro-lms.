# LearnPro LMS v19 — Real Authentication 2.0

v19 connects the visible student/admin login screens to the existing backend authentication APIs.

## Included
- Student registration with bcrypt-backed server storage
- Student login with real JWT session
- Admin login with role verification
- Existing 2-active-device session enforcement remains server-side
- Inactive student accounts are rejected by the backend
- Real logout revokes the current session and clears browser credentials
- Password field no longer contains a hard-coded demo password
- Authentication errors are shown in the student UI

## Important
Password-reset/OTP email delivery is not fully implemented yet because it requires an email/OTP provider and secure reset-token workflow. The UI currently identifies this as the next authentication step rather than pretending recovery is live.
