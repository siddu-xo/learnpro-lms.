# LearnPro LMS v25

v25 is a QA-focused release based on v24. It adds an automated, dependency-light smoke test (`npm test`) that validates required project files, server syntax, and the presence of critical LMS/security routes and configuration. It also verifies that the MCQ schema/server do not reintroduce a Marks field.

## Run

```bash
npm install
npm test
npm run check
npm start
```

## QA note

The automated checks are static/dependency-light. Full browser/E2E testing and real third-party integrations (Razorpay, SMTP, secure video/DRM) require dependencies, configured credentials, and a deployment-like environment. Passing this smoke test is not a production certification.
