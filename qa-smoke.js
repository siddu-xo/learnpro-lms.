const fs = require('fs');
const cp = require('child_process');
const path = require('path');
const root = __dirname;
const required = ['server.js','schema.sql','package.json','public/index.html','DEPLOYMENT.md','MCQ_IMPORT_TEMPLATE.csv'];
let failures = [];
for (const f of required) if (!fs.existsSync(path.join(root,f))) failures.push(`Missing required file: ${f}`);
try { cp.execFileSync(process.execPath,['--check',path.join(root,'server.js')],{stdio:'ignore'}); } catch { failures.push('server.js syntax check failed'); }
const pkg = JSON.parse(fs.readFileSync(path.join(root,'package.json'),'utf8'));
if (pkg.scripts?.test !== 'node qa-smoke.js') failures.push('package.json test script is not configured');
const server = fs.readFileSync(path.join(root,'server.js'),'utf8');
const schema = fs.readFileSync(path.join(root,'schema.sql'),'utf8');
const checks = [
  ['health endpoint', /app\.get\('\/health'/.test(server)],
  ['public course endpoint', /app\.get\('\/api\/public\/courses'/.test(server)],
  ['student login endpoint', /app\.post\('\/api\/auth\/login'/.test(server)],
  ['registration endpoint', /app\.post\('\/api\/auth\/register'/.test(server)],
  ['password reset endpoint', /request-password-reset/.test(server) && /reset-password/.test(server)],
  ['payment verification', /\/api\/payments\/verify/.test(server)],
  ['payment webhook', /\/api\/payments\/webhook/.test(server)],
  ['student progress', /\/api\/student\/lessons\/:id\/progress/.test(server)],
  ['test submission', /\/api\/student\/tests\/submit/.test(server)],
  ['MCQ CSV import', /bulk-import-csv/.test(server)],
  ['MCQ PDF import', /import-pdf/.test(server)],
  ['materials upload', /materials\/upload/.test(server)],
  ['admin student management', /\/api\/admin\/students/.test(server)],
  ['rate limiting', /rateLimit\(/.test(server)],
  ['security headers', /X-Content-Type-Options/.test(server) && /X-Frame-Options/.test(server) && /Referrer-Policy/.test(server)],
  ['no marks field', !/\bmarks\b/i.test(schema) && !/\bmarks\b/i.test(server)],
];
for (const [name,ok] of checks) if (!ok) failures.push(`Failed check: ${name}`);
if (failures.length) { console.error('QA FAILED'); failures.forEach(x=>console.error(' - '+x)); process.exit(1); }
console.log(`QA PASS: ${required.length} required files + ${checks.length} integration/security checks`);
