// Minimal .env loader so production deployments do not depend on a global dotenv package.
const fs0 = require('fs');
const path0 = require('path');
try {
  const envPath = path0.join(__dirname, '.env');
  if (fs0.existsSync(envPath)) {
    for (const raw of fs0.readFileSync(envPath, 'utf8').split(/\r?\n/)) {
      const line = raw.trim();
      if (!line || line.startsWith('#') || !line.includes('=')) continue;
      const i = line.indexOf('=');
      const key = line.slice(0, i).trim();
      let value = line.slice(i + 1).trim();
      if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) value = value.slice(1, -1);
      if (!process.env[key]) process.env[key] = value;
    }
  }
} catch (e) { console.warn('Could not load .env:', e.message); }

const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');
const multer = require('multer');
const pdfParse = require('pdf-parse');
const os = require('os');
const https = require('https');
const { execFile } = require('child_process');
const { promisify } = require('util');
const nodemailer = require('nodemailer');
const execFileAsync = promisify(execFile);

const app = express();
if (process.env.TRUST_PROXY === '1') app.set('trust proxy', 1);
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-only-change-me';
const RAZORPAY_KEY_ID = process.env.RAZORPAY_KEY_ID || '';
const RAZORPAY_KEY_SECRET = process.env.RAZORPAY_KEY_SECRET || '';
const RAZORPAY_CURRENCY = process.env.RAZORPAY_CURRENCY || 'INR';
const SMTP_HOST = process.env.SMTP_HOST || '';
const SMTP_PORT = Number(process.env.SMTP_PORT || 587);
const SMTP_USER = process.env.SMTP_USER || '';
const SMTP_PASS = process.env.SMTP_PASS || '';
const SMTP_FROM = process.env.SMTP_FROM || SMTP_USER;
const OTP_TTL_MINUTES = Number(process.env.OTP_TTL_MINUTES || 10);
const NODE_ENV = process.env.NODE_ENV || 'development';
const RAZORPAY_WEBHOOK_SECRET = process.env.RAZORPAY_WEBHOOK_SECRET || '';
if (NODE_ENV === 'production' && (!process.env.JWT_SECRET || JWT_SECRET.length < 32)) throw new Error('JWT_SECRET must be a strong 32+ character secret in production.');
const otpLimiter = new Map();
const db = new Database(path.join(__dirname, 'learnpro.db'));
db.pragma('foreign_keys = ON');
db.exec(require('fs').readFileSync(path.join(__dirname, 'schema.sql'), 'utf8'));
db.exec(`CREATE TABLE IF NOT EXISTS test_results (id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,course_id INTEGER REFERENCES courses(id) ON DELETE SET NULL,total_questions INTEGER NOT NULL,correct INTEGER NOT NULL,wrong INTEGER NOT NULL,unanswered INTEGER NOT NULL,accuracy REAL NOT NULL,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP); CREATE INDEX IF NOT EXISTS idx_test_results_user ON test_results(user_id);`);
db.exec(`CREATE TABLE IF NOT EXISTS audit_logs (id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,action TEXT NOT NULL,ip TEXT,details TEXT,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP); CREATE INDEX IF NOT EXISTS idx_audit_logs_created ON audit_logs(created_at);`);
function audit(req,action,details=''){ try{ db.prepare('INSERT INTO audit_logs(user_id,action,ip,details) VALUES(?,?,?,?)').run(req.user?.id||null,action,req.ip||'',JSON.stringify(details).slice(0,4000)); }catch(e){} }
try { db.exec("ALTER TABLE users ADD COLUMN active INTEGER NOT NULL DEFAULT 1"); } catch(e) {}
try { db.exec("ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 1"); } catch(e) {}
// Basic security hardening without requiring extra packages.
app.disable('x-powered-by');
app.use((req,res,next)=>{
  res.setHeader('X-Content-Type-Options','nosniff');
  res.setHeader('X-Frame-Options','SAMEORIGIN');
  res.setHeader('Referrer-Policy','strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy','camera=(), microphone=(), geolocation=()');
  if (NODE_ENV === 'production') res.setHeader('Strict-Transport-Security','max-age=31536000; includeSubDomains');
  next();
});
const rateBuckets = new Map();
function rateLimit({windowMs=60000,max=60,keyFn=req=>req.ip||'unknown'}={}){ return (req,res,next)=>{ const key=keyFn(req), now=Date.now(); let b=rateBuckets.get(key); if(!b || now-b.start>=windowMs) b={start:now,count:0}; b.count++; rateBuckets.set(key,b); if(b.count>max){ res.setHeader('Retry-After',Math.ceil((b.start+windowMs-now)/1000)); return res.status(429).json({error:'Too many requests. Please try again later.'}); } next(); }; }
app.use(rateLimit({windowMs:60000,max:120}));
app.post('/api/payments/webhook', express.raw({type:'application/json',limit:'256kb'}), (req,res)=>{ const sig=req.headers['x-razorpay-signature']; if(!verifyWebhookSignature(req.body,sig)) return res.status(400).send('invalid signature'); try{ const event=JSON.parse(req.body.toString('utf8')); const entity=event.payload?.payment?.entity; if(event.event==='payment.captured' && entity?.order_id && entity?.id){ const p=db.prepare("SELECT * FROM payments WHERE provider='razorpay' AND provider_order_id=?").get(entity.order_id); if(p && Number(entity.amount)===Number(p.amount_paise) && entity.currency===RAZORPAY_CURRENCY){ db.prepare("UPDATE payments SET provider_payment_id=?,status='paid' WHERE id=?").run(entity.id,p.id); db.prepare("INSERT INTO enrollments(user_id,course_id,payment_ref,status) VALUES(?,?,?,'active') ON CONFLICT(user_id,course_id) DO UPDATE SET status='active',payment_ref=excluded.payment_ref").run(p.user_id,p.course_id,entity.id); } } if(event.event==='payment.failed' && entity?.order_id){ db.prepare("UPDATE payments SET provider_payment_id=?,status='failed' WHERE provider_order_id=?").run(entity.id||null,entity.order_id); } res.json({ok:true}); }catch(e){res.status(400).send('bad payload');} });
app.use(express.json({limit:'10mb'}));
app.use(express.urlencoded({extended:false,limit:'50kb'}));
app.use(express.static(path.join(__dirname, 'public'),{dotfiles:'deny',index:'index.html'}));
const upload = multer({storage: multer.memoryStorage(), limits:{fileSize: 15*1024*1024, files:1}, fileFilter:(req,file,cb)=>{ const ok=file.mimetype==='text/csv'||file.mimetype==='application/pdf'||/\.(csv|pdf)$/i.test(file.originalname||''); cb(ok?null:new Error('Only CSV or PDF files are allowed.'),ok); }});
const materialUpload = multer({fileFilter:(req,file,cb)=>{ const allowed=['application/pdf','application/msword','application/vnd.openxmlformats-officedocument.wordprocessingml.document','application/vnd.ms-powerpoint','application/vnd.openxmlformats-officedocument.presentationml.presentation','application/vnd.ms-excel','application/vnd.openxmlformats-officedocument.spreadsheetml.sheet','text/plain','image/jpeg','image/png','application/zip','application/x-zip-compressed']; cb(allowed.includes(file.mimetype)||/\.(pdf|doc|docx|ppt|pptx|xls|xlsx|txt|jpg|jpeg|png|zip)$/i.test(file.originalname||'')?null:new Error('Unsupported material file type.'),true);}, storage: multer.diskStorage({destination:(req,file,cb)=>{const dir=path.join(__dirname,'storage','materials');fs.mkdirSync(dir,{recursive:true});cb(null,dir)},filename:(req,file,cb)=>{const safe=String(file.originalname||'file').replace(/[^a-zA-Z0-9._-]+/g,'_');cb(null,`${Date.now()}-${crypto.randomUUID()}-${safe}`)}}), limits:{fileSize:50*1024*1024}});


function issueToken(user, sessionId){ return jwt.sign({sub:user.id, role:user.role, sid:sessionId}, JWT_SECRET, {expiresIn:'7d'}); }
function auth(req,res,next){
  try {
    const h=req.headers.authorization||''; if(!h.startsWith('Bearer ')) throw new Error();
    const p=jwt.verify(h.slice(7), JWT_SECRET);
    const s=db.prepare('SELECT * FROM sessions WHERE id=? AND user_id=? AND revoked_at IS NULL').get(p.sid,p.sub);
    if(!s) return res.status(401).json({error:'Session expired or logged out from another device.'});
    db.prepare("UPDATE sessions SET last_seen_at=CURRENT_TIMESTAMP WHERE id=?").run(s.id);
    req.user=db.prepare('SELECT id,name,email,role,active FROM users WHERE id=?').get(p.sub); if(!req.user || req.user.active===0) return res.status(401).json({error:'Account is inactive.'});
    req.session=s; next();
  } catch { res.status(401).json({error:'Authentication required'}); }
}
function admin(req,res,next){ if(req.user?.role!=='admin') return res.status(403).json({error:'Admin only'}); next(); }


function normalizeEmail(v){ return String(v||'').trim().toLowerCase(); }
function makeOtp(){ return String(crypto.randomInt(100000,1000000)); }
function hashOtp(code){ return crypto.createHash('sha256').update(String(code)+JWT_SECRET).digest('hex'); }
function canSendOtp(email,purpose){ const key=`${purpose}:${email}`; const now=Date.now(); const last=otpLimiter.get(key)||0; if(now-last<60_000) return false; otpLimiter.set(key,now); return true; }
async function sendOtp(email, code, purpose){
  const subject=purpose==='email_verify'?'Verify your LearnPro account':'Reset your LearnPro password';
  const action=purpose==='email_verify'?'verify your email address':'reset your password';
  if(!SMTP_HOST || !SMTP_USER || !SMTP_PASS){ console.log(`[LearnPro OTP] ${purpose} ${email}: ${code}`); return {dev:true,code}; }
  const transporter=nodemailer.createTransport({host:SMTP_HOST,port:SMTP_PORT,secure:SMTP_PORT===465,auth:{user:SMTP_USER,pass:SMTP_PASS}});
  await transporter.sendMail({from:SMTP_FROM,to:email,subject,text:`Your LearnPro verification code is ${code}. Use it to ${action}. It expires in ${OTP_TTL_MINUTES} minutes. Do not share this code.`});
  return {dev:false};
}
async function createOtp(user,purpose){
  if(!canSendOtp(user.email,purpose)) throw new Error('Please wait 60 seconds before requesting another code.');
  const code=makeOtp(); const hash=hashOtp(code);
  db.prepare("UPDATE verification_codes SET used_at=CURRENT_TIMESTAMP WHERE user_id=? AND purpose=? AND used_at IS NULL").run(user.id,purpose);
  db.prepare("INSERT INTO verification_codes(user_id,purpose,code_hash,expires_at) VALUES(?,?,?,?,?)".replace('VALUES(?,?,?,?,?)','VALUES(?,?,?,datetime(\'now\', ?))')).run(user.id,purpose,hash,`+${OTP_TTL_MINUTES} minutes`);
  return sendOtp(user.email,code,purpose);
}
function consumeOtp(userId,purpose,code){
  const row=db.prepare("SELECT * FROM verification_codes WHERE user_id=? AND purpose=? AND used_at IS NULL ORDER BY created_at DESC LIMIT 1").get(userId,purpose);
  if(!row) throw new Error('Verification code not found. Request a new code.');
  if(Date.parse(row.expires_at.replace(' ','T')+'Z') < Date.now()) throw new Error('Verification code has expired.');
  if(row.attempts>=5) throw new Error('Too many attempts. Request a new code.');
  db.prepare('UPDATE verification_codes SET attempts=attempts+1 WHERE id=?').run(row.id);
  if(!crypto.timingSafeEqual(Buffer.from(row.code_hash),Buffer.from(hashOtp(code)))) throw new Error('Invalid verification code.');
  db.prepare('UPDATE verification_codes SET used_at=CURRENT_TIMESTAMP WHERE id=?').run(row.id);
  return true;
}

app.post('/api/auth/register', async (req,res)=>{
  const {name,password}=req.body||{}; const email=normalizeEmail(req.body?.email);
  if(!name||!email||!password||password.length<8) return res.status(400).json({error:'Name, email and password (8+ characters) are required.'});
  try{
    const hash=await bcrypt.hash(password,12);
    const info=db.prepare('INSERT INTO users(name,email,password_hash,role,active,email_verified) VALUES(?,?,?,\'student\',1,0)').run(String(name).trim(),email,hash);
    const user=db.prepare('SELECT id,name,email,role,email_verified FROM users WHERE id=?').get(info.lastInsertRowid);
    let delivery='email'; let result;
    try{ result=await createOtp(user,'email_verify'); delivery=result.dev?'development_log':'email'; }
    catch(e){ db.prepare('DELETE FROM users WHERE id=?').run(user.id); return res.status(503).json({error:e.message||'Could not send verification code.'}); }
    res.status(201).json({requires_verification:true,email:user.email,delivery, ...(NODE_ENV!=='production' && delivery==='development_log' ? {dev_code:result?.code||null} : {}),message:delivery==='development_log'?'Development mode: the verification code is shown on this test screen. Configure SMTP for real email delivery.':'Verification code sent to your email.'});
  }catch(e){ res.status(409).json({error:'Email already registered.'}); }
});

app.post('/api/auth/verify-email', async (req,res)=>{
  const email=normalizeEmail(req.body?.email), code=String(req.body?.code||'').trim();
  const user=db.prepare("SELECT * FROM users WHERE email=? AND role='student'").get(email);
  if(!user) return res.status(400).json({error:'Account not found.'});
  try{ consumeOtp(user.id,'email_verify',code); db.prepare('UPDATE users SET email_verified=1 WHERE id=?').run(user.id); res.json({ok:true,message:'Email verified. You can now log in.'}); }
  catch(e){ res.status(400).json({error:e.message}); }
});

app.post('/api/auth/resend-verification', async (req,res)=>{
  const email=normalizeEmail(req.body?.email); const user=db.prepare("SELECT id,name,email,role,email_verified FROM users WHERE email=? AND role='student'").get(email);
  if(!user) return res.json({ok:true,message:'If the account exists, a verification code has been sent.'});
  if(user.email_verified) return res.json({ok:true,message:'Email is already verified.'});
  try{ const result=await createOtp(user,'email_verify'); res.json({ok:true,delivery:result.dev?'development_log':'email'}); }catch(e){res.status(429).json({error:e.message});}
});

app.post('/api/auth/request-password-reset', async (req,res)=>{
  const email=normalizeEmail(req.body?.email); const user=db.prepare("SELECT id,name,email,role FROM users WHERE email=? AND role='student'").get(email);
  if(!user) return res.json({ok:true,message:'If the account exists, a reset code has been sent.'});
  try{ const result=await createOtp(user,'password_reset'); res.json({ok:true,delivery:result.dev?'development_log':'email',...(NODE_ENV!=='production' && result.dev ? {dev_code:result.code} : {}),message:'If the account exists, a reset code has been sent.'}); }catch(e){res.status(429).json({error:e.message});}
});

app.post('/api/auth/reset-password', async (req,res)=>{
  const email=normalizeEmail(req.body?.email), code=String(req.body?.code||'').trim(), password=String(req.body?.password||'');
  if(password.length<8) return res.status(400).json({error:'New password must be at least 8 characters.'});
  const user=db.prepare("SELECT * FROM users WHERE email=? AND role='student'").get(email);
  if(!user) return res.status(400).json({error:'Invalid reset request.'});
  try{ consumeOtp(user.id,'password_reset',code); const hash=await bcrypt.hash(password,12); db.prepare('UPDATE users SET password_hash=? WHERE id=?').run(hash,user.id); db.prepare('UPDATE sessions SET revoked_at=CURRENT_TIMESTAMP WHERE user_id=? AND revoked_at IS NULL').run(user.id); res.json({ok:true,message:'Password reset successfully. Please log in again.'}); }
  catch(e){res.status(400).json({error:e.message});}
});

app.post('/api/auth/free-test-student', rateLimit({windowMs:60000,max:10}), async (req,res)=>{
  if(NODE_ENV==='production') return res.status(404).json({error:'Free test access is disabled in production.'});
  const email='test.student@learnpro.local';
  let user=db.prepare("SELECT * FROM users WHERE email=? AND role='student'").get(email);
  if(!user){
    const hash=await bcrypt.hash('LearnProTest123!',10);
    const info=db.prepare("INSERT INTO users(name,email,password_hash,role,active,email_verified) VALUES(?,?,?,?,1,1)").run('Test Student',email,hash,'student');
    user=db.prepare('SELECT * FROM users WHERE id=?').get(info.lastInsertRowid);
  } else if(!user.email_verified || !user.active){ db.prepare('UPDATE users SET active=1,email_verified=1 WHERE id=?').run(user.id); user=db.prepare('SELECT * FROM users WHERE id=?').get(user.id); }
  const active=db.prepare("SELECT id FROM sessions WHERE user_id=? AND revoked_at IS NULL ORDER BY created_at ASC").all(user.id);
  if(active.length>=2) db.prepare("UPDATE sessions SET revoked_at=CURRENT_TIMESTAMP WHERE id=?").run(active[0].id);
  const sessionId=crypto.randomUUID(); db.prepare('INSERT INTO sessions(id,user_id,device_label) VALUES(?,?,?)').run(sessionId,user.id,'Free test browser');
  const safe={id:user.id,name:user.name,email:user.email,role:user.role};
  res.json({user:safe,token:issueToken(safe,sessionId),test_account:true,message:'Free test student session created.'});
});

app.post('/api/auth/login', rateLimit({windowMs:15*60*1000,max:20,keyFn:req=>`${req.ip||'unknown'}:${normalizeEmail(req.body?.email)}`}), async (req,res)=>{
  const {email,password}=req.body||{}; const user=db.prepare('SELECT * FROM users WHERE email=?').get((email||'').toLowerCase());
  if(!user || !(await bcrypt.compare(password||'',user.password_hash))) return res.status(401).json({error:'Invalid email or password.'});
  if(user.role==='student' && user.email_verified===0) return res.status(403).json({error:'Please verify your email before logging in.',code:'EMAIL_NOT_VERIFIED'});
  const active=db.prepare("SELECT id FROM sessions WHERE user_id=? AND revoked_at IS NULL ORDER BY created_at ASC").all(user.id);
  if(active.length>=2){ const oldest=active[0].id; db.prepare("UPDATE sessions SET revoked_at=CURRENT_TIMESTAMP WHERE id=?").run(oldest); }
  const sessionId=crypto.randomUUID(); db.prepare('INSERT INTO sessions(id,user_id,device_label) VALUES(?,?,?)').run(sessionId,user.id,req.headers['user-agent']||'Browser');
  const safe={id:user.id,name:user.name,email:user.email,role:user.role}; res.json({user:safe,token:issueToken(safe,sessionId)});
});

app.post('/api/auth/logout',auth,(req,res)=>{db.prepare('UPDATE sessions SET revoked_at=CURRENT_TIMESTAMP WHERE id=?').run(req.session.id); audit(req,'logout'); res.json({ok:true});});
app.get('/api/me',auth,(req,res)=>res.json({user:req.user}));

app.get('/api/notifications',auth,(req,res)=>{
  const rows=db.prepare(`SELECT id,title,message,type,course_id,created_at,read_at FROM notifications WHERE user_id=? ORDER BY created_at DESC LIMIT 50`).all(req.user.id);
  res.json({notifications:rows,unread:rows.filter(x=>!x.read_at).length});
});
app.post('/api/notifications/:id/read',auth,(req,res)=>{
  db.prepare("UPDATE notifications SET read_at=CURRENT_TIMESTAMP WHERE id=? AND user_id=?").run(req.params.id,req.user.id);
  res.json({ok:true});
});
app.post('/api/admin/notifications',auth,admin,(req,res)=>{
  const {title,message,type='announcement',course_id=null,user_ids=null}=req.body||{};
  if(!title||!message) return res.status(400).json({error:'Title and message are required.'});
  let ids;
  if(Array.isArray(user_ids)&&user_ids.length) ids=user_ids.map(Number).filter(Number.isInteger);
  else ids=db.prepare("SELECT id FROM users WHERE role='student'").all().map(x=>x.id);
  const stmt=db.prepare('INSERT INTO notifications(user_id,title,message,type,course_id) VALUES(?,?,?,?,?)');
  const tx=db.transaction(()=>ids.forEach(id=>stmt.run(id,title,message,type,course_id)));
  tx(); res.json({ok:true,sent:ids.length});
});
app.get('/api/devices',auth,(req,res)=>res.json(db.prepare("SELECT id,device_label,created_at,last_seen_at,(id=?) AS current FROM sessions WHERE user_id=? AND revoked_at IS NULL ORDER BY last_seen_at DESC").all(req.session.id,req.user.id)));
app.delete('/api/devices/:id',auth,(req,res)=>{const r=db.prepare("UPDATE sessions SET revoked_at=CURRENT_TIMESTAMP WHERE id=? AND user_id=? AND revoked_at IS NULL").run(req.params.id,req.user.id);res.json({ok:r.changes>0});});

function razorpayRequest(method, pathName, body){
  return new Promise((resolve,reject)=>{
    if(!RAZORPAY_KEY_ID || !RAZORPAY_KEY_SECRET) return reject(new Error('Razorpay keys are not configured.'));
    const data=body?JSON.stringify(body):'';
    const auth=Buffer.from(`${RAZORPAY_KEY_ID}:${RAZORPAY_KEY_SECRET}`).toString('base64');
    const req=https.request({hostname:'api.razorpay.com',path:pathName,method,headers:{'Authorization':`Basic ${auth}`,'Content-Type':'application/json','Content-Length':Buffer.byteLength(data)}},r=>{
      let out=''; r.on('data',d=>out+=d); r.on('end',()=>{try{const j=JSON.parse(out); if(r.statusCode>=200&&r.statusCode<300) resolve(j); else reject(new Error(j.error?.description||'Razorpay API error'));}catch(e){reject(e)}});
    });
    req.on('error',reject); if(data) req.write(data); req.end();
  });
}


async function razorpayPayment(paymentId){ return razorpayRequest('GET',`/v1/payments/${encodeURIComponent(paymentId)}`); }
function verifyWebhookSignature(rawBody,signature){ if(!RAZORPAY_WEBHOOK_SECRET||!signature) return false; const expected=crypto.createHmac('sha256',RAZORPAY_WEBHOOK_SECRET).update(rawBody).digest('hex'); return crypto.timingSafeEqual(Buffer.from(expected),Buffer.from(String(signature))); }

app.post('/api/payments/create-order',auth,async(req,res)=>{
  try{
    const {course_id}=req.body||{};
    const c=db.prepare('SELECT id,title,price_paise FROM courses WHERE id=? AND published=1').get(course_id);
    if(!c) return res.status(404).json({error:'Course not found'});
    if(!Number.isInteger(c.price_paise)||c.price_paise<=0) return res.status(400).json({error:'Course price must be greater than zero.'});
    if(db.prepare("SELECT 1 FROM enrollments WHERE user_id=? AND course_id=? AND status='active'").get(req.user.id,c.id)) return res.status(409).json({error:'Course is already unlocked.'});
    const receipt=`lp_${req.user.id}_${c.id}_${Date.now()}`;
    const order=await razorpayRequest('POST','/v1/orders',{amount:c.price_paise,currency:RAZORPAY_CURRENCY,receipt,notes:{user_id:String(req.user.id),course_id:String(c.id)}});
    db.prepare('INSERT INTO payments(user_id,course_id,provider,provider_order_id,amount_paise,status) VALUES(?,?,?,?,?,?)').run(req.user.id,c.id,'razorpay',order.id,c.price_paise,'created');
    res.json({key_id:RAZORPAY_KEY_ID,order_id:order.id,amount:order.amount,currency:order.currency,course:{id:c.id,title:c.title}});
  }catch(e){res.status(503).json({error:e.message||'Payment gateway is not configured.'});}
});

app.post('/api/payments/verify',auth,async(req,res)=>{
  try{
    const {razorpay_order_id,razorpay_payment_id,razorpay_signature}=req.body||{};
    if(!razorpay_order_id||!razorpay_payment_id||!razorpay_signature) return res.status(400).json({error:'Incomplete payment response.'});
    const payment=db.prepare("SELECT * FROM payments WHERE provider='razorpay' AND provider_order_id=? AND user_id=?").get(razorpay_order_id,req.user.id);
    if(!payment) return res.status(404).json({error:'Payment order not found.'});
    if(!RAZORPAY_KEY_SECRET) return res.status(503).json({error:'Payment verification is not configured.'});
    const expected=crypto.createHmac('sha256',RAZORPAY_KEY_SECRET).update(`${razorpay_order_id}|${razorpay_payment_id}`).digest('hex');
    if(expected.length!==String(razorpay_signature).length || !crypto.timingSafeEqual(Buffer.from(expected),Buffer.from(String(razorpay_signature)))) return res.status(400).json({error:'Payment signature verification failed.'});
    const rp=await razorpayPayment(razorpay_payment_id);
    if(rp.order_id!==razorpay_order_id || Number(rp.amount)!==Number(payment.amount_paise) || rp.currency!==RAZORPAY_CURRENCY || rp.status!=='captured') return res.status(400).json({error:'Payment is not captured or does not match the order.'});
    db.prepare("UPDATE payments SET provider_payment_id=?,status='paid' WHERE id=?").run(razorpay_payment_id,payment.id);
    audit(req,'payment_verified',{course_id:payment.course_id,order_id:razorpay_order_id,payment_id:razorpay_payment_id});
    db.prepare("INSERT INTO enrollments(user_id,course_id,payment_ref,status) VALUES(?,?,?,'active') ON CONFLICT(user_id,course_id) DO UPDATE SET status='active',payment_ref=excluded.payment_ref").run(req.user.id,payment.course_id,razorpay_payment_id);
    res.json({ok:true,course_id:payment.course_id,message:'Payment verified and course unlocked.'});
  }catch(e){res.status(400).json({error:'Could not verify payment.'});}
});

app.get('/api/admin/analytics',auth,admin,(req,res)=>{
  const students=db.prepare("SELECT COUNT(*) n FROM users WHERE role='student'").get().n;
  const courses=db.prepare('SELECT COUNT(*) n FROM courses').get().n;
  const published_courses=db.prepare('SELECT COUNT(*) n FROM courses WHERE published=1').get().n;
  const enrollments=db.prepare("SELECT COUNT(*) n FROM enrollments WHERE status='active'").get().n;
  const revenue=db.prepare("SELECT COALESCE(SUM(amount_paise),0) n FROM payments WHERE status='paid'").get().n;
  const payments_paid=db.prepare("SELECT COUNT(*) n FROM payments WHERE status='paid'").get().n;
  const payments_failed=db.prepare("SELECT COUNT(*) n FROM payments WHERE status IN ('failed','cancelled')").get().n;
  const lessons=db.prepare('SELECT COUNT(*) n FROM lessons').get().n;
  const mcqs=db.prepare('SELECT COUNT(*) n FROM mcqs').get().n;
  const materials=db.prepare('SELECT COUNT(*) n FROM materials').get().n;
  const demo_lessons=db.prepare('SELECT COUNT(*) n FROM lessons WHERE is_demo=1').get().n;
  const demo_mcqs=db.prepare('SELECT COUNT(*) n FROM mcqs WHERE is_demo=1').get().n;
  const demo_materials=db.prepare('SELECT COUNT(*) n FROM materials WHERE is_demo=1').get().n;
  const test_attempts=db.prepare('SELECT COUNT(*) n FROM test_results').get().n;
  const avg_accuracy=(db.prepare('SELECT AVG(accuracy) n FROM test_results').get().n||0);
  const recent=db.prepare(`SELECT p.id,u.name,u.email,c.title,p.amount_paise,p.status,p.created_at FROM payments p JOIN users u ON u.id=p.user_id JOIN courses c ON c.id=p.course_id ORDER BY p.id DESC LIMIT 8`).all();
  const top_courses=db.prepare(`SELECT c.id,c.title,COUNT(e.id) enrollments,COALESCE(SUM(CASE WHEN p.status='paid' THEN p.amount_paise ELSE 0 END),0) revenue_paise FROM courses c LEFT JOIN enrollments e ON e.course_id=c.id AND e.status='active' LEFT JOIN payments p ON p.course_id=c.id GROUP BY c.id ORDER BY enrollments DESC,c.id DESC LIMIT 8`).all();
  const activity=db.prepare(`SELECT DATE(updated_at) day,COUNT(*) completed_lessons FROM lesson_progress WHERE completed=1 GROUP BY DATE(updated_at) ORDER BY day DESC LIMIT 7`).all().reverse();
  res.json({students,courses,published_courses,enrollments,revenue_paise:revenue,payments_paid,payments_failed,lessons,mcqs,materials,demo_content:demo_lessons+demo_mcqs+demo_materials,test_attempts,avg_accuracy:Math.round(avg_accuracy*10)/10,recent,top_courses,activity});
});


app.get('/api/admin/students',auth,admin,(req,res)=>{
  const q=String(req.query.q||'').trim();
  const rows=db.prepare(`SELECT u.id,u.name,u.email,u.active,u.created_at,
    (SELECT COUNT(*) FROM enrollments e WHERE e.user_id=u.id AND e.status='active') AS enrollments,
    (SELECT COUNT(*) FROM payments p WHERE p.user_id=u.id AND p.status='paid') AS paid_payments,
    (SELECT COALESCE(SUM(p.amount_paise),0) FROM payments p WHERE p.user_id=u.id AND p.status='paid') AS paid_paise,
    (SELECT COUNT(*) FROM lesson_progress lp WHERE lp.user_id=u.id AND lp.completed=1) AS completed_lessons,
    (SELECT COUNT(*) FROM test_results tr WHERE tr.user_id=u.id) AS test_attempts,
    (SELECT COALESCE(ROUND(AVG(tr.accuracy),1),0) FROM test_results tr WHERE tr.user_id=u.id) AS avg_accuracy,
    (SELECT COUNT(*) FROM sessions se WHERE se.user_id=u.id AND se.revoked_at IS NULL) AS active_devices,
    (SELECT MAX(se.last_seen_at) FROM sessions se WHERE se.user_id=u.id) AS last_active
    FROM users u WHERE u.role='student' AND (?='' OR u.name LIKE ? OR u.email LIKE ?) ORDER BY u.id DESC LIMIT 200`).all(q,`%${q}%`,`%${q}%`);
  res.json(rows);
});
app.get('/api/admin/students/:id',auth,admin,(req,res)=>{
  const id=Number(req.params.id); const u=db.prepare(`SELECT id,name,email,active,created_at FROM users WHERE id=? AND role='student'`).get(id);
  if(!u)return res.status(404).json({error:'Student not found'});
  u.courses=db.prepare(`SELECT c.id,c.title,e.status,e.created_at enrolled_at,(SELECT COUNT(*) FROM lessons l JOIN chapters ch ON ch.id=l.chapter_id WHERE ch.course_id=c.id) total_lessons,(SELECT COUNT(*) FROM lesson_progress lp JOIN lessons l ON l.id=lp.lesson_id JOIN chapters ch ON ch.id=l.chapter_id WHERE lp.user_id=? AND ch.course_id=c.id AND lp.completed=1) completed_lessons FROM enrollments e JOIN courses c ON c.id=e.course_id WHERE e.user_id=? ORDER BY e.id DESC`).all(id,id);
  u.payments=db.prepare(`SELECT p.*,c.title FROM payments p JOIN courses c ON c.id=p.course_id WHERE p.user_id=? ORDER BY p.id DESC LIMIT 50`).all(id);
  u.devices=db.prepare(`SELECT id,device_label,created_at,last_seen_at,revoked_at FROM sessions WHERE user_id=? ORDER BY revoked_at IS NULL DESC,last_seen_at DESC`).all(id);
  u.tests=db.prepare(`SELECT tr.*,c.title FROM test_results tr LEFT JOIN courses c ON c.id=tr.course_id WHERE tr.user_id=? ORDER BY tr.id DESC LIMIT 20`).all(id);
  res.json(u);
});
app.patch('/api/admin/students/:id/status',auth,admin,(req,res)=>{
  const id=Number(req.params.id), active=req.body?.active?1:0; const r=db.prepare("UPDATE users SET active=? WHERE id=? AND role='student'").run(active,id);
  if(!r.changes)return res.status(404).json({error:'Student not found'}); if(!active) db.prepare("UPDATE sessions SET revoked_at=CURRENT_TIMESTAMP WHERE user_id=? AND revoked_at IS NULL").run(id); res.json({ok:true,active:!!active});
});
app.post('/api/admin/students/:id/courses',auth,admin,(req,res)=>{
  const id=Number(req.params.id), courseId=Number(req.body?.course_id); if(!db.prepare("SELECT 1 FROM users WHERE id=? AND role='student'").get(id))return res.status(404).json({error:'Student not found'}); if(!db.prepare('SELECT 1 FROM courses WHERE id=?').get(courseId))return res.status(404).json({error:'Course not found'});
  db.prepare("INSERT INTO enrollments(user_id,course_id,status) VALUES(?,?, 'active') ON CONFLICT(user_id,course_id) DO UPDATE SET status='active'").run(id,courseId); res.json({ok:true});
});
app.delete('/api/admin/students/:id/courses/:courseId',auth,admin,(req,res)=>{const r=db.prepare("UPDATE enrollments SET status='revoked' WHERE user_id=? AND course_id=?").run(Number(req.params.id),Number(req.params.courseId));res.json({ok:true,changed:r.changes});});
app.post('/api/admin/students/:id/logout-all',auth,admin,(req,res)=>{const r=db.prepare("UPDATE sessions SET revoked_at=CURRENT_TIMESTAMP WHERE user_id=? AND revoked_at IS NULL").run(Number(req.params.id));res.json({ok:true,revoked:r.changes});});

app.get('/api/payments',auth,(req,res)=>{
  const rows=req.user.role==='admin' ? db.prepare('SELECT p.*,u.name,u.email,c.title FROM payments p JOIN users u ON u.id=p.user_id JOIN courses c ON c.id=p.course_id ORDER BY p.id DESC').all() : db.prepare('SELECT p.*,c.title FROM payments p JOIN courses c ON c.id=p.course_id WHERE p.user_id=? ORDER BY p.id DESC').all(req.user.id);
  res.json(rows);
});


app.get('/api/courses', (req,res)=>{
 const rows=db.prepare('SELECT id,title,description,price_paise,published FROM courses WHERE published=1 ORDER BY id DESC').all(); res.json(rows);
});
app.get('/api/student/dashboard',auth,(req,res)=>{
  if(req.user.role!=='student') return res.status(403).json({error:'Student only'});
  const enrolled=db.prepare(`SELECT c.id,c.title,c.description,c.price_paise,e.created_at AS enrolled_at
    FROM enrollments e JOIN courses c ON c.id=e.course_id WHERE e.user_id=? AND e.status='active' ORDER BY e.created_at DESC`).all(req.user.id);
  const courses=enrolled.map(c=>{
    const total=db.prepare('SELECT COUNT(*) AS n FROM lessons l JOIN chapters ch ON ch.id=l.chapter_id WHERE ch.course_id=?').get(c.id).n;
    const done=db.prepare(`SELECT COUNT(*) AS n FROM lesson_progress lp JOIN lessons l ON l.id=lp.lesson_id JOIN chapters ch ON ch.id=l.chapter_id WHERE lp.user_id=? AND lp.completed=1 AND ch.course_id=?`).get(req.user.id,c.id).n;
    return {...c, total_lessons:total, completed_lessons:done, progress_percent: total?Math.round(done*100/total):0};
  });
  const tests=db.prepare('SELECT COUNT(*) AS n FROM test_results WHERE user_id=?').get(req.user.id).n;
  const avgRow=db.prepare('SELECT AVG(accuracy) AS avg_accuracy FROM test_results WHERE user_id=?').get(req.user.id);
  const avg_accuracy=avgRow && avgRow.avg_accuracy!=null ? Math.round(avgRow.avg_accuracy*10)/10 : 0;
  const recent=db.prepare(`SELECT l.id AS lesson_id,l.title AS lesson_title,ch.title AS chapter_title,ch.course_id,c.title AS course_title,COALESCE(lp.completed,0) AS completed
    FROM lessons l JOIN chapters ch ON ch.id=l.chapter_id JOIN courses c ON c.id=ch.course_id
    JOIN enrollments e ON e.course_id=c.id AND e.user_id=? AND e.status='active'
    LEFT JOIN lesson_progress lp ON lp.lesson_id=l.id AND lp.user_id=?
    WHERE COALESCE(lp.completed,0)=0 ORDER BY ch.course_id,l.sort_order,l.id LIMIT 1`).get(req.user.id,req.user.id);
  const hoursRow=db.prepare(`SELECT COALESCE(SUM(CASE WHEN completed=1 THEN 0.5 ELSE 0 END),0) AS hours FROM lesson_progress WHERE user_id=?`).get(req.user.id);
  res.json({courses,tests_attempted:tests,avg_accuracy,hours_learned:Number(hoursRow.hours||0),recent_lesson:recent||null});
});

app.post('/api/student/lessons/:id/progress',auth,(req,res)=>{
  if(req.user.role!=='student') return res.status(403).json({error:'Student only'});
  const lesson=db.prepare('SELECT l.id,ch.course_id FROM lessons l JOIN chapters ch ON ch.id=l.chapter_id WHERE l.id=?').get(req.params.id);
  if(!lesson) return res.status(404).json({error:'Lesson not found'});
  const enrolled=db.prepare("SELECT 1 FROM enrollments WHERE user_id=? AND course_id=? AND status='active'").get(req.user.id,lesson.course_id);
  if(!enrolled && !db.prepare('SELECT is_demo FROM lessons WHERE id=?').get(lesson.id)?.is_demo) return res.status(403).json({error:'Course access required'});
  const completed=req.body?.completed?1:0;
  db.prepare(`INSERT INTO lesson_progress(user_id,lesson_id,completed) VALUES(?,?,?)
    ON CONFLICT(user_id,lesson_id) DO UPDATE SET completed=excluded.completed,updated_at=CURRENT_TIMESTAMP`).run(req.user.id,lesson.id,completed);
  res.json({ok:true,lesson_id:lesson.id,completed:!!completed});
});


// Student MCQ/Test Engine v2
app.get('/api/student/mcq-bank',auth,(req,res)=>{
  if(req.user.role!=='student') return res.status(403).json({error:'Student only'});
  const courseId=Number(req.query.course_id)||null, chapterId=Number(req.query.chapter_id)||null;
  if(!courseId) return res.status(400).json({error:'course_id is required'});
  const enrolled=!!db.prepare("SELECT 1 FROM enrollments WHERE user_id=? AND course_id=? AND status='active'").get(req.user.id,courseId);
  let sql=`SELECT id,chapter_id,question,option_a,option_b,option_c,option_d,is_demo FROM mcqs WHERE course_id=? AND (is_demo=1 OR ?)`;
  const args=[courseId,enrolled?1:0];
  if(chapterId){sql+=' AND chapter_id=?';args.push(chapterId)}
  sql+=' ORDER BY id';
  res.json({enrolled,questions:db.prepare(sql).all(...args)});
});

app.post('/api/student/tests/start',auth,(req,res)=>{
  if(req.user.role!=='student') return res.status(403).json({error:'Student only'});
  const {course_id,chapter_id=null,mode='full',limit=null}=req.body||{};
  const courseId=Number(course_id)||null;
  if(!courseId)return res.status(400).json({error:'course_id is required'});
  const enrolled=!!db.prepare("SELECT 1 FROM enrollments WHERE user_id=? AND course_id=? AND status='active'").get(req.user.id,courseId);
  const isDemo=String(mode).toLowerCase()==='demo';
  if(!isDemo&&!enrolled)return res.status(403).json({error:'Full tests require course access.'});
  const max=Math.min(Math.max(Number(limit)|| (isDemo?10:20),1),100);
  let sql=`SELECT id,chapter_id,question,option_a,option_b,option_c,option_d FROM mcqs WHERE course_id=? AND (is_demo=1 OR ?)`;
  const args=[courseId,enrolled?1:0];
  if(chapter_id){sql+=' AND chapter_id=?';args.push(Number(chapter_id))}
  sql+=' ORDER BY RANDOM() LIMIT ?';args.push(max);
  const questions=db.prepare(sql).all(...args);
  res.json({test_id:crypto.randomUUID(),course_id:courseId,chapter_id:chapter_id?Number(chapter_id):null,mode:isDemo?'demo':'full',duration_minutes:isDemo?10:20,questions});
});

app.post('/api/student/tests/submit',auth,(req,res)=>{
  if(req.user.role!=='student')return res.status(403).json({error:'Student only'});
  const {course_id,question_ids,answers}=req.body||{}; const courseId=Number(course_id)||null;
  if(!courseId||!Array.isArray(question_ids)||!question_ids.length)return res.status(400).json({error:'Course and question IDs are required.'});
  const ids=question_ids.map(Number).filter(Number.isInteger);
  if(ids.length!==question_ids.length)return res.status(400).json({error:'Invalid question IDs.'});
  const enrolled=!!db.prepare("SELECT 1 FROM enrollments WHERE user_id=? AND course_id=? AND status='active'").get(req.user.id,courseId);
  const placeholders=ids.map(()=>'?').join(',');
  const qs=db.prepare(`SELECT id,course_id,question,option_a,option_b,option_c,option_d,correct_option,explanation,is_demo FROM mcqs WHERE course_id=? AND id IN (${placeholders})`).all(courseId,...ids);
  if(qs.length!==ids.length)return res.status(400).json({error:'One or more questions are invalid for this course.'});
  if(!enrolled && qs.some(q=>!q.is_demo))return res.status(403).json({error:'Premium questions require course access.'});
  const amap=answers&&typeof answers==='object'?answers:{}; let correct=0,answered=0;
  const review=qs.map(q=>{const raw=amap[String(q.id)];const ans=raw==null?'':String(raw).toUpperCase();const ok=!!ans&&ans===q.correct_option;if(ans)answered++;if(ok)correct++;return {id:q.id,question:q.question,options:{A:q.option_a,B:q.option_b,C:q.option_c,D:q.option_d},your_answer:ans||null,correct_option:q.correct_option,correct:ok,explanation:q.explanation||''};});
  const total=qs.length,wrong=answered-correct,unanswered=total-answered,accuracy=total?Math.round(correct/total*10000)/100:0;
  const info=db.prepare('INSERT INTO test_results(user_id,course_id,total_questions,correct,wrong,unanswered,accuracy) VALUES(?,?,?,?,?,?,?)').run(req.user.id,courseId,total,correct,wrong,unanswered,accuracy);
  res.json({result_id:info.lastInsertRowid,course_id:courseId,total_questions:total,correct,wrong,unanswered,accuracy,review});
});

app.get('/api/student/tests/history',auth,(req,res)=>{
  if(req.user.role!=='student')return res.status(403).json({error:'Student only'});
  const courseId=Number(req.query.course_id)||null;
  let sql=`SELECT tr.*,c.title AS course_title FROM test_results tr LEFT JOIN courses c ON c.id=tr.course_id WHERE tr.user_id=?`;
  const args=[req.user.id]; if(courseId){sql+=' AND tr.course_id=?';args.push(courseId)} sql+=' ORDER BY tr.created_at DESC LIMIT 100';
  res.json({results:db.prepare(sql).all(...args)});
});

app.get('/api/student/tests/:id',auth,(req,res)=>{
  if(req.user.role!=='student')return res.status(403).json({error:'Student only'});
  const r=db.prepare('SELECT tr.*,c.title AS course_title FROM test_results tr LEFT JOIN courses c ON c.id=tr.course_id WHERE tr.id=? AND tr.user_id=?').get(req.params.id,req.user.id);
  if(!r)return res.status(404).json({error:'Test result not found'}); res.json({result:r});
});

app.get('/api/student/progress/:courseId',auth,(req,res)=>{
 if(req.user.role!=='student') return res.status(403).json({error:'Student only'});
 const courseId=Number(req.params.courseId);
 const allowed=!!db.prepare("SELECT 1 FROM enrollments WHERE user_id=? AND course_id=? AND status='active'").get(req.user.id,courseId);
 if(!allowed) return res.status(403).json({error:'Course access required'});
 const rows=db.prepare(`SELECT lp.lesson_id,lp.completed,lp.updated_at,l.chapter_id FROM lesson_progress lp JOIN lessons l ON l.id=lp.lesson_id JOIN chapters ch ON ch.id=l.chapter_id WHERE lp.user_id=? AND ch.course_id=?`).all(req.user.id,courseId);
 const total=db.prepare('SELECT COUNT(*) n FROM lessons l JOIN chapters ch ON ch.id=l.chapter_id WHERE ch.course_id=?').get(courseId).n;
 const completed=rows.filter(r=>r.completed).length;
 res.json({course_id:courseId,total_lessons:total,completed_lessons:completed,percentage:total?Math.round(completed/total*100):0,lessons:rows});
});
app.post('/api/student/progress',auth,(req,res)=>{
 if(req.user.role!=='student') return res.status(403).json({error:'Student only'});
 const lessonId=Number(req.body?.lesson_id); const completed=req.body?.completed?1:0;
 const lesson=db.prepare('SELECT l.id,ch.course_id,l.is_demo FROM lessons l JOIN chapters ch ON ch.id=l.chapter_id WHERE l.id=?').get(lessonId);
 if(!lesson) return res.status(404).json({error:'Lesson not found'});
 const allowed=lesson.is_demo || !!db.prepare("SELECT 1 FROM enrollments WHERE user_id=? AND course_id=? AND status='active'").get(req.user.id,lesson.course_id);
 if(!allowed) return res.status(403).json({error:'Course access required'});
 db.prepare(`INSERT INTO lesson_progress(user_id,lesson_id,completed,updated_at) VALUES(?,?,?,CURRENT_TIMESTAMP) ON CONFLICT(user_id,lesson_id) DO UPDATE SET completed=excluded.completed,updated_at=CURRENT_TIMESTAMP`).run(req.user.id,lessonId,completed);
 res.json({ok:true,lesson_id:lessonId,completed:!!completed});
});

app.patch('/api/me',auth,async(req,res)=>{try{const name=String(req.body?.name||'').trim();if(!name)return res.status(400).json({error:'Name is required.'});db.prepare('UPDATE users SET name=? WHERE id=?').run(name,req.user.id);res.json({ok:true,user:db.prepare('SELECT id,name,email,role,active FROM users WHERE id=?').get(req.user.id)});}catch(e){res.status(400).json({error:'Could not update profile.'});}});
app.post('/api/auth/change-password',auth,async(req,res)=>{try{const current=String(req.body?.current_password||''),next=String(req.body?.new_password||'');if(next.length<8)return res.status(400).json({error:'New password must be at least 8 characters.'});const u=db.prepare('SELECT password_hash FROM users WHERE id=?').get(req.user.id);if(!u||!(await bcrypt.compare(current,u.password_hash)))return res.status(400).json({error:'Current password is incorrect.'});const hash=await bcrypt.hash(next,12);db.prepare('UPDATE users SET password_hash=? WHERE id=?').run(hash,req.user.id);db.prepare('UPDATE sessions SET revoked_at=CURRENT_TIMESTAMP WHERE user_id=? AND id<>? AND revoked_at IS NULL').run(req.user.id,req.session.id);audit(req,'password_changed');res.json({ok:true,message:'Password changed. Other active sessions were logged out.'});}catch(e){res.status(400).json({error:'Could not change password.'});}});
app.get('/api/student/payments',auth,(req,res)=>{const rows=db.prepare(`SELECT p.id,p.amount_paise,p.status,p.provider_order_id,p.provider_payment_id,p.created_at,c.title FROM payments p JOIN courses c ON c.id=p.course_id WHERE p.user_id=? ORDER BY p.id DESC`).all(req.user.id);res.json({payments:rows});});
app.get('/api/student/materials',auth,(req,res)=>{const rows=db.prepare(`SELECT m.id,m.title,m.is_demo,m.file_url,c.id course_id,c.title course_title FROM materials m JOIN courses c ON c.id=m.course_id WHERE m.is_demo=1 OR EXISTS(SELECT 1 FROM enrollments e WHERE e.user_id=? AND e.course_id=m.course_id AND e.status='active') ORDER BY m.id DESC`).all(req.user.id);res.json({materials:rows});});
app.get('/api/public/config',(req,res)=>res.json({razorpay_enabled:Boolean(RAZORPAY_KEY_ID&&RAZORPAY_KEY_SECRET)}));
app.get('/api/public/courses',(req,res)=>{
  const courses=db.prepare(`SELECT id,title,description,price_paise,published FROM courses WHERE published=1 ORDER BY id DESC`).all();
  res.json({courses});
});
app.get('/api/public/courses/:id',(req,res)=>{
  const c=db.prepare('SELECT id,title,description,price_paise,published FROM courses WHERE id=? AND published=1').get(req.params.id);
  if(!c)return res.status(404).json({error:'Course not found'});
  const chapters=db.prepare('SELECT id,title,sort_order FROM chapters WHERE course_id=? ORDER BY sort_order,id').all(c.id).map(ch=>({...ch,lessons:db.prepare('SELECT id,title,is_demo,sort_order FROM lessons WHERE chapter_id=? ORDER BY sort_order,id').all(ch.id)}));
  const materials=db.prepare('SELECT id,title,is_demo FROM materials WHERE course_id=? AND is_demo=1 ORDER BY id DESC').all(c.id);
  const mcqCount=db.prepare('SELECT COUNT(*) n FROM mcqs WHERE course_id=? AND is_demo=1').get(c.id).n;
  res.json({course:c,chapters,materials,mcq_count:mcqCount});
});

app.get('/api/courses/:id',auth,(req,res)=>{
 const c=db.prepare('SELECT * FROM courses WHERE id=? AND published=1').get(req.params.id); if(!c) return res.status(404).json({error:'Course not found'});
 const enrolled=!!db.prepare("SELECT 1 FROM enrollments WHERE user_id=? AND course_id=? AND status='active'").get(req.user.id,c.id);
 const chapters=db.prepare('SELECT * FROM chapters WHERE course_id=? ORDER BY sort_order,id').all(c.id).map(ch=>({...ch,lessons:db.prepare(`SELECT l.id,l.title,l.is_demo,l.sort_order,CASE WHEN l.is_demo=1 OR ? THEN l.video_url ELSE NULL END video_url,COALESCE(lp.completed,0) completed FROM lessons l LEFT JOIN lesson_progress lp ON lp.lesson_id=l.id AND lp.user_id=? WHERE l.chapter_id=? ORDER BY l.sort_order,l.id`).all(enrolled,req.user.id,ch.id)}));
 const mcqs=db.prepare('SELECT id,chapter_id,question,option_a,option_b,option_c,option_d,correct_option,explanation,is_demo FROM mcqs WHERE course_id=? AND (is_demo=1 OR ?) ORDER BY id').all(c.id,enrolled);
 const materials=db.prepare('SELECT id,title,is_demo,CASE WHEN is_demo=1 OR ? THEN file_url ELSE NULL END file_url FROM materials WHERE course_id=? AND (is_demo=1 OR ?)').all(enrolled,c.id,enrolled);
 const totalLessons=db.prepare('SELECT COUNT(*) n FROM lessons l JOIN chapters ch ON ch.id=l.chapter_id WHERE ch.course_id=?').get(c.id).n; const completedLessons=db.prepare('SELECT COUNT(*) n FROM lesson_progress lp JOIN lessons l ON l.id=lp.lesson_id JOIN chapters ch ON ch.id=l.chapter_id WHERE lp.user_id=? AND ch.course_id=? AND lp.completed=1').get(req.user.id,c.id).n; const progress=totalLessons?Math.round(completedLessons/totalLessons*100):0; res.json({course:c,enrolled,progress,total_lessons:totalLessons,completed_lessons:completedLessons,chapters,mcqs,materials});
});

app.post('/api/admin/courses',auth,admin,(req,res)=>{const {title,description='',price_paise=0,published=0}=req.body; if(!title)return res.status(400).json({error:'Title required'}); const r=db.prepare('INSERT INTO courses(title,description,price_paise,published) VALUES(?,?,?,?)').run(title,description,price_paise,published?1:0);res.json(db.prepare('SELECT * FROM courses WHERE id=?').get(r.lastInsertRowid));});
app.get('/api/admin/courses',auth,admin,(req,res)=>{
 const courses=db.prepare('SELECT * FROM courses ORDER BY id DESC').all().map(c=>{
  const chapters=db.prepare('SELECT * FROM chapters WHERE course_id=? ORDER BY sort_order,id').all(c.id).map(ch=>({...ch,lessons:db.prepare('SELECT id,title,video_url,is_demo,sort_order FROM lessons WHERE chapter_id=? ORDER BY sort_order,id').all(ch.id)}));
  const materials=db.prepare('SELECT id,title,file_url,is_demo FROM materials WHERE course_id=? ORDER BY id DESC').all(c.id);
  const mcqs=db.prepare('SELECT id,chapter_id,question,correct_option,is_demo FROM mcqs WHERE course_id=? ORDER BY id DESC').all(c.id);
  return {...c,chapters,materials,mcqs};
 }); res.json({courses});
});
app.put('/api/admin/courses/:id',auth,admin,(req,res)=>{const {title,description='',price_paise=0,published=0}=req.body||{};if(!title)return res.status(400).json({error:'Title required'});const r=db.prepare('UPDATE courses SET title=?,description=?,price_paise=?,published=? WHERE id=?').run(title,description,Number(price_paise)||0,published?1:0,req.params.id);if(!r.changes)return res.status(404).json({error:'Course not found'});res.json(db.prepare('SELECT * FROM courses WHERE id=?').get(req.params.id));});
app.delete('/api/admin/courses/:id',auth,admin,(req,res)=>{const r=db.prepare('DELETE FROM courses WHERE id=?').run(req.params.id);if(!r.changes)return res.status(404).json({error:'Course not found'});res.json({ok:true});});
app.put('/api/admin/chapters/:id',auth,admin,(req,res)=>{const {title,sort_order=0}=req.body||{};if(!title)return res.status(400).json({error:'Title required'});const r=db.prepare('UPDATE chapters SET title=?,sort_order=? WHERE id=?').run(title,Number(sort_order)||0,req.params.id);if(!r.changes)return res.status(404).json({error:'Chapter not found'});res.json(db.prepare('SELECT * FROM chapters WHERE id=?').get(req.params.id));});
app.delete('/api/admin/chapters/:id',auth,admin,(req,res)=>{const r=db.prepare('DELETE FROM chapters WHERE id=?').run(req.params.id);if(!r.changes)return res.status(404).json({error:'Chapter not found'});res.json({ok:true});});
app.put('/api/admin/lessons/:id',auth,admin,(req,res)=>{const {title,video_url='',is_demo=0,sort_order=0}=req.body||{};if(!title)return res.status(400).json({error:'Title required'});const r=db.prepare('UPDATE lessons SET title=?,video_url=?,is_demo=?,sort_order=? WHERE id=?').run(title,video_url,is_demo?1:0,Number(sort_order)||0,req.params.id);if(!r.changes)return res.status(404).json({error:'Lesson not found'});res.json(db.prepare('SELECT id,title,video_url,is_demo,sort_order FROM lessons WHERE id=?').get(req.params.id));});
app.delete('/api/admin/lessons/:id',auth,admin,(req,res)=>{const r=db.prepare('DELETE FROM lessons WHERE id=?').run(req.params.id);if(!r.changes)return res.status(404).json({error:'Lesson not found'});res.json({ok:true});});

app.post('/api/admin/chapters',auth,admin,(req,res)=>{const {course_id,title,sort_order=0}=req.body;const r=db.prepare('INSERT INTO chapters(course_id,title,sort_order) VALUES(?,?,?)').run(course_id,title,sort_order);res.json(db.prepare('SELECT * FROM chapters WHERE id=?').get(r.lastInsertRowid));});
app.post('/api/admin/lessons',auth,admin,(req,res)=>{const {chapter_id,title,video_url='',is_demo=0,sort_order=0}=req.body;const r=db.prepare('INSERT INTO lessons(chapter_id,title,video_url,is_demo,sort_order) VALUES(?,?,?,?,?)').run(chapter_id,title,video_url,is_demo?1:0,sort_order);res.json(db.prepare('SELECT id,title,is_demo,sort_order FROM lessons WHERE id=?').get(r.lastInsertRowid));});
app.post('/api/admin/materials',auth,admin,(req,res)=>{const {course_id,title,file_url,is_demo=0}=req.body;const r=db.prepare('INSERT INTO materials(course_id,title,file_url,is_demo) VALUES(?,?,?,?)').run(course_id,title,file_url,is_demo?1:0);res.json(db.prepare('SELECT * FROM materials WHERE id=?').get(r.lastInsertRowid));});
app.post('/api/admin/materials/upload',auth,admin,materialUpload.single('file'),(req,res)=>{
  try{
    const {course_id,title,is_demo=0}=req.body||{};
    if(!course_id || !title || !req.file) return res.status(400).json({error:'Course, title and file are required.'});
    const course=db.prepare('SELECT id FROM courses WHERE id=?').get(Number(course_id));
    if(!course) return res.status(404).json({error:'Course not found.'});
    const fileUrl=`/api/materials/${req.file.filename}`;
    const r=db.prepare('INSERT INTO materials(course_id,title,file_url,is_demo) VALUES(?,?,?,?)').run(Number(course_id),String(title).trim(),fileUrl,Number(is_demo)?1:0);
    res.json({ok:true,material:db.prepare('SELECT * FROM materials WHERE id=?').get(r.lastInsertRowid)});
  }catch(e){ if(req.file?.path) try{fs.unlinkSync(req.file.path)}catch{}; res.status(500).json({error:e.message}); }
});
app.delete('/api/admin/materials/:id',auth,admin,(req,res)=>{
  const m=db.prepare('SELECT * FROM materials WHERE id=?').get(req.params.id);
  if(!m)return res.status(404).json({error:'Material not found'});
  if(String(m.file_url||'').startsWith('/api/materials/')){const file=path.join(__dirname,'storage','materials',path.basename(m.file_url));try{fs.unlinkSync(file)}catch{}}
  db.prepare('DELETE FROM materials WHERE id=?').run(req.params.id);res.json({ok:true});
});
app.get('/api/materials/:filename',auth,(req,res)=>{
  const filename=path.basename(req.params.filename);
  const m=db.prepare('SELECT m.*,c.id AS course_id FROM materials m JOIN courses c ON c.id=m.course_id WHERE m.file_url=?').get('/api/materials/'+filename);
  if(!m)return res.status(404).json({error:'Material not found'});
  const allowed=!!db.prepare("SELECT 1 FROM enrollments WHERE user_id=? AND course_id=? AND status='active'").get(req.user.id,m.course_id) || !!m.is_demo || req.user.role==='admin';
  if(!allowed)return res.status(403).json({error:'Course access required'});
  const file=path.join(__dirname,'storage','materials',filename);
  if(!fs.existsSync(file))return res.status(404).json({error:'File missing'});
  res.download(file, path.basename(file).replace(/^\d+-[^-]+-/,'') || 'study-material');
});
app.post('/api/admin/mcqs',auth,admin,(req,res)=>{
 const {course_id,chapter_id=null,question,option_a,option_b,option_c,option_d,correct_option,explanation='',is_demo=0}=req.body;
 if(!question||![option_a,option_b,option_c,option_d].every(Boolean)||!['A','B','C','D'].includes(correct_option)) return res.status(400).json({error:'Question, four options and correct answer are required.'});
 const r=db.prepare('INSERT INTO mcqs(course_id,chapter_id,question,option_a,option_b,option_c,option_d,correct_option,explanation,is_demo) VALUES(?,?,?,?,?,?,?,?,?,?)').run(course_id,chapter_id,question,option_a,option_b,option_c,option_d,correct_option,explanation,is_demo?1:0);
 res.json(db.prepare('SELECT * FROM mcqs WHERE id=?').get(r.lastInsertRowid));
});


function csvParse(text){
  const rows=[]; let row=[], cell='', quoted=false;
  for(let i=0;i<text.length;i++){
    const ch=text[i], nx=text[i+1];
    if(quoted){ if(ch==='"' && nx==='"'){cell+='"'; i++;} else if(ch==='"'){quoted=false;} else cell+=ch; }
    else if(ch==='"'){quoted=true;}
    else if(ch===','){row.push(cell.trim()); cell='';}
    else if(ch==='\n'){row.push(cell.trim()); rows.push(row); row=[]; cell='';}
    else if(ch!=='\r') cell+=ch;
  }
  if(cell.length || row.length){row.push(cell.trim()); rows.push(row);}
  return rows.filter(r=>r.some(Boolean));
}
function normalizeMcqRow(obj){
  const g=(...keys)=>{for(const k of keys){if(obj[k]!==undefined && String(obj[k]).trim()!=='') return String(obj[k]).trim();} return '';};
  const correct=g('correct_option','correct answer','correct','answer').toUpperCase();
  return {question:g('question','q'),option_a:g('option_a','option a','a'),option_b:g('option_b','option b','b'),option_c:g('option_c','option c','c'),option_d:g('option_d','option d','d'),correct_option:correct,explanation:g('explanation','answer explanation'),is_demo:/^(1|true|yes|demo)$/i.test(g('is_demo','demo'))?1:0,chapter_id:g('chapter_id','chapter')};
}
function validateMcq(q){return !!q.question && [q.option_a,q.option_b,q.option_c,q.option_d].every(Boolean) && ['A','B','C','D'].includes(q.correct_option);}

app.get('/api/admin/mcqs',auth,admin,(req,res)=>{
  const courseId=Number(req.query.course_id)||null, chapterId=Number(req.query.chapter_id)||null, demo=req.query.demo;
  const search=String(req.query.search||'').trim();
  let sql=`SELECT m.*, c.title AS course_title, ch.title AS chapter_title FROM mcqs m JOIN courses c ON c.id=m.course_id LEFT JOIN chapters ch ON ch.id=m.chapter_id WHERE 1=1`;
  const args=[];
  if(courseId){sql+=' AND m.course_id=?';args.push(courseId)}
  if(chapterId){sql+=' AND m.chapter_id=?';args.push(chapterId)}
  if(demo==='0'||demo==='1'){sql+=' AND m.is_demo=?';args.push(Number(demo))}
  if(search){sql+=' AND (m.question LIKE ? OR m.explanation LIKE ?)';args.push('%'+search+'%','%'+search+'%')}
  sql+=' ORDER BY m.id DESC LIMIT 1000';
  res.json({mcqs:db.prepare(sql).all(...args)});
});
app.put('/api/admin/mcqs/:id',auth,admin,(req,res)=>{
  const q=normalizeMcqRow(req.body||{});
  if(!validateMcq(q)) return res.status(400).json({error:'Question, four options and a valid correct answer (A/B/C/D) are required.'});
  const r=db.prepare(`UPDATE mcqs SET course_id=?,chapter_id=?,question=?,option_a=?,option_b=?,option_c=?,option_d=?,correct_option=?,explanation=?,is_demo=? WHERE id=?`).run(Number(req.body.course_id),q.chapter_id?Number(q.chapter_id):null,q.question,q.option_a,q.option_b,q.option_c,q.option_d,q.correct_option,q.explanation,q.is_demo,req.params.id);
  if(!r.changes)return res.status(404).json({error:'MCQ not found'});
  res.json(db.prepare('SELECT * FROM mcqs WHERE id=?').get(req.params.id));
});
app.delete('/api/admin/mcqs/:id',auth,admin,(req,res)=>{const r=db.prepare('DELETE FROM mcqs WHERE id=?').run(req.params.id);if(!r.changes)return res.status(404).json({error:'MCQ not found'});res.json({ok:true});});
app.post('/api/admin/mcqs/bulk-delete',auth,admin,(req,res)=>{const ids=Array.isArray(req.body?.ids)?req.body.ids.map(Number).filter(Number.isInteger):[];if(!ids.length)return res.status(400).json({error:'No MCQs selected.'});const stmt=db.prepare('DELETE FROM mcqs WHERE id=?');const tx=db.transaction(()=>ids.reduce((n,id)=>n+stmt.run(id).changes,0));res.json({ok:true,deleted:tx()});});
app.post('/api/admin/mcqs/bulk-import-csv',auth,admin,upload.single('csv'),(req,res)=>{
  try{
    if(!req.file)return res.status(400).json({error:'CSV file is required.'});
    const rows=csvParse(req.file.buffer.toString('utf8').replace(/^\uFEFF/,''));
    if(rows.length<2)return res.status(400).json({error:'CSV must contain a header row and at least one question.'});
    const headers=rows[0].map(x=>x.toLowerCase().trim());
    const objects=rows.slice(1).map(r=>Object.fromEntries(headers.map((h,i)=>[h,r[i]??''])));
    const parsed=objects.map(normalizeMcqRow);
    const valid=parsed.filter(validateMcq), invalid=parsed.length-valid.length;
    const courseId=Number(req.body.course_id)||null;
    if(!courseId)return res.status(400).json({error:'Select a course before importing.'});
    const chapterDefault=Number(req.body.chapter_id)||null;
    const stmt=db.prepare('INSERT INTO mcqs(course_id,chapter_id,question,option_a,option_b,option_c,option_d,correct_option,explanation,is_demo) VALUES(?,?,?,?,?,?,?,?,?,?)');
    const tx=db.transaction(items=>items.map(q=>stmt.run(courseId,q.chapter_id?Number(q.chapter_id):chapterDefault,q.question,q.option_a,q.option_b,q.option_c,q.option_d,q.correct_option,q.explanation,q.is_demo).lastInsertRowid));
    const ids=tx(valid);
    res.json({ok:true,total:parsed.length,imported:valid.length,skipped:invalid,ids,warning:invalid?'Some rows were skipped because required fields/correct answers were invalid.':''});
  }catch(e){res.status(400).json({error:'Could not parse CSV file.'});}
});
app.post('/api/admin/mcqs/import-pdf-commit',auth,admin,(req,res)=>{
  const items=Array.isArray(req.body?.questions)?req.body.questions:[]; const courseId=Number(req.body.course_id)||null, chapterDefault=Number(req.body.chapter_id)||null;
  if(!courseId||!items.length)return res.status(400).json({error:'Course and at least one question are required.'});
  const clean=items.map(normalizeMcqRow).filter(validateMcq);
  const stmt=db.prepare('INSERT INTO mcqs(course_id,chapter_id,question,option_a,option_b,option_c,option_d,correct_option,explanation,is_demo) VALUES(?,?,?,?,?,?,?,?,?,?)');
  const tx=db.transaction(xs=>xs.map(q=>stmt.run(courseId,q.chapter_id?Number(q.chapter_id):chapterDefault,q.question,q.option_a,q.option_b,q.option_c,q.option_d,q.correct_option,q.explanation,q.is_demo).lastInsertRowid));
  const ids=tx(clean); res.json({ok:true,imported:ids.length,skipped:items.length-clean.length});
});

app.post('/api/admin/mcqs/import-pdf', auth, admin, upload.single('pdf'), async (req,res)=>{
  let dir;
  try{
    if(!req.file) return res.status(400).json({error:'PDF file is required.'});
    let data=await pdfParse(req.file.buffer);
    let text=data.text||'';
    let ocrUsed=false;
    if(text.trim().length < 40){
      ocrUsed=true;
      dir=fs.mkdtempSync(path.join(os.tmpdir(),'learnpro-ocr-'));
      const pdfPath=path.join(dir,'input.pdf'); fs.writeFileSync(pdfPath,req.file.buffer);
      await execFileAsync('pdftoppm',['-jpeg','-r','180',pdfPath,path.join(dir,'page')],{timeout:120000});
      const images=fs.readdirSync(dir).filter(f=>/^page-\d+\.jpg$/i.test(f)).sort((a,b)=>a.localeCompare(b,undefined,{numeric:true}));
      const parts=[];
      for(const img of images){ const {stdout}=await execFileAsync('tesseract',[path.join(dir,img),'stdout','--psm','6'],{timeout:120000,maxBuffer:5*1024*1024}); parts.push(stdout); }
      text=parts.join('\n');
    }
    const blocks=text.split(/\n(?=\s*(?:Q(?:uestion)?\s*)?\d+[.)]\s*)/i).map(x=>x.trim()).filter(Boolean);
    const parsed=[];
    for(const block of blocks){
      const q=block.match(/^(?:Q(?:uestion)?\s*)?\d+[.)]\s*(.*?)(?=\n\s*A[.)]\s*)/is);
      const opts={};
      for(const letter of ['A','B','C','D']){ const next=String.fromCharCode(letter.charCodeAt(0)+1); const re=new RegExp('\\n\\s*'+letter+'[.)]\\s*(.*?)(?=\\n\\s*'+(letter==='D'?'(?:Answer|Correct|Explanation|$)':next+'[.)]')+'|$)','is'); const m=block.match(re); if(m) opts[letter]=m[1].trim(); }
      const ans=block.match(/(?:Correct\s*Answer|Answer)\s*[:\-]?\s*([ABCD])/i);
      const exp=block.match(/Explanation\s*[:\-]?\s*([\s\S]*?)(?=\n\s*(?:Q(?:uestion)?\s*)?\d+[.)]|$)/i);
      if(q && opts.A && opts.B && opts.C && opts.D) parsed.push({question:q[1].trim(), option_a:opts.A, option_b:opts.B, option_c:opts.C, option_d:opts.D, correct_option:ans?ans[1].toUpperCase():'', explanation:exp?exp[1].trim():'', is_demo:0});
    }
    res.json({pages:data.numpages||1, ocr_used:ocrUsed, extracted_count:parsed.length, questions:parsed, warning: parsed.length===0 ? 'No reliably structured MCQs were detected. Check the PDF format and review OCR text.' : 'Review every question before importing.'});
  }catch(e){res.status(400).json({error:'Could not read PDF or run OCR. Make sure the uploaded file is a valid PDF.'});}
  finally{ if(dir) fs.rmSync(dir,{recursive:true,force:true}); }
});

app.post('/api/payments/confirm-demo',auth,(req,res)=>{const {course_id,payment_ref}=req.body||{};const c=db.prepare('SELECT id FROM courses WHERE id=? AND published=1').get(course_id);if(!c)return res.status(404).json({error:'Course not found'});db.prepare("INSERT INTO enrollments(user_id,course_id,payment_ref,status) VALUES(?,?,?,'active') ON CONFLICT(user_id,course_id) DO UPDATE SET status='active',payment_ref=excluded.payment_ref").run(req.user.id,course_id,payment_ref||crypto.randomUUID());res.json({ok:true,message:'Demo payment confirmed; course unlocked.'});});

// Seed an admin only when none exists. Change credentials in production.
(async()=>{ if(!db.prepare("SELECT 1 FROM users WHERE role='admin' LIMIT 1").get()){ const email=process.env.ADMIN_EMAIL; const pw=process.env.ADMIN_PASSWORD; if(!email||!pw){ if(NODE_ENV==='production') throw new Error('ADMIN_EMAIL and ADMIN_PASSWORD are required in production.'); console.warn('No ADMIN_EMAIL/ADMIN_PASSWORD configured; development admin seed skipped.'); return; } const hash=await bcrypt.hash(pw,12); db.prepare("INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,'admin')").run('Administrator',email,hash); console.log(`Admin created: ${email}`); }})();

app.get('/health',(req,res)=>res.json({ok:true,service:'LearnPro LMS'}));
app.use((req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));
const server = app.listen(PORT, '0.0.0.0', () => console.log(`LearnPro LMS running on port ${PORT}`));
function shutdown(signal){
  console.log(`${signal}: shutting down LearnPro LMS...`);
  server.close(()=>{ try{ db.close(); }catch(e){} process.exit(0); });
  setTimeout(()=>process.exit(1),10000).unref();
}
process.on('SIGTERM',()=>shutdown('SIGTERM'));
process.on('SIGINT',()=>shutdown('SIGINT'));
