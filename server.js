require('dotenv').config();

const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const Tesseract = require('tesseract.js'); 
const { createClient } = require('@libsql/client');
const Jimp = require('jimp');
const jsQR = require('jsqr');

const app = express();
const PORT = process.env.PORT || 3000;

// ============================================================
// CONFIG
// ============================================================
const AMOUNT = 500;                          // ราคา 500 บาท
const DURATION_MS = 24 * 60 * 60 * 1000;     // 24 ชั่วโมง
const PAYMENT_TIMEOUT_MS = 10 * 60 * 1000;   // 10 นาที (ถ้าไม่จ่ายลบไอดี)
const ADMIN_DEFAULT_USER = 'admin';
const ADMIN_DEFAULT_PASS = '0647748563';

const EXPECTED_ACCOUNT_LAST4 = process.env.RECEIVER_ACCOUNT_LAST4 || '';
const expectedNameTH = process.env.RECEIVER_NAME ? process.env.RECEIVER_NAME.replace(/\s+/g, '') : '';
const expectedNameEN = process.env.RECEIVER_NAME_ENG ? process.env.RECEIVER_NAME_ENG.replace(/\s+/g, '').toUpperCase() : '';

// ตั้งค่ารับไฟล์รูปภาพ (เก็บไว้ใน Memory ชั่วคราวก่อนเพื่อรอตรวจสอบ)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 }, // รับไฟล์ใหญ่สุด 10MB
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('รองรับเฉพาะไฟล์รูปภาพเท่านั้น'));
    }
  }
});

// ============================================================
// TURSO CONNECTION & DB INIT
// ============================================================
if (!process.env.TURSO_DATABASE_URL || !process.env.TURSO_AUTH_TOKEN) {
  console.error('❌ ต้องตั้งค่า TURSO_DATABASE_URL และ TURSO_AUTH_TOKEN ใน .env');
  process.exit(1);
}

const turso = createClient({
  url: process.env.TURSO_DATABASE_URL,
  authToken: process.env.TURSO_AUTH_TOKEN,
});

async function dbGet(sql, args = []) {
  const r = await turso.execute({ sql, args });
  return r.rows[0] || null;
}
async function dbAll(sql, args = []) {
  const r = await turso.execute({ sql, args });
  return r.rows;
}
async function dbRun(sql, args = []) {
  return await turso.execute({ sql, args });
}

const PUBLIC_DIR = path.join(__dirname, 'public');
if (!fs.existsSync(PUBLIC_DIR)) fs.mkdirSync(PUBLIC_DIR, { recursive: true });

async function initDB() {
  await dbRun(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      status TEXT NOT NULL DEFAULT 'unpaid',
      paid_at INTEGER,
      expires_at INTEGER,
      transaction_id TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      created_by TEXT
    )
  `);

  await dbRun(`
    CREATE TABLE IF NOT EXISTS payment_intents (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ref TEXT UNIQUE NOT NULL,
      username TEXT NOT NULL,
      amount INTEGER NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      created_at INTEGER NOT NULL,
      paid_at INTEGER,
      transaction_id TEXT,
      slip_trans_ref TEXT
    )
  `);

  // เพิ่มคอลัมน์ใหม่สำหรับเก็บลิงก์รูปสลิป
  try { await dbRun(`ALTER TABLE payment_intents ADD COLUMN slip_trans_ref TEXT`); } catch (e) {}
  try { await dbRun(`ALTER TABLE payment_intents ADD COLUMN slip_image_url TEXT`); } catch (e) {}
  try { await dbRun(`ALTER TABLE users ADD COLUMN last_slip_url TEXT`); } catch (e) {}

  await dbRun(`CREATE INDEX IF NOT EXISTS idx_payment_ref ON payment_intents(ref)`);
  await dbRun(`CREATE INDEX IF NOT EXISTS idx_payment_username ON payment_intents(username)`);
  await dbRun(`CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)`);

  const admin = await dbGet('SELECT 1 FROM users WHERE username=?', [ADMIN_DEFAULT_USER]);
  if (!admin) {
    const hash = bcrypt.hashSync(ADMIN_DEFAULT_PASS, 10);
    await dbRun(
      `INSERT INTO users (username,password_hash,role,status,created_by) VALUES (?,?,?,?,?)`,
      [ADMIN_DEFAULT_USER, hash, 'admin', 'paid', 'system']
    );
  }
}

// ============================================================
// MIDDLEWARE
// ============================================================
app.set('trust proxy', 1);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors({ origin: true, credentials: true }));

app.use(session({
  name: 'fd.sid',
  secret: process.env.SESSION_SECRET || 'fd-secret-key-1234',
  resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, secure: false, maxAge: 30 * 24 * 60 * 60 * 1000 }
}));

function requireLogin(req, res, next) {
  if (!req.session.user) return res.status(401).json({ ok: false, msg: 'กรุณาเข้าสู่ระบบ' });
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== 'admin')
    return res.status(403).json({ ok: false, msg: 'ต้องเป็นแอดมินเท่านั้น' });
  next();
}

// ============================================================
// AUTH API
// ============================================================
app.get('/api/health', (req, res) => res.json({ ok: true }));

app.get('/api/me', requireLogin, async (req, res) => {
  const u = await dbGet('SELECT * FROM users WHERE username=?', [req.session.user.username]);
  if (!u) { req.session.destroy(()=>{}); return res.json({ ok: false, msg: 'บัญชีถูกลบ' }); }

  const now = Date.now();
  let status = u.status;
  if (u.role !== 'admin' && status === 'paid' && u.expires_at && u.expires_at <= now) {
    await dbRun('UPDATE users SET status=? WHERE id=?', ['expired', u.id]);
    status = 'expired';
  }

  res.json({
    ok: true,
    user: {
      username: u.username, role: u.role, status,
      expiresAt: u.expires_at, remainingMs: (u.expires_at && u.expires_at > now) ? u.expires_at - now : 0
    }
  });
});

app.post('/api/register', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || password.length < 4) return res.json({ ok: false, msg: 'ข้อมูลไม่ถูกต้อง' });

  const exists = await dbGet('SELECT 1 FROM users WHERE username=?', [username]);
  if (exists) return res.json({ ok: false, msg: 'ชื่อผู้ใช้นี้มีอยู่แล้ว' });

  const hash = bcrypt.hashSync(password, 10);
  await dbRun(`INSERT INTO users (username,password_hash,role,status,created_by) VALUES (?,?,?,?,?)`, [username, hash, 'user', 'unpaid', 'self']);

  req.session.user = { username, role: 'user' };
  req.session.save(() => res.json({ ok: true, user: { username, role: 'user', status: 'unpaid' } }));
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {};
  const user = await dbGet('SELECT * FROM users WHERE username=?', [username]);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) 
    return res.json({ ok: false, msg: 'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง' });

  // ⭐ คำนวณสถานะปัจจุบัน (เช็คหมดอายุ)
  const now = Date.now();
  let status = user.status;
  if (user.role !== 'admin' && status === 'paid' && user.expires_at && user.expires_at <= now) {
    await dbRun('UPDATE users SET status=? WHERE id=?', ['expired', user.id]);
    status = 'expired';
  }

  req.session.user = { username: user.username, role: user.role };
  req.session.save(() => res.json({
    ok: true,
    user: {                                    // ⭐ ส่ง user object กลับ
      username: user.username,
      role: user.role,
      status: status,
      expiresAt: user.expires_at,
      remainingMs: (user.expires_at && user.expires_at > now) ? user.expires_at - now : 0
    }
  }));
});

app.post('/api/logout', (req, res) => { req.session.destroy(() => res.json({ ok: true })); });

// ============================================================
// PAYMENT API 
// ============================================================
app.post('/api/create-payment', requireLogin, async (req, res) => {
  const username = req.session.user.username;
  const existing = await dbGet(`SELECT * FROM payment_intents WHERE username=? AND status='pending' AND created_at > ? ORDER BY id DESC LIMIT 1`, [username, Date.now() - PAYMENT_TIMEOUT_MS]);

  if (existing) return res.json({ ok: true, ref: existing.ref, amount: existing.amount, reused: true });

  const ref = 'FD' + Date.now().toString(36).toUpperCase() + Math.random().toString(36).slice(2, 6).toUpperCase();
  await dbRun(`INSERT INTO payment_intents (ref, username, amount, status, created_at) VALUES (?,?,?,?,?)`, [ref, username, AMOUNT, 'pending', Date.now()]);
  res.json({ ok: true, ref, amount: AMOUNT });
});

app.get('/api/check-payment', requireLogin, async (req, res) => {
  const { ref } = req.query;
  const intent = await dbGet('SELECT * FROM payment_intents WHERE ref=? AND username=?', [ref, req.session.user.username]);
  if (!intent) return res.json({ ok: false });

  if (intent.status === 'paid') {
    const u = await dbGet('SELECT * FROM users WHERE username=?', [req.session.user.username]);
    const now = Date.now();
    const baseTime = (u.status === 'paid' && u.expires_at && u.expires_at > now) ? u.expires_at : now;
    await dbRun(`UPDATE users SET status=?, paid_at=?, expires_at=? WHERE id=?`, ['paid', now, baseTime + DURATION_MS, u.id]);
    return res.json({ ok: true, paid: true });
  }
  res.json({ ok: true, paid: false, status: intent.status });
});

// ---- ระบบตรวจสอบสลิปอัตโนมัติด้วย AI (QR Code + Tesseract OCR) ----
app.post('/api/verify-slip', requireLogin, upload.single('slip'), async (req, res) => {
  try {
    if (!req.file) return res.json({ ok: false, msg: 'กรุณาแนบรูปสลิป' });

    const username = req.session.user.username;
    const { ref } = req.body || {};
    const intent = await dbGet('SELECT * FROM payment_intents WHERE ref=? AND username=?', [ref, username]);
    if (!intent || intent.status !== 'pending') return res.json({ ok: false, msg: 'รหัสอ้างอิงไม่ถูกต้อง หรืออาจหมดอายุไปแล้ว (เกิน 10 นาที)' });

    // ==========================================
    // LAYER 1: สแกน QR Code จากสลิป
    // ==========================================
    console.log(`🔍 กำลังค้นหา QR Code ในสลิป...`);
    const image = await Jimp.read(req.file.buffer);
    // แปลงภาพเพื่อให้ jsQR อ่านได้
    const qrCode = jsQR(new Uint8ClampedArray(image.bitmap.data), image.bitmap.width, image.bitmap.height);

    let slipQrPayload = null;
    if (qrCode) {
      slipQrPayload = qrCode.data;
      console.log("📝 ข้อมูลจาก QR Code:", slipQrPayload);

      // เช็คว่า QR Code นี้เคยถูกใช้ยืนยันไปแล้วหรือยัง (ป้องกันการวนสลิป 100%)
      const usedQR = await dbGet('SELECT id FROM payment_intents WHERE slip_trans_ref=?', [slipQrPayload]);
      if (usedQR) return res.json({ ok: false, msg: '❌ สลิปใบนี้ถูกนำมาใช้ยืนยันไปแล้ว' });
    } else {
      console.log("⚠️ ไม่พบ QR Code");
      return res.json({ ok: false, msg: '❌ ไม่พบ QR Code บนสลิป หรือรูปภาพไม่ชัดเจน (สลิปจริงต้องมี QR)' });
    }

    // ==========================================
    // LAYER 2: อ่านข้อความด้วย OCR (เช็คยอดเงิน, ชื่อ, เวลา)
    // ==========================================
    console.log(`🔍 ตรวจพบ QR กำลังให้ AI อ่านตัวอักษรต่อ...`);
    const { data: { text } } = await Tesseract.recognize(req.file.buffer, 'tha+eng');
    const cleanText = text.replace(/\s+/g, '');
    
    // 1. ตรวจสอบยอดเงิน (หาคำว่า 500 หรือ 500.00)
    if (!cleanText.includes('500.00') && !cleanText.includes('500')) {
      return res.json({ ok: false, msg: 'AI ไม่พบยอดเงิน 500 บาทในสลิป' });
    }

    // 2. ตรวจสอบชื่อบัญชีผู้รับ
    if (expectedNameTH || expectedNameEN) {
      const foundTH = expectedNameTH && cleanText.includes(expectedNameTH);
      const foundEN = expectedNameEN && textUpper.includes(expectedNameEN);
      
      if (!foundTH && !foundEN) {
        return res.json({ ok: false, msg: 'ชื่อผู้รับเงินในสลิปไม่ตรงกับร้าน (ไม่พบชื่อไทยหรืออังกฤษ)' });
      }
    }

    // 3. ตรวจสอบเลขบัญชี 4 ตัวท้าย
    if (EXPECTED_ACCOUNT_LAST4 && !cleanText.includes(EXPECTED_ACCOUNT_LAST4)) {
      return res.json({ ok: false, msg: 'เลขบัญชีผู้รับ 4 ตัวท้ายไม่ตรงกัน' });
    }

    // 4. ตรวจสอบเวลา (ไม่เกิน 10 นาที)
    const timeMatch = cleanText.match(/(\d{2}):(\d{2})/);
    if (timeMatch) {
       const slipHour = parseInt(timeMatch[1], 10);
       const slipMin = parseInt(timeMatch[2], 10);
       
       const now = new Date();
       const thaiTime = new Date(now.toLocaleString("en-US", {timeZone: "Asia/Bangkok"}));
       
       let diffMins = (thaiTime.getHours() * 60 + thaiTime.getMinutes()) - (slipHour * 60 + slipMin);
       if (diffMins < -1000) diffMins += 24 * 60; // จัดการกรณีโอนข้ามวัน

       if (diffMins > 10) return res.json({ ok: false, msg: 'สลิปนี้หมดอายุแล้ว (โอนผ่านมาเกิน 10 นาที)' });
       else if (diffMins < -5) return res.json({ ok: false, msg: 'เวลาในสลิปล่วงหน้าผิดปกติ' });
    } else {
       console.log("⚠️ AI หาระบุเวลาในสลิปไม่เจอ อนุโลมให้ผ่าน เพราะตรวจ QR ผ่านแล้ว");
    }

    // ==== บันทึกไฟล์รูปสลิปลงเซิร์ฟเวอร์เพื่อให้แอดมินดู ====
    const slipsDir = path.join(PUBLIC_DIR, 'slips');
    if (!fs.existsSync(slipsDir)) fs.mkdirSync(slipsDir, { recursive: true });
    
    const ext = path.extname(req.file.originalname) || '.jpg';
    const filename = `slip_${username}_${Date.now()}${ext}`;
    const filepath = path.join(slipsDir, filename);
    
    fs.writeFileSync(filepath, req.file.buffer);
    const slipUrl = `/slips/${filename}`;
    // ===================================================

    // ผ่านเงื่อนไขทั้งหมด อนุมัติทันที!
    const nowStamp = Date.now();
    await dbRun(
      // บันทึก slipQrPayload ลงในคอลัมน์ slip_trans_ref เพื่อใช้เช็คสลิปซ้ำในอนาคต
      `UPDATE payment_intents SET status=?, paid_at=?, transaction_id=?, slip_trans_ref=?, slip_image_url=? WHERE ref=?`,
      ['paid', nowStamp, 'QR-VERIFIED-' + nowStamp, slipQrPayload, slipUrl, intent.ref]
    );

    await dbRun(`UPDATE users SET last_slip_url=? WHERE username=?`, [slipUrl, username]);

    console.log(`✅ อนุมัติสลิปสำเร็จ: ${username} (ref=${intent.ref})`);
    res.json({ ok: true, msg: 'ตรวจสอบสลิปสำเร็จ กำลังเข้าสู่ระบบ...', ref: intent.ref });
  } catch (e) {
    res.status(500).json({ ok: false, msg: 'อ่านภาพไม่สำเร็จ โปรดลองใหม่: ' + e.message });
  }
});

// ============================================================
// ADMIN API
// ============================================================
app.get('/api/admin/payment-intents', requireAdmin, async (req, res) => {
  const rows = await dbAll(`SELECT * FROM payment_intents ORDER BY created_at DESC LIMIT 100`);
  res.json({ ok: true, intents: rows });
});

app.post('/api/admin/verify-payment', requireAdmin, async (req, res) => {
  const { ref } = req.body || {};
  const intent = await dbGet('SELECT * FROM payment_intents WHERE ref=?', [ref]);
  if (!intent) return res.json({ ok: false, msg: 'ไม่พบ ref' });
  
  const now = Date.now();
  await dbRun(`UPDATE payment_intents SET status=?, paid_at=?, transaction_id=? WHERE ref=?`, ['paid', now, 'ADMIN-' + now, ref]);
  res.json({ ok: true });
});

app.get('/api/users', requireAdmin, async (req, res) => {
  // ดึง last_slip_url มาให้แอดมินด้วย
  const rows = await dbAll(`SELECT id, username, role, status, paid_at, expires_at, transaction_id, created_at, created_by, last_slip_url FROM users ORDER BY id`);
  res.json({ ok: true, users: rows });
});

app.post('/api/users/:username/approve', requireAdmin, async (req, res) => {
  const u = await dbGet('SELECT * FROM users WHERE username=?', [req.params.username]);
  if (!u) return res.json({ ok: false, msg: 'ไม่พบผู้ใช้' });
  const now = Date.now();
  const baseTime = (u.status === 'paid' && u.expires_at > now) ? u.expires_at : now;
  await dbRun(`UPDATE users SET status=?, paid_at=?, expires_at=?, transaction_id=? WHERE id=?`, ['paid', now, baseTime + DURATION_MS, 'ADMIN-' + now, u.id]);
  res.json({ ok: true });
});

app.delete('/api/users/:username', requireAdmin, async (req, res) => {
  await dbRun('DELETE FROM users WHERE username=?', [req.params.username]);
  res.json({ ok: true });
});

// ============================================================
// AUTO DELETE UNPAID USERS (10 MINS)
// ============================================================
setInterval(async () => {
  try {
    const unpaidUsers = await dbAll(`SELECT * FROM users WHERE role != 'admin' AND status = 'unpaid'`);
    const now = Date.now();
    for (const u of unpaidUsers) {
      const createdAtDate = new Date(u.created_at + 'Z'); 
      const diffMins = (now - createdAtDate.getTime()) / (1000 * 60);
      
      if (diffMins > 10) {
        console.log(`🗑 ลบบัญชี ${u.username} อัตโนมัติ (ไม่ชำระเงินใน 10 นาที)`);
        await dbRun('DELETE FROM users WHERE id=?', [u.id]);
        await dbRun('DELETE FROM payment_intents WHERE username=?', [u.username]);
      }
    }
  } catch (e) {
    console.error("Auto-delete error:", e);
  }
}, 60 * 1000); 

// ============================================================
// ERROR HANDLER
// ============================================================
app.use((err, req, res, next) => {
  console.error('❌ Server Error:', err.message);
  res.status(500).json({ ok: false, msg: 'เซิร์ฟเวอร์ขัดข้อง: ' + err.message });
});

// ============================================================
// STATIC & START
// ============================================================
app.use(express.static(PUBLIC_DIR));
app.get('*', (req, res) => res.sendFile(path.join(PUBLIC_DIR, 'index.html')));

initDB().then(() => {
  app.listen(PORT, () => {
    console.log('');
    console.log('═══════════════════════════════════════════');
    console.log(`✅ Server running on port ${PORT}`);
    console.log(`📁 Static dir: ${PUBLIC_DIR}`);
    console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log('═══════════════════════════════════════════');
    console.log('');
  });
}).catch(err => {
  console.error('❌ initDB failed:', err);
  process.exit(1);
});
