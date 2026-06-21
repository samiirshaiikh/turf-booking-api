// Turf Booking API — real backend + persistent database (Turso/libSQL)
// Same proven pattern as the FootballGears backend: works on Render's free
// tier (no disk needed), survives restarts/redeploys.

const express = require('express');
const cors = require('cors');
const { createClient } = require('@libsql/client');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const Razorpay = require('razorpay');

const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID || '',
  key_secret: process.env.RAZORPAY_KEY_SECRET || '',
});

const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-secret-in-production';

if (!process.env.TURSO_DATABASE_URL) {
  console.error('Missing TURSO_DATABASE_URL environment variable!');
}
const db = createClient({
  url: process.env.TURSO_DATABASE_URL,
  authToken: process.env.TURSO_AUTH_TOKEN,
});

// Turf operating hours — 6 AM to 12 AM (midnight) => slots 6..23 (18 one-hour slots)
const OPEN_HOUR = 6;
const CLOSE_HOUR = 24;

async function init() {
  await db.execute(`CREATE TABLE IF NOT EXISTS bookings (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    phone TEXT NOT NULL,
    email TEXT,
    date TEXT NOT NULL,
    startHour INTEGER NOT NULL,
    duration INTEGER NOT NULL,
    notes TEXT,
    status TEXT DEFAULT 'confirmed',
    amount INTEGER,
    razorpayOrderId TEXT,
    razorpayPaymentId TEXT,
    createdAt TEXT DEFAULT CURRENT_TIMESTAMP
  )`);
  await db.execute(`CREATE TABLE IF NOT EXISTS blocked_slots (
    id INTEGER PRIMARY KEY,
    date TEXT NOT NULL,
    startHour INTEGER NOT NULL,
    reason TEXT
  )`);
  await db.execute(`CREATE TABLE IF NOT EXISTS admins (
    username TEXT PRIMARY KEY,
    passwordHash TEXT NOT NULL
  )`);

  const adminCount = await db.execute('SELECT COUNT(*) AS c FROM admins');
  if (adminCount.rows[0].c === 0) {
    const defaultUser = process.env.ADMIN_USER || 'admin';
    const defaultPass = process.env.ADMIN_PASS || 'changeme123';
    const hash = bcrypt.hashSync(defaultPass, 10);
    await db.execute({ sql: 'INSERT INTO admins (username, passwordHash) VALUES (?, ?)', args: [defaultUser, hash] });
    console.log(`Seeded default admin user "${defaultUser}". CHANGE THIS PASSWORD.`);
  }
}

const app = express();
app.use(cors());
app.use(express.json({ limit: '5mb' }));

function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Missing token' });
  try {
    req.admin = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

function overlaps(aStart, aDur, bStart, bDur) {
  const aEnd = aStart + aDur;
  const bEnd = bStart + bDur;
  return aStart < bEnd && bStart < aEnd;
}

async function isSlotFree(date, startHour, duration, excludeId) {
  if (startHour < OPEN_HOUR || startHour + duration > CLOSE_HOUR) return false;

  const bookingsRes = await db.execute({
    sql: `SELECT * FROM bookings WHERE date = ? AND status != 'cancelled'`,
    args: [date],
  });
  for (const b of bookingsRes.rows) {
    if (excludeId && b.id === excludeId) continue;
    if (overlaps(startHour, duration, b.startHour, b.duration)) return false;
  }

  const blockedRes = await db.execute({ sql: 'SELECT * FROM blocked_slots WHERE date = ?', args: [date] });
  for (const blk of blockedRes.rows) {
    if (overlaps(startHour, duration, blk.startHour, 1)) return false;
  }
  return true;
}

// ====================== AUTH ======================
app.post('/api/admin/login', async (req, res) => {
  const { username, password } = req.body || {};
  const result = await db.execute({ sql: 'SELECT * FROM admins WHERE username = ?', args: [username] });
  const row = result.rows[0];
  if (!row || !bcrypt.compareSync(password || '', row.passwordHash)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '12h' });
  res.json({ token });
});

app.post('/api/admin/change-password', requireAuth, async (req, res) => {
  const { newPassword } = req.body || {};
  if (!newPassword || newPassword.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }
  const hash = bcrypt.hashSync(newPassword, 10);
  await db.execute({ sql: 'UPDATE admins SET passwordHash = ? WHERE username = ?', args: [hash, req.admin.username] });
  res.json({ ok: true });
});

// ====================== AVAILABILITY ======================
// Returns the full day's slot map: { hour: 'available' | 'booked' | 'blocked' }
app.get('/api/availability', async (req, res) => {
  const { date } = req.query;
  if (!date) return res.status(400).json({ error: 'date query param required' });

  const slots = {};
  for (let h = OPEN_HOUR; h < CLOSE_HOUR; h++) slots[h] = 'available';

  const bookingsRes = await db.execute({
    sql: `SELECT * FROM bookings WHERE date = ? AND status != 'cancelled'`,
    args: [date],
  });
  for (const b of bookingsRes.rows) {
    for (let h = b.startHour; h < b.startHour + b.duration; h++) {
      if (slots[h] !== undefined) slots[h] = 'booked';
    }
  }

  const blockedRes = await db.execute({ sql: 'SELECT * FROM blocked_slots WHERE date = ?', args: [date] });
  for (const blk of blockedRes.rows) {
    if (slots[blk.startHour] !== undefined) slots[blk.startHour] = 'blocked';
  }

  res.json({ date, openHour: OPEN_HOUR, closeHour: CLOSE_HOUR, slots });
});

// ====================== BOOKINGS ======================
app.get('/api/bookings', requireAuth, async (req, res) => {
  const { date } = req.query;
  let result;
  if (date) {
    result = await db.execute({ sql: 'SELECT * FROM bookings WHERE date = ? ORDER BY startHour ASC', args: [date] });
  } else {
    result = await db.execute('SELECT * FROM bookings ORDER BY date DESC, startHour ASC');
  }
  res.json(result.rows);
});

app.post('/api/bookings', async (req, res) => {
  const { name, phone, email, date, startHour, duration, notes, amount, requirePayment } = req.body || {};
  if (!name || !phone || !date || startHour === undefined || !duration) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  const sh = Number(startHour);
  const dur = Number(duration);

  const free = await isSlotFree(date, sh, dur);
  if (!free) {
    return res.status(409).json({ error: 'This slot is no longer available. Please pick another time.' });
  }

  const id = Date.now();
  const initialStatus = requirePayment ? 'pending_payment' : 'confirmed';
  await db.execute({
    sql: `INSERT INTO bookings (id,name,phone,email,date,startHour,duration,notes,status,amount)
          VALUES (?,?,?,?,?,?,?,?,?,?)`,
    args: [id, name, phone, email || '', date, sh, dur, notes || '', initialStatus, amount || null],
  });
  const result = await db.execute({ sql: 'SELECT * FROM bookings WHERE id = ?', args: [id] });
  res.json(result.rows[0]);
});

// Releases a booking that's still awaiting payment (e.g. user closed the
// Razorpay popup without paying) so the slot becomes available again.
// Only works on bookings still in 'pending_payment' status — safe to be public.
app.post('/api/bookings/:id/release', async (req, res) => {
  const id = Number(req.params.id);
  const result = await db.execute({ sql: 'SELECT * FROM bookings WHERE id = ?', args: [id] });
  const booking = result.rows[0];
  if (!booking || booking.status !== 'pending_payment') {
    return res.status(400).json({ error: 'Booking cannot be released' });
  }
  await db.execute({ sql: `UPDATE bookings SET status = 'cancelled' WHERE id = ?`, args: [id] });
  res.json({ ok: true });
});

// ====================== PAYMENTS (Razorpay) ======================
app.post('/api/payment/create-order', async (req, res) => {
  const { amount, bookingId } = req.body || {};
  if (!amount || !bookingId) return res.status(400).json({ error: 'amount and bookingId required' });
  try {
    const order = await razorpay.orders.create({
      amount: Math.round(Number(amount) * 100), // amount in paise
      currency: 'INR',
      receipt: 'booking_' + bookingId,
      notes: { bookingId: String(bookingId) },
    });
    await db.execute({ sql: 'UPDATE bookings SET razorpayOrderId = ? WHERE id = ?', args: [order.id, bookingId] });
    res.json({ orderId: order.id, amount: order.amount, currency: order.currency, keyId: process.env.RAZORPAY_KEY_ID });
  } catch (e) {
    console.error('Razorpay order creation failed:', e);
    res.status(500).json({ error: 'Could not initiate payment' });
  }
});

app.post('/api/payment/verify', async (req, res) => {
  const { razorpay_order_id, razorpay_payment_id, razorpay_signature, bookingId } = req.body || {};
  if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature || !bookingId) {
    return res.status(400).json({ error: 'Missing payment verification fields' });
  }
  const expectedSignature = crypto
    .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET || '')
    .update(razorpay_order_id + '|' + razorpay_payment_id)
    .digest('hex');

  if (expectedSignature !== razorpay_signature) {
    return res.status(400).json({ error: 'Payment verification failed' });
  }

  await db.execute({
    sql: `UPDATE bookings SET status = 'confirmed', razorpayPaymentId = ? WHERE id = ?`,
    args: [razorpay_payment_id, bookingId],
  });
  const result = await db.execute({ sql: 'SELECT * FROM bookings WHERE id = ?', args: [bookingId] });
  res.json({ ok: true, booking: result.rows[0] });
});

app.put('/api/bookings/:id', requireAuth, async (req, res) => {
  const id = Number(req.params.id);
  const { name, phone, email, date, startHour, duration, notes, status } = req.body || {};

  if (date && startHour !== undefined && duration) {
    const free = await isSlotFree(date, Number(startHour), Number(duration), id);
    if (!free) return res.status(409).json({ error: 'New slot is not available' });
  }

  await db.execute({
    sql: `UPDATE bookings SET name=?,phone=?,email=?,date=?,startHour=?,duration=?,notes=?,status=? WHERE id=?`,
    args: [name, phone, email || '', date, Number(startHour), Number(duration), notes || '', status || 'confirmed', id],
  });
  const result = await db.execute({ sql: 'SELECT * FROM bookings WHERE id = ?', args: [id] });
  res.json(result.rows[0]);
});

app.delete('/api/bookings/:id', requireAuth, async (req, res) => {
  await db.execute({ sql: `UPDATE bookings SET status = 'cancelled' WHERE id = ?`, args: [Number(req.params.id)] });
  res.json({ ok: true });
});

// ====================== BLOCKED SLOTS ======================
app.get('/api/blocked', async (req, res) => {
  const { date } = req.query;
  const result = date
    ? await db.execute({ sql: 'SELECT * FROM blocked_slots WHERE date = ?', args: [date] })
    : await db.execute('SELECT * FROM blocked_slots ORDER BY date DESC');
  res.json(result.rows);
});

app.post('/api/blocked', requireAuth, async (req, res) => {
  const { date, startHour, reason } = req.body || {};
  const id = Date.now();
  await db.execute({
    sql: 'INSERT INTO blocked_slots (id, date, startHour, reason) VALUES (?, ?, ?, ?)',
    args: [id, date, Number(startHour), reason || ''],
  });
  res.json({ ok: true, id });
});

app.delete('/api/blocked/:id', requireAuth, async (req, res) => {
  await db.execute({ sql: 'DELETE FROM blocked_slots WHERE id = ?', args: [Number(req.params.id)] });
  res.json({ ok: true });
});

app.get('/api/health', (req, res) => res.json({ ok: true }));

init()
  .then(() => app.listen(PORT, () => console.log(`Turf Booking API listening on port ${PORT}`)))
  .catch((e) => {
    console.error('Failed to initialize database:', e);
    process.exit(1);
  });
