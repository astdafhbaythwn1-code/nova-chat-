require("dotenv").config();
const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;
const DB_FILE = path.join(__dirname, "data.json");

app.use(helmet({ contentSecurityPolicy: false })); // CSP can be tightened for production.
app.use(express.json({ limit: "100kb" }));
app.use(session({
  name: "nova.sid",
  secret: process.env.SESSION_SECRET || "development-only-change-this-secret",
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production", maxAge: 1000 * 60 * 60 * 24 }
}));
app.use(express.static(path.join(__dirname, "public")));

const initial = { users: [], messages: [], gifts: [], verifications: [] };
function loadDB() {
  try { return { ...initial, ...JSON.parse(fs.readFileSync(DB_FILE, "utf8")) }; }
  catch { return structuredClone(initial); }
}
let db = loadDB();
function saveDB() {
  const tmp = DB_FILE + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(db, null, 2));
  fs.renameSync(tmp, DB_FILE);
}
const id = () => crypto.randomUUID();
const cleanUser = u => ({ id: u.id, username: u.username, displayName: u.displayName, role: u.role,
  stars: u.role === "admin" ? "∞" : u.stars, premium: !!u.premium, verified: !!u.verified });
const requireAuth = (req, res, next) => req.session.userId ? next() : res.status(401).json({ error: "سجّل الدخول الأول" });
const currentUser = req => db.users.find(u => u.id === req.session.userId);
const requireAdmin = (req, res, next) => {
  const u = currentUser(req);
  if (!u || u.role !== "admin") return res.status(403).json({ error: "الصلاحية دي للأدمن فقط" });
  next();
};

// Bootstrap the admin from environment variables. The account is created once.
async function bootstrapAdmin() {
  const username = process.env.ADMIN_USERNAME;
  const hash = process.env.ADMIN_PASSWORD_HASH;
  if (!username || !hash || hash.includes("replace-with")) {
    console.warn("Admin not bootstrapped: set ADMIN_USERNAME and ADMIN_PASSWORD_HASH in .env");
    return;
  }
  let admin = db.users.find(u => u.role === "admin");
  if (!admin) {
    db.users.push({ id: id(), username, displayName: "Nova Admin", passwordHash: hash,
      role: "admin", stars: 0, premium: true, verified: true, createdAt: new Date().toISOString() });
    saveDB();
  }
}

app.post("/api/register", async (req, res) => {
  const username = String(req.body.username || "").trim().toLowerCase();
  const displayName = String(req.body.displayName || username).trim().slice(0, 40);
  const password = String(req.body.password || "");
  if (!/^[a-z0-9_]{3,24}$/.test(username)) return res.status(400).json({ error: "اسم المستخدم: 3 إلى 24 حرفًا/رقمًا أو _" });
  if (password.length < 8) return res.status(400).json({ error: "كلمة المرور لازم تكون 8 أحرف على الأقل" });
  if (db.users.some(u => u.username === username)) return res.status(409).json({ error: "اسم المستخدم مستخدم بالفعل" });
  const user = { id: id(), username, displayName, passwordHash: await bcrypt.hash(password, 12),
    role: "user", stars: 20, premium: false, verified: false, createdAt: new Date().toISOString() };
  db.users.push(user); saveDB(); req.session.userId = user.id;
  res.json({ user: cleanUser(user) });
});
app.post("/api/login", async (req, res) => {
  const username = String(req.body.username || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  const user = db.users.find(u => u.username === username);
  if (!user || !(await bcrypt.compare(password, user.passwordHash))) return res.status(401).json({ error: "اسم المستخدم أو كلمة المرور غلط" });
  req.session.userId = user.id;
  res.json({ user: cleanUser(user) });
});
app.post("/api/logout", (req, res) => req.session.destroy(() => res.json({ ok: true })));
app.get("/api/me", requireAuth, (req, res) => res.json({ user: cleanUser(currentUser(req)) }));
app.get("/api/users", requireAuth, (req, res) => res.json({ users: db.users.filter(u => u.id !== req.session.userId).map(cleanUser) }));

app.get("/api/messages", requireAuth, (req, res) => {
  const peer = String(req.query.with || "");
  res.json({ messages: db.messages.filter(m =>
    (m.from === req.session.userId && m.to === peer) || (m.from === peer && m.to === req.session.userId)
  ).slice(-200) });
});
app.post("/api/messages", requireAuth, (req, res) => {
  const to = String(req.body.to || "");
  const text = String(req.body.text || "").trim().slice(0, 2000);
  if (!text || !db.users.some(u => u.id === to)) return res.status(400).json({ error: "اختار مستخدم واكتب رسالة" });
  const msg = { id: id(), from: req.session.userId, to, text, createdAt: new Date().toISOString() };
  db.messages.push(msg); saveDB(); res.json({ message: msg });
});
app.post("/api/gifts", requireAuth, (req, res) => {
  const to = String(req.body.to || "");
  const gift = String(req.body.gift || "🌟");
  const cost = ({ "🌟": 5, "💎": 20, "🎁": 10, "🚀": 50 })[gift];
  const sender = currentUser(req);
  const recipient = db.users.find(u => u.id === to);
  if (!recipient || !cost) return res.status(400).json({ error: "الهدية غير متاحة" });
  if (sender.role !== "admin" && sender.stars < cost) return res.status(400).json({ error: "رصيد النجوم مش كفاية" });
  if (sender.role !== "admin") sender.stars -= cost;
  if (recipient.role !== "admin") recipient.stars += cost;
  db.gifts.push({ id: id(), from: sender.id, to, gift, cost, createdAt: new Date().toISOString() });
  saveDB(); res.json({ ok: true, user: cleanUser(sender), message: "تم إرسال الهدية تجريبيًا" });
});
app.post("/api/premium/request", requireAuth, (req, res) => {
  const user = currentUser(req);
  user.premiumRequest = { status: "pending", createdAt: new Date().toISOString() };
  saveDB(); res.json({ ok: true, message: "تم تسجيل طلب الحساب المميز. الدفع الحقيقي غير مفعّل." });
});
app.post("/api/verification/request", requireAuth, (req, res) => {
  const type = String(req.body.type || "account");
  const link = String(req.body.link || "").trim().slice(0, 300);
  if (!link) return res.status(400).json({ error: "اكتب رابط الحساب أو القناة أو الجروب" });
  const item = { id: id(), userId: req.session.userId, type, link, status: "pending", createdAt: new Date().toISOString() };
  db.verifications.push(item); saveDB(); res.json({ ok: true, message: "طلب التوثيق اتسجل للمراجعة داخل التطبيق فقط." });
});
app.get("/api/admin/overview", requireAuth, requireAdmin, (req, res) => {
  res.json({ users: db.users.map(cleanUser), messages: db.messages.length, gifts: db.gifts,
    verifications: db.verifications, premiumRequests: db.users.filter(u => u.premiumRequest).map(u => ({ id: u.id, username: u.username, ...u.premiumRequest })) });
});
app.post("/api/admin/verification/:id", requireAuth, requireAdmin, (req, res) => {
  const item = db.verifications.find(v => v.id === req.params.id);
  if (!item) return res.status(404).json({ error: "الطلب مش موجود" });
  item.status = req.body.approve ? "approved_in_app" : "rejected";
  if (req.body.approve) {
    const u = db.users.find(x => x.id === item.userId);
    if (u) u.verified = true;
  }
  saveDB(); res.json({ ok: true });
});
app.post("/api/admin/stars", requireAuth, requireAdmin, (req, res) => {
  const target = db.users.find(u => u.id === String(req.body.userId || ""));
  const amount = Number(req.body.amount);
  if (!target || !Number.isInteger(amount) || amount < 1 || amount > 1000000) return res.status(400).json({ error: "بيانات غير صحيحة" });
  if (target.role !== "admin") target.stars += amount;
  saveDB(); res.json({ ok: true, user: cleanUser(target), message: "تمت إضافة النجوم داخل التطبيق" });
});
app.post("/api/admin/premium/:id", requireAuth, requireAdmin, (req, res) => {
  const target = db.users.find(u => u.id === req.params.id);
  if (!target) return res.status(404).json({ error: "المستخدم مش موجود" });
  target.premium = !!req.body.enabled; saveDB(); res.json({ ok: true });
});

bootstrapAdmin().then(() => app.listen(PORT, () => console.log(`Nova Chat running at http://localhost:${PORT}`)));
