const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const nodemailer = require("nodemailer");

const PORT = Number(process.env.PORT) || 3000;
const DATA_DIR = process.env.DATA_DIR ? path.resolve(process.env.DATA_DIR) : path.join(__dirname, "data");
const DATA_FILE = path.join(DATA_DIR, "db.json");

const SEED_ITEMS = [
  { id: "gauze", nameAr: "شاش", nameEn: "Gauze", noteAr: "ع 40", type: "qty", required: 40 },
  { id: "bandage", nameAr: "Bondage", nameEn: "Bandage", noteAr: "S/M/L", type: "qty", required: 4 },
  { id: "binder", nameAr: "مشد", nameEn: "Support binder", noteAr: "S/M/L", type: "qty", required: 2 },
  { id: "burn", nameAr: "مرهم حرق", nameEn: "Burn ointment", noteAr: "ع 1", type: "qty", required: 1 },
  { id: "kash", nameAr: "مرهم كش", nameEn: "Ointment", noteAr: "ع 1", type: "qty", required: 2 },
  { id: "sofratulle", nameAr: "Sofratulle", nameEn: "Sofratulle dressing", noteAr: "tulle dressing", type: "qty", required: 12 },
  { id: "serum", nameAr: "مصل", nameEn: "Serum", noteAr: "saline / IV", type: "qty", required: 1 },
  { id: "betadine", nameAr: "بيتادين", nameEn: "Betadine", noteAr: "ع 1", type: "qty", required: 1 },
  { id: "wound-tape", nameAr: "تلزيق جرح", nameEn: "Wound plaster", noteAr: "", type: "qty", required: 5 },
  { id: "gauze-roll", nameAr: "رولو شاش", nameEn: "Gauze roll", noteAr: "ع 1", type: "qty", required: 10 },
  { id: "elz", nameAr: "إلز", nameEn: "Elastic adhesive", noteAr: "ع 6", type: "qty", required: 6 },
  { id: "hypo", nameAr: "تلزيق ضد الحساسية", nameEn: "Hypoallergenic plaster", noteAr: "", type: "qty", required: 1 },
  { id: "pressure", nameAr: "ضماد ضاغط", nameEn: "Pressure dressing", noteAr: "ع 12", type: "qty", required: 1 },
  { id: "ice", nameAr: "كيس ثلج", nameEn: "Ice pack", noteAr: "ع 4", type: "qty", required: 1 },
  { id: "cleanisept", nameAr: "CLEANISEPT", nameEn: "CLEANISEPT change", noteAr: "كل 72 ساعة", type: "interval", required: 1, intervalHours: 72 },
];

function freshDb() {
  return {
    users: [
      {
        id: "admin",
        username: "admin",
        passwordHash: bcrypt.hashSync("admin", 10),
        role: "admin",
        name: "المسؤول",
      },
      {
        id: "user",
        username: "user",
        passwordHash: bcrypt.hashSync("user", 10),
        role: "user",
        name: "المسعف",
      },
    ],
    settings: {
      stationName: "لمى بتم الدين",
      adminEmail: "",
      smtp: { host: "", port: 587, secure: false, user: "", pass: "", from: "" },
    },
    items: SEED_ITEMS,
    checks: [],
  };
}

function loadDb() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(DATA_FILE)) {
    const db = freshDb();
    fs.writeFileSync(DATA_FILE, JSON.stringify(db, null, 2));
    return db;
  }
  const db = JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
  if (!Array.isArray(db.items) || !db.items.length) db.items = SEED_ITEMS;
  if (!db.settings) db.settings = freshDb().settings;
  if (!db.settings.smtp) db.settings.smtp = freshDb().settings.smtp;
  if (!Array.isArray(db.checks)) db.checks = [];
  if (!Array.isArray(db.users)) db.users = freshDb().users;
  for (const item of db.items) {
    if (!item.noteAr && item.noteEn) item.noteAr = String(item.noteEn);
    delete item.noteEn;
  }
  return db;
}

let db = loadDb();
saveDb();

function saveDb() {
  fs.writeFileSync(DATA_FILE, JSON.stringify(db, null, 2));
}

function newId() {
  return crypto.randomBytes(8).toString("hex");
}

function publicUser(user) {
  if (!user) return null;
  return { id: user.id, username: user.username, role: user.role, name: user.name };
}

function currentUser(req) {
  if (!req.session || !req.session.userId) return null;
  return db.users.find((u) => u.id === req.session.userId) || null;
}

function requireUser(req, res, next) {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: "forbidden" });
  req.user = user;
  next();
}

function requireAdmin(req, res, next) {
  requireUser(req, res, () => {
    if (req.user.role !== "admin") return res.status(403).json({ error: "forbidden" });
    next();
  });
}

function clampInt(value, min, max) {
  const n = Number(value);
  if (!Number.isInteger(n)) return null;
  if (n < min || n > max) return null;
  return n;
}

function parseDate(value) {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return null;
  const [y, m, d] = value.split("-").map(Number);
  const dt = new Date(Date.UTC(y, m - 1, d));
  if (dt.getUTCFullYear() !== y || dt.getUTCMonth() !== m - 1 || dt.getUTCDate() !== d) return null;
  if (y < 2020 || y > 2100) return null;
  return value;
}

function escHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function maskEmail(email) {
  const raw = String(email || "");
  const at = raw.indexOf("@");
  if (at < 1) return "";
  return `${raw.slice(0, 1)}***${raw.slice(at)}`;
}

function presentCheck(check, viewer) {
  const copy = JSON.parse(JSON.stringify(check));
  if (viewer.role !== "admin" && copy.email && copy.email.to) {
    copy.email.to = maskEmail(copy.email.to);
  }
  return copy;
}

function smtpReady() {
  const smtp = db.settings.smtp || {};
  return Boolean(db.settings.adminEmail && smtp.host && smtp.user && smtp.pass);
}

function buildLines(body) {
  const counts = body.counts && typeof body.counts === "object" ? body.counts : null;
  if (!counts) return { error: "invalid" };

  let lastChange = null;
  if (body.cleaniseptLastChange) {
    const parsed = new Date(body.cleaniseptLastChange);
    if (Number.isNaN(parsed.getTime())) return { error: "invalid" };
    lastChange = parsed.toISOString();
  }

  const lines = [];
  for (const item of db.items) {
    if (item.type === "qty") {
      if (!Object.prototype.hasOwnProperty.call(counts, item.id)) return { error: "invalid" };
      const actual = clampInt(counts[item.id], 0, 99999);
      if (actual === null) return { error: "invalid" };
      const shortage = Math.max(0, item.required - actual);
      lines.push({
        itemId: item.id,
        nameAr: item.nameAr,
        nameEn: item.nameEn,
        noteAr: item.noteAr || "",
        type: "qty",
        required: item.required,
        actual,
        shortage,
      });
    } else {
      const hours = item.intervalHours || 72;
      const elapsed = lastChange ? (Date.now() - new Date(lastChange).getTime()) / 36e5 : Infinity;
      const overdue = !lastChange || elapsed > hours;
      lines.push({
        itemId: item.id,
        nameAr: item.nameAr,
        nameEn: item.nameEn,
        noteAr: item.noteAr || "",
        type: "interval",
        intervalHours: hours,
        lastChange,
        overdue,
        required: hours,
        actual: lastChange ? Math.floor(elapsed) : null,
        shortage: overdue ? 1 : 0,
      });
    }
  }
  return { lines, shortages: lines.filter((line) => line.shortage > 0) };
}

function emailLogo() {
  return `<table cellpadding="0" cellspacing="0" role="presentation" style="border-collapse:separate;background:#ffffff;border:2px solid #ffffff;border-radius:10px">
    <tr><td style="padding:6px">
      <table cellpadding="0" cellspacing="0" role="presentation" style="border-collapse:collapse">
        <tr>
          <td width="8" height="8" style="font-size:0;line-height:0">&nbsp;</td>
          <td width="10" height="8" bgcolor="#e30613" style="font-size:0;line-height:0;background:#e30613">&nbsp;</td>
          <td width="8" height="8" style="font-size:0;line-height:0">&nbsp;</td>
        </tr>
        <tr>
          <td width="8" height="10" bgcolor="#e30613" style="font-size:0;line-height:0;background:#e30613">&nbsp;</td>
          <td width="10" height="10" bgcolor="#e30613" style="font-size:0;line-height:0;background:#e30613">&nbsp;</td>
          <td width="8" height="10" bgcolor="#e30613" style="font-size:0;line-height:0;background:#e30613">&nbsp;</td>
        </tr>
        <tr>
          <td width="8" height="8" style="font-size:0;line-height:0">&nbsp;</td>
          <td width="10" height="8" bgcolor="#e30613" style="font-size:0;line-height:0;background:#e30613">&nbsp;</td>
          <td width="8" height="8" style="font-size:0;line-height:0">&nbsp;</td>
        </tr>
      </table>
    </td></tr>
  </table>`;
}

function buildShortageMail(check, stationName) {
  const rows = check.shortages
    .map((line, index) => {
      const bg = index % 2 === 0 ? "#ffffff" : "#fff8f8";
      const cell = `padding:10px 8px;background:${bg};border-bottom:1px solid #f6dfe1;font-family:Tahoma,Arial,sans-serif;font-size:14px`;
      let required = String(line.required);
      let actual = String(line.actual);
      let missing = String(line.shortage);
      if (line.type === "interval") {
        required = `كل ${escHtml(line.intervalHours)} ساعة`;
        actual = line.lastChange ? escHtml(new Date(line.lastChange).toLocaleString("en-GB")) : "غير مسجّل";
        missing = "متأخر";
      }
      return `<tr>
        <td style="${cell};text-align:right">
          <div style="font-weight:bold;color:#2a1216">${escHtml(line.nameAr)}</div>
          <div style="color:#8a656a;font-size:12px;margin-top:2px">${escHtml(line.nameEn)}</div>
        </td>
        <td style="${cell};text-align:center;color:#2a1216">${required}</td>
        <td style="${cell};text-align:center;color:#2a1216">${actual}</td>
        <td style="${cell};text-align:center">
          <span style="display:inline-block;background:#fff0f1;color:#b10e18;font-weight:bold;border-radius:999px;padding:4px 10px">${missing}</span>
        </td>
      </tr>`;
    })
    .join("");

  const notes = check.notes
    ? `<tr><td style="padding:4px 16px 8px">
        <table width="100%" cellpadding="0" cellspacing="0" role="presentation" style="background:#fff8f8;border:1px solid #f3d5d8;border-radius:12px">
          <tr><td style="padding:12px 14px;font-family:Tahoma,Arial,sans-serif;color:#2a1216">
            <div style="font-size:12px;color:#8a656a;font-weight:bold">ملاحظات · Notes</div>
            <div style="margin-top:4px">${escHtml(check.notes)}</div>
          </td></tr>
        </table>
      </td></tr>`
    : "";

  const text = [
    `نواقص جردة المعدات — ${check.date}`,
    `الاسم: ${stationName}`,
    `المسعف: ${check.paramedicName}`,
    "",
    ...check.shortages.map((line) =>
      line.type === "interval"
        ? `${line.nameAr} (${line.nameEn}): متأخر عن ${line.intervalHours} ساعة. آخر تغيير: ${line.lastChange || "غير مسجّل"}`
        : `${line.nameAr} (${line.nameEn}): المطلوب ${line.required}، الموجود ${line.actual}، النقص ${line.shortage}`
    ),
    check.notes ? `\nملاحظات: ${check.notes}` : "",
  ].join("\n");

  const infoRow = (label, value, ltr) => `<tr>
    <td style="padding:0 0 8px">
      <table width="100%" cellpadding="0" cellspacing="0" role="presentation" bgcolor="#fff8f8" style="background:#fff8f8;border:1px solid #f3d5d8;border-radius:12px">
        <tr>
          <td align="right" style="padding:12px 14px;font-family:Tahoma,Arial,sans-serif;color:#8a656a;font-size:13px">${label}</td>
          <td align="left" dir="${ltr ? "ltr" : "rtl"}" style="padding:12px 14px;font-family:Tahoma,Arial,sans-serif;color:#2a1216;font-weight:bold;font-size:15px;line-height:1.4;${ltr ? "white-space:nowrap" : ""}">${value}</td>
        </tr>
      </table>
    </td>
  </tr>`;

  const html = `<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light only">
  <meta name="supported-color-schemes" content="light">
</head>
<body style="margin:0;padding:0;background:#fff5f6">
  <table width="100%" cellpadding="0" cellspacing="0" role="presentation" bgcolor="#fff5f6" style="background:#fff5f6">
    <tr><td align="center" class="outer" style="padding:20px 12px">
      <table dir="rtl" width="100%" cellpadding="0" cellspacing="0" role="presentation" bgcolor="#ffffff" style="width:100%;max-width:560px;background:#ffffff;border:1px solid #f3d5d8;border-radius:16px">
        <tr><td bgcolor="#e30613" style="background:#e30613;padding:16px 16px 18px;border-radius:16px 16px 0 0">
          <table width="100%" cellpadding="0" cellspacing="0" role="presentation">
            <tr>
              <td width="46" valign="top">${emailLogo()}</td>
              <td valign="middle" align="right" style="padding-right:12px;font-family:Tahoma,Arial,sans-serif;color:#ffffff">
                <div style="font-size:20px;font-weight:bold;line-height:1.35">نواقص جردة المعدات</div>
                <div style="font-size:13px;line-height:1.4;margin-top:4px">Missing supplies from the daily check</div>
                <div style="margin-top:10px">
                  <span style="display:inline-block;background:#ffffff;color:#e30613;border-radius:999px;padding:4px 12px;font-family:Arial,sans-serif;font-weight:bold;font-size:14px">${check.shortages.length} نواقص</span>
                </div>
              </td>
            </tr>
          </table>
        </td></tr>
        <tr><td style="padding:16px 16px 4px">
          <table width="100%" cellpadding="0" cellspacing="0" role="presentation">
            ${infoRow("التاريخ · Date", escHtml(check.date), true)}
            ${infoRow("الاسم · Sheet", escHtml(stationName), false)}
            ${infoRow("المسعف · Paramedic", escHtml(check.paramedicName), false)}
          </table>
        </td></tr>
        <tr><td style="padding:8px 16px 8px">
          <table width="100%" cellpadding="0" cellspacing="0" role="presentation" style="border:1px solid #f3d5d8;border-radius:12px">
            <tr bgcolor="#e30613" style="background:#e30613;color:#ffffff;font-family:Tahoma,Arial,sans-serif">
              <th align="right" style="padding:10px 8px;font-size:12px">المادة</th>
              <th align="center" width="54" style="padding:10px 4px;font-size:12px">المطلوب</th>
              <th align="center" width="54" style="padding:10px 4px;font-size:12px">الموجود</th>
              <th align="center" width="54" style="padding:10px 4px;font-size:12px">النقص</th>
            </tr>
            ${rows}
          </table>
        </td></tr>
        ${notes}
        <tr><td style="padding:6px 16px 18px;font-family:Tahoma,Arial,sans-serif;color:#8a656a;font-size:12px;line-height:1.7">
          رسالة آلية من سجل الجردة. لا ترد على هذا البريد إن لم يكن مخصصاً للاستقبال.
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>`;

  return {
    subject: `نواقص الجردة ${check.date} — ${check.shortages.length} (${stationName})`,
    text,
    html,
  };
}

async function sendShortageEmail(check) {
  if (!check.shortages.length) {
    return { sent: false, skipped: true, reason: "nothing_missing", error: null, to: "" };
  }
  const settings = db.settings;
  const smtp = settings.smtp || {};
  if (!settings.adminEmail || !smtp.host || !smtp.user || !smtp.pass) {
    return { sent: false, skipped: false, reason: "not_configured", error: null, to: settings.adminEmail || "" };
  }

  const mail = buildShortageMail(check, settings.stationName);

  try {
    const transporter = nodemailer.createTransport({
      host: smtp.host,
      port: Number(smtp.port) || 587,
      secure: Boolean(smtp.secure),
      auth: { user: smtp.user, pass: smtp.pass },
    });
    await transporter.sendMail({
      from: smtp.from || smtp.user,
      to: settings.adminEmail,
      subject: mail.subject,
      text: mail.text,
      html: mail.html,
    });
    return {
      sent: true,
      skipped: false,
      reason: "sent",
      error: null,
      to: settings.adminEmail,
      at: new Date().toISOString(),
    };
  } catch (err) {
    return {
      sent: false,
      skipped: false,
      reason: "failed",
      error: String(err.message || "email failed").slice(0, 300),
      to: settings.adminEmail,
    };
  }
}

const attempts = new Map();

function tooManyAttempts(ip) {
  const now = Date.now();
  const recent = (attempts.get(ip) || []).filter((t) => now - t < 15 * 60 * 1000);
  attempts.set(ip, recent);
  return recent.length >= 8;
}

function markAttempt(ip) {
  const recent = attempts.get(ip) || [];
  recent.push(Date.now());
  attempts.set(ip, recent);
}

const app = express();
const production = process.env.NODE_ENV === "production";
if (production) app.set("trust proxy", 1);
app.disable("x-powered-by");
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  next();
});
app.use(express.json({ limit: "200kb" }));
app.use(
  session({
    name: "checklist.sid",
    secret: process.env.SESSION_SECRET || crypto.randomBytes(24).toString("hex"),
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: production,
      maxAge: 7 * 24 * 60 * 60 * 1000,
    },
  })
);

app.get("/api/me", (req, res) => {
  res.json({ user: publicUser(currentUser(req)) });
});

app.post("/api/login", (req, res) => {
  const ip = req.ip || "local";
  if (tooManyAttempts(ip)) return res.status(429).json({ error: "locked" });
  const username = String(req.body.username || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  const user = db.users.find((u) => u.username === username);
  if (!user || !bcrypt.compareSync(password, user.passwordHash)) {
    markAttempt(ip);
    return res.status(401).json({ error: "bad_login" });
  }
  req.session.regenerate((err) => {
    if (err) return res.status(500).json({ error: "server" });
    req.session.userId = user.id;
    res.json({ user: publicUser(user) });
  });
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("checklist.sid");
    res.json({ ok: true });
  });
});

app.get("/api/bootstrap", requireUser, (req, res) => {
  res.json({
    user: publicUser(req.user),
    items: db.items,
    stationName: db.settings.stationName,
    emailConfigured: smtpReady(),
  });
});

app.get("/api/checks", requireUser, (req, res) => {
  let list = db.checks.filter((check) => req.user.role === "admin" || check.userId === req.user.id);
  if (typeof req.query.month === "string" && /^\d{4}-\d{2}$/.test(req.query.month)) {
    list = list.filter((check) => check.date.startsWith(req.query.month));
  }
  if (typeof req.query.date === "string") {
    list = list.filter((check) => check.date === req.query.date);
  }
  list = list.slice().sort((a, b) => (b.updatedAt || "").localeCompare(a.updatedAt || ""));
  res.json(list.map((check) => presentCheck(check, req.user)));
});

app.post("/api/checks", requireUser, async (req, res) => {
  const date = parseDate(req.body.date);
  const paramedicName = String(req.body.paramedicName || "").trim();
  const notes = String(req.body.notes || "").trim();
  if (!date || paramedicName.length < 2 || paramedicName.length > 80 || notes.length > 500) {
    return res.status(400).json({ error: "invalid" });
  }
  const built = buildLines(req.body);
  if (built.error) return res.status(400).json({ error: built.error });

  const now = new Date().toISOString();
  const existing = db.checks.find((check) => check.userId === req.user.id && check.date === date);
  const check = {
    id: existing ? existing.id : newId(),
    userId: req.user.id,
    username: req.user.username,
    userName: req.user.name,
    paramedicName,
    date,
    notes,
    lines: built.lines,
    shortages: built.shortages,
    email: { sent: false, skipped: false, reason: "pending", error: null, to: "" },
    createdAt: existing ? existing.createdAt : now,
    updatedAt: now,
  };
  check.email = await sendShortageEmail(check);
  if (existing) {
    const index = db.checks.findIndex((row) => row.id === existing.id);
    db.checks[index] = check;
  } else {
    db.checks.push(check);
  }
  saveDb();
  res.json({ check: presentCheck(check, req.user) });
});

app.post("/api/checks/:id/resend", requireAdmin, async (req, res) => {
  const check = db.checks.find((row) => row.id === req.params.id);
  if (!check) return res.status(404).json({ error: "not_found" });
  if (!check.shortages.length) return res.status(400).json({ error: "nothing_missing" });
  check.email = await sendShortageEmail(check);
  check.updatedAt = new Date().toISOString();
  saveDb();
  res.json({ check: presentCheck(check, req.user) });
});

app.put("/api/items", requireAdmin, (req, res) => {
  if (!Array.isArray(req.body.items) || !req.body.items.length || req.body.items.length > 500) {
    return res.status(400).json({ error: "invalid" });
  }
  const next = [];
  const seen = new Set();
  for (const incoming of req.body.items) {
    if (!incoming || typeof incoming !== "object") return res.status(400).json({ error: "invalid" });
    const nameAr = String(incoming.nameAr || "").trim();
    const nameEn = String(incoming.nameEn || "").trim();
    const primaryAr = (nameAr || nameEn).slice(0, 80);
    const primaryEn = (nameEn || nameAr).slice(0, 80);
    if (!primaryAr) return res.status(400).json({ error: "invalid" });
    const prev = db.items.find((item) => item.id === incoming.id);
    let id = prev ? prev.id : newId();
    if (seen.has(id)) id = newId();
    seen.add(id);
    const type = prev ? prev.type : incoming.type === "interval" ? "interval" : "qty";
    const item = {
      id,
      nameAr: primaryAr,
      nameEn: primaryEn,
      noteAr: String(incoming.noteAr || "").trim().slice(0, 80),
      type,
    };
    if (type === "qty") {
      const required = clampInt(incoming.required, 0, 9999);
      if (required === null) return res.status(400).json({ error: "invalid" });
      item.required = required;
    } else {
      const intervalHours = clampInt(incoming.intervalHours ?? (prev && prev.intervalHours) ?? 72, 1, 24 * 30);
      if (intervalHours === null) return res.status(400).json({ error: "invalid" });
      item.intervalHours = intervalHours;
      item.required = 1;
    }
    next.push(item);
  }
  db.items = next;
  saveDb();
  res.json({ items: db.items });
});

function publicSettings() {
  const smtp = db.settings.smtp || {};
  return {
    stationName: db.settings.stationName,
    adminEmail: db.settings.adminEmail,
    smtp: {
      host: smtp.host || "",
      port: Number(smtp.port) || 587,
      secure: Boolean(smtp.secure),
      user: smtp.user || "",
      from: smtp.from || "",
      hasPassword: Boolean(smtp.pass),
    },
    emailConfigured: smtpReady(),
  };
}

app.get("/api/settings", requireAdmin, (req, res) => {
  res.json(publicSettings());
});

app.put("/api/settings", requireAdmin, (req, res) => {
  const stationName = String(req.body.stationName || "").trim();
  const adminEmail = String(req.body.adminEmail || "").trim();
  const smtp = req.body.smtp || {};
  if (!stationName || stationName.length > 80) return res.status(400).json({ error: "invalid" });
  if (adminEmail && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(adminEmail)) {
    return res.status(400).json({ error: "invalid" });
  }
  const port = clampInt(smtp.port, 1, 65535);
  if (port === null) return res.status(400).json({ error: "invalid" });
  db.settings.stationName = stationName;
  db.settings.adminEmail = adminEmail;
  db.settings.smtp = {
    host: String(smtp.host || "").trim().slice(0, 120),
    port,
    secure: Boolean(smtp.secure),
    user: String(smtp.user || "").trim().slice(0, 120),
    pass: smtp.pass ? String(smtp.pass).slice(0, 200) : db.settings.smtp.pass || "",
    from: String(smtp.from || "").trim().slice(0, 120),
  };
  saveDb();
  res.json(publicSettings());
});

app.post("/api/settings/test-email", requireAdmin, async (req, res) => {
  if (!smtpReady()) return res.status(400).json({ error: "smtp_incomplete" });
  const probe = {
    date: new Date().toISOString().slice(0, 10),
    paramedicName: req.user.name || "Admin",
    notes: "",
    shortages: [
      {
        type: "qty",
        nameAr: "رسالة تجربة",
        nameEn: "Test message",
        required: 1,
        actual: 0,
        shortage: 1,
        intervalHours: 72,
      },
    ],
  };
  const result = await sendShortageEmail(probe);
  if (!result.sent) return res.status(502).json({ error: "email_failed", message: result.error || "" });
  res.json({ ok: true });
});

app.get("/api/users", requireAdmin, (req, res) => {
  res.json(db.users.map(publicUser));
});

app.post("/api/users", requireAdmin, (req, res) => {
  const username = String(req.body.username || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  const name = String(req.body.name || "").trim();
  const role = req.body.role === "admin" ? "admin" : "user";
  if (!/^[a-z0-9._-]{3,32}$/.test(username)) return res.status(400).json({ error: "invalid" });
  if (password.length < 6 || password.length > 72) return res.status(400).json({ error: "weak_password" });
  if (!name || name.length > 80) return res.status(400).json({ error: "invalid" });
  if (db.users.some((user) => user.username === username)) return res.status(400).json({ error: "user_exists" });
  const user = { id: newId(), username, passwordHash: bcrypt.hashSync(password, 10), role, name };
  db.users.push(user);
  saveDb();
  res.json({ user: publicUser(user) });
});

app.post("/api/users/:id/password", requireAdmin, (req, res) => {
  const user = db.users.find((row) => row.id === req.params.id);
  if (!user) return res.status(404).json({ error: "not_found" });
  const password = String(req.body.password || "");
  if (password.length < 6 || password.length > 72) return res.status(400).json({ error: "weak_password" });
  user.passwordHash = bcrypt.hashSync(password, 10);
  saveDb();
  res.json({ ok: true });
});

app.delete("/api/users/:id", requireAdmin, (req, res) => {
  if (req.params.id === req.user.id) return res.status(400).json({ error: "cannot_delete_self" });
  const user = db.users.find((row) => row.id === req.params.id);
  if (!user) return res.status(404).json({ error: "not_found" });
  const admins = db.users.filter((row) => row.role === "admin");
  if (user.role === "admin" && admins.length < 2) return res.status(400).json({ error: "last_admin" });
  db.users = db.users.filter((row) => row.id !== user.id);
  saveDb();
  res.json({ ok: true });
});

app.post("/api/me/password", requireUser, (req, res) => {
  const current = String(req.body.current || "");
  const next = String(req.body.next || "");
  if (!bcrypt.compareSync(current, req.user.passwordHash)) {
    return res.status(400).json({ error: "wrong_password" });
  }
  if (next.length < 6 || next.length > 72) return res.status(400).json({ error: "weak_password" });
  req.user.passwordHash = bcrypt.hashSync(next, 10);
  saveDb();
  res.json({ ok: true });
});

app.use(express.static(path.join(__dirname, "public")));
app.use((req, res) => {
  if (req.path.startsWith("/api")) return res.status(404).json({ error: "not_found" });
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

if (require.main === module) {
  const server = app.listen(PORT, () => {
    console.log(`Checklist running at http://localhost:${PORT}`);
  });

  server.on("error", (err) => {
    if (err.code === "EADDRINUSE") {
      console.error(`Port ${PORT} is already in use.`);
    } else {
      console.error(err);
    }
    process.exit(1);
  });
}

module.exports = { buildShortageMail };
