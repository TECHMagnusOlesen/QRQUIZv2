// server.js
const express      = require('express');
const path         = require('path');
const fs           = require('fs');
const cookieParser = require('cookie-parser');
const crypto       = require('crypto');
const { v4: uuidv4 } = require('uuid');
const low           = require('lowdb');
const FileSync      = require('lowdb/adapters/FileSync');

const app = express();

// ---------- Paths ----------
const CORE_FILE      = path.join(__dirname, 'core.json');   // global users
const TENANTS_DIR    = path.join(__dirname, 'tenants');     // per-user dbs
const PUBLIC_DIR     = __dirname; // dine html/css/js ligger her

if (!fs.existsSync(TENANTS_DIR)) fs.mkdirSync(TENANTS_DIR, { recursive: true });

// ---------- Core DB (users) ----------
const coreAdapter = new FileSync(CORE_FILE);
const coreDb = low(coreAdapter);
coreDb.defaults({ users: [] }).write();

// ---------- Helpers ----------
function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
  return { salt, hash };
}
function verifyPassword(password, user) {
  const test = crypto.pbkdf2Sync(password, user.salt, 100000, 64, 'sha512').toString('hex');
  return test === user.hash;
}

// Cache af tenant DB'er
const tenantCache = new Map();
function getTenantDb(tenant) {
  const safe = String(tenant || '').trim();
  if (!safe) throw new Error('Missing tenant');
  if (tenantCache.has(safe)) return tenantCache.get(safe);

  const file = path.join(TENANTS_DIR, `${safe}.json`);
  const adapter = new FileSync(file);
  const db = low(adapter);
  db.defaults({ teams: [], tasks: [], records: [], events: [], logs: [] }).write();
  tenantCache.set(safe, db);
  return db;
}

// ---------- Middleware ----------
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

// Protect admin.html
app.get('/admin.html', (req, res) => {
  if (req.cookies.admin === 'true') return res.sendFile(path.join(PUBLIC_DIR, 'admin.html'));
  return res.redirect('/?needLogin=1');
});

// ---------- Public ----------
app.get('/', (req, res) => res.sendFile(path.join(PUBLIC_DIR, 'index.html')));

// First-time setup (create owner)
app.get('/api/auth/hasUsers', (req, res) => {
  const hasUsers = coreDb.get('users').size().value() > 0;
  res.json({ hasUsers });
});
app.post('/api/auth/setup', (req, res) => {
  const { username, password } = req.body;
  const hasUsers = coreDb.get('users').size().value() > 0;
  if (hasUsers) return res.status(400).json({ error: 'Allerede konfigureret' });
  if (!username || !password) return res.status(400).json({ error: 'Manglende felter' });

  const { salt, hash } = hashPassword(password);
  coreDb.get('users').push({ id: uuidv4(), username, salt, hash, role: 'owner', created: Date.now() }).write();

  // ensure tenant db exists for owner
  getTenantDb(username);

  res.cookie('admin', 'true', { httpOnly: true });
  res.cookie('adminUser', username, { httpOnly: true });
  res.cookie('tenant', username, { httpOnly: true });
  res.json({ ok: true });
});

// Login / logout
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = coreDb.get('users').find({ username }).value();
  if (!user || !verifyPassword(password, user)) return res.redirect('/?error=1');

  // make sure tenant db exists
  getTenantDb(username);

  res.cookie('admin', 'true', { httpOnly: true });
  res.cookie('adminUser', username, { httpOnly: true });
  res.cookie('tenant', username, { httpOnly: true });
  res.redirect('/admin.html');
});
app.post('/logout', (req, res) => {
  res.clearCookie('admin');
  res.clearCookie('adminUser');
  res.clearCookie('tenant');
  res.redirect('/');
});

// Static
app.use(express.static(PUBLIC_DIR));

// ---------- Tenant resolution ----------
function resolveTenantFromReq(req) {
  // priority: query ?t=  -> cookie.tenant -> cookie.adminUser
  const q = (req.query.t || '').toString().trim();
  const fromQuery = q || null;
  const fromCookie = (req.cookies.tenant || req.cookies.adminUser || '').toString().trim() || null;
  const tenant = fromQuery || fromCookie;
  return tenant;
}

// ---------- Public game routes ----------
app.get('/join.html', (req, res) => {
  const tenant = resolveTenantFromReq(req);
  if (!tenant) return res.status(400).send('Mangler tenant');
  const db = getTenantDb(tenant);

  const { teamId, eventId } = req.query;
  const team = db.get('teams').find({ id: teamId }).value();
  if (!team) return res.status(400).send('Ugyldigt teamId');

  if (eventId) {
    const ev = db.get('events').find({ id: eventId }).value();
    if (!ev) return res.status(400).send('Ugyldigt eventId');
    if (!ev.teamIds.includes(teamId)) return res.status(403).send('Hold ikke med i event');
    res.cookie('eventId', eventId, { httpOnly: false });
  }

  // set tenant for player
  res.cookie('tenant', tenant, { httpOnly: false });
  res.cookie('teamId', teamId, { httpOnly: false });

  // log
  db.get('logs').push({ id: uuidv4(), type: 'join', teamId, eventId: eventId || null, time: Date.now() }).write();
  res.redirect('/joined.html');
});

app.get('/scan', (req, res) => {
  const tenant = resolveTenantFromReq(req);
  if (!tenant) return res.status(400).send('Mangler tenant');
  const db = getTenantDb(tenant);

  const { taskId, optionIndex } = req.query;
  const teamId  = req.cookies.teamId;
  const eventId = req.cookies.eventId || null;

  if (!teamId) return res.redirect('/join.html');

  const task = db.get('tasks').find({ id: taskId }).value();
  if (!task) return res.status(400).send('Ugyldig opgave');

  if (eventId) {
    const ev = db.get('events').find({ id: eventId }).value();
    if (!ev) return res.status(400).send('Ugyldigt event');
    if (!ev.taskIds.includes(taskId)) return res.redirect('/joined.html?notinEvent=true');
    if (!ev.teamIds.includes(teamId)) return res.status(403).send('Hold ikke med i event');
  }

  if (db.get('records').find({ teamId, taskId }).value()) {
    return res.redirect('/joined.html?already=true');
  }

  const idx = parseInt(optionIndex, 10);
  const opt = task.options[idx];
  if (!opt) return res.status(400).send('Ugyldig svar');

  db.get('records').push({ id: uuidv4(), teamId, taskId, optionIndex: idx, points: opt.points, eventId, time: Date.now() }).write();
  db.get('teams').find({ id: teamId }).update('score', n => n + opt.points).write();
  db.get('logs').push({ id: uuidv4(), type: 'answer', teamId, taskId, optionIndex: idx, points: opt.points, eventId, time: Date.now() }).write();

  res.redirect(`/joined.html?points=${opt.points}`);
});

app.get('/api/task/:id', (req, res) => {
  const tenant = resolveTenantFromReq(req);
  if (!tenant) return res.status(400).json({ error: 'Mangler tenant' });
  const db = getTenantDb(tenant);

  const task = db.get('tasks').find({ id: req.params.id }).value();
  if (!task) return res.status(404).json({ error: 'Ikke fundet' });
  res.json(task);
});

// Score for joined.html
app.get('/api/score', (req, res) => {
  const tenant = resolveTenantFromReq(req);
  if (!tenant) return res.status(400).json({ error: 'Mangler tenant' });
  const db = getTenantDb(tenant);

  const teamId = req.cookies.teamId;
  if (!teamId) return res.status(400).json({ error: 'Ikke tilknyttet hold' });
  const team = db.get('teams').find({ id: teamId }).value();
  if (!team) return res.status(404).json({ error: 'Hold ikke fundet' });
  res.json({ score: team.score, name: team.name });
});

// NEW: Event-name for joined.html
app.get('/api/event', (req, res) => {
  try {
    const tenant = resolveTenantFromReq(req);
    if (!tenant) return res.json({ event: null });
    const db = getTenantDb(tenant);

    const eventId = req.cookies.eventId;
    if (!eventId) return res.json({ event: null });

    const ev = db.get('events').find({ id: eventId }).value();
    if (!ev) return res.json({ event: null });

    res.json({ event: { id: ev.id, name: ev.name } });
  } catch {
    res.json({ event: null });
  }
});

// ---------- Admin middlewares ----------
function adminApi(req, res, next) {
  if (req.cookies.admin === 'true') return next();
  return res.status(403).json({ error: 'Ikke autoriseret' });
}
function masterApi(req, res, next) {
  if (req.cookies.admin !== 'true') return res.status(403).json({ error: 'Ikke autoriseret' });
  const user = coreDb.get('users').find({ username: req.cookies.adminUser }).value();
  if (!user || user.role !== 'owner') return res.status(403).json({ error: 'Kun master' });
  return next();
}
function withTenantDb(req, res, next) {
  try {
    const tenant = resolveTenantFromReq(req) || req.cookies.adminUser;
    if (!tenant) return res.status(400).json({ error: 'Mangler tenant' });
    req.tenant = tenant;
    req.tenantDb = getTenantDb(tenant);
    next();
  } catch (e) {
    res.status(400).json({ error: e.message || 'Tenant fejl' });
  }
}

// ---------- Admin Info ----------
app.get('/api/admin/me', adminApi, (req, res) => {
  const user = coreDb.get('users').find({ username: req.cookies.adminUser }).value();
  if (!user) return res.status(404).json({ error: 'Bruger ikke fundet' });
  res.json({ username: user.username, role: user.role });
});

// ---------- Admin (tenant-scoped) ----------
app.use('/api/admin', adminApi, withTenantDb);

// tasks
app.post('/api/admin/tasks', (req, res) => {
  const { title, options } = req.body;
  const id = uuidv4();
  req.tenantDb.get('tasks').push({ id, title, options }).write();
  res.json({ id });
});
app.delete('/api/admin/tasks/:id', (req, res) => {
  const taskId = req.params.id;
  req.tenantDb.get('tasks').remove({ id: taskId }).write();
  req.tenantDb.get('records').remove({ taskId }).write();
  res.json({ ok: true });
});

// teams
app.post('/api/admin/teams/create', (req, res) => {
  const count = parseInt(req.body.count, 10) || 1;
  const teams = [];
  for (let i = 0; i < count; i++) {
    const id = uuidv4();
    const name = `Hold ${req.tenantDb.get('teams').size().value() + 1}`;
    req.tenantDb.get('teams').push({ id, name, score: 0 }).write();
    teams.push({ id, name });
  }
  res.json({ teams });
});
app.post('/api/admin/teams/reset', (req, res) => {
  req.tenantDb.set('teams', []).write();
  req.tenantDb.set('records', []).write();
  res.json({ ok: true });
});

// events
app.post('/api/admin/events', (req, res) => {
  const { name, teamIds = [], taskIds = [] } = req.body;
  if (!name) return res.status(400).json({ error: 'Mangler navn' });
  const id = uuidv4();
  req.tenantDb.get('events').push({ id, name, teamIds, taskIds, created: Date.now() }).write();
  res.json({ id });
});
app.get('/api/admin/events', (req, res) => {
  res.json({ events: req.tenantDb.get('events').value() });
});
app.get('/api/admin/events/:id', (req, res) => {
  const ev = req.tenantDb.get('events').find({ id: req.params.id }).value();
  if (!ev) return res.status(404).json({ error: 'Event ikke fundet' });
  res.json({ event: ev });
});
app.post('/api/admin/events/:id/append', (req, res) => {
  const ev = req.tenantDb.get('events').find({ id: req.params.id }).value();
  if (!ev) return res.status(404).json({ error: 'Event ikke fundet' });
  const addTeams = Array.isArray(req.body.teamIds) ? req.body.teamIds : [];
  const addTasks = Array.isArray(req.body.taskIds) ? req.body.taskIds : [];
  const next = {
    ...ev,
    teamIds: Array.from(new Set([...(ev.teamIds || []), ...addTeams])),
    taskIds: Array.from(new Set([...(ev.taskIds || []), ...addTasks])),
  };
  req.tenantDb.get('events').find({ id: ev.id }).assign(next).write();
  res.json({ event: next });
});

// logs
app.get('/api/admin/logs', (req, res) => {
  const teamId = req.query.teamId || null;
  const logsRaw = req.tenantDb.get('logs').value().filter(l => !teamId || l.teamId === teamId);

  const teamsById  = Object.fromEntries(req.tenantDb.get('teams').value().map(t => [t.id, t]));
  const tasksById  = Object.fromEntries(req.tenantDb.get('tasks').value().map(t => [t.id, t]));
  const eventsById = Object.fromEntries(req.tenantDb.get('events').value().map(e => [e.id, e]));

  const logs = logsRaw
    .slice()
    .sort((a,b) => b.time - a.time)
    .map(l => {
      const teamName  = (l.teamId && teamsById[l.teamId] ? teamsById[l.teamId].name : '—');
      const taskTitle = (l.taskId && tasksById[l.taskId] ? tasksById[l.taskId].title : '');
      const eventName = (l.eventId && eventsById[l.eventId] ? eventsById[l.eventId].name : '');
      let message = '';
      if (l.type === 'join') {
        message = `Enhed tilføjet til ${teamName}${eventName ? ` (event: ${eventName})` : ''}.`;
      } else if (l.type === 'answer') {
        const korrekt = (l.points || 0) > 0 ? 'rigtigt' : 'forkert';
        message = `${teamName} svarede på "${taskTitle}" ${korrekt} og fik ${l.points || 0} point${eventName ? ` (event: ${eventName})` : ''}.`;
      } else if (l.type === 'bonus') {
        const by = l.by || 'admin';
        message = `${by} gav ${l.points || 0} bonuspoint til ${teamName}.`;
      } else {
        message = 'Ukendt hændelse.';
      }
      return { id: l.id, type: l.type, time: l.time, message, teamId: l.teamId || null, eventId: l.eventId || null, taskId: l.taskId || null, points: l.points || 0 };
    });

  res.json({ logs });
});
app.post('/api/admin/logs/clear', (req, res) => {
  req.tenantDb.set('logs', []).write();
  res.json({ ok: true });
});

// backup (tenant's own)
app.get('/api/admin/backup', (req, res) => {
  const file = path.join(TENANTS_DIR, `${req.tenant}.json`);
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  res.download(file, `${req.tenant}-backup-${stamp}.json`);
});

// reset scores & records
app.post('/api/admin/reset', (req, res) => {
  req.tenantDb.set('records', []).write();
  req.tenantDb.get('teams').forEach(t => req.tenantDb.get('teams').find({ id: t.id }).assign({ score: 0 }).write()).value();
  res.json({ ok: true });
});

// state
app.get('/api/admin/state', (req, res) => {
  res.json({ teams: req.tenantDb.get('teams').value(), tasks: req.tenantDb.get('tasks').value() });
});

// bonus (+ log)
app.post('/api/admin/bonus', (req, res) => {
  const { teamId, extra } = req.body;
  const add = Number(extra) || 0;
  req.tenantDb.get('teams').find({ id: teamId }).update('score', n => n + add).write();
  const byUser = coreDb.get('users').find({ username: req.cookies.adminUser }).value();
  req.tenantDb.get('logs').push({ id: uuidv4(), type: 'bonus', teamId, points: add, by: byUser ? byUser.username : 'admin', time: Date.now() }).write();
  res.json({ ok: true });
});

// ---------- Master admin ----------
app.get('/api/master/me', masterApi, (req, res) => {
  const user = coreDb.get('users').find({ username: req.cookies.adminUser }).value();
  res.json({ username: user.username, role: user.role });
});
app.get('/api/master/users', masterApi, (req, res) => {
  const users = coreDb.get('users').value().map(u => ({ id: u.id, username: u.username, role: u.role || 'admin', created: u.created || null }));
  res.json({ users });
});
app.post('/api/master/users', masterApi, (req, res) => {
  const { username, password, role } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Manglende felter' });
  if (coreDb.get('users').find({ username }).value()) return res.status(409).json({ error: 'Brugernavn findes allerede' });
  const { salt, hash } = hashPassword(password);
  coreDb.get('users').push({ id: uuidv4(), username, salt, hash, role: role === 'owner' ? 'owner' : 'admin', created: Date.now() }).write();
  // create empty tenant db
  getTenantDb(username);
  res.json({ ok: true });
});
app.get('/api/master/backup/:tenant', masterApi, (req, res) => {
  const tenant = String(req.params.tenant || '').trim();
  if (!tenant) return res.status(400).json({ error: 'Mangler tenant' });
  const file = path.join(TENANTS_DIR, `${tenant}.json`);
  if (!fs.existsSync(file)) return res.status(404).json({ error: 'Tenant DB ikke fundet' });
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  res.download(file, `${tenant}-backup-${stamp}.json`);
});

// ---------- Start server ----------
const HOST = '0.0.0.0';
const PORT = process.env.PORT || 3000;
app.listen(PORT, HOST, () => console.log(`Server kører på http://${HOST}:${PORT}`));
