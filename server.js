// server.js
const express      = require('express');
const path         = require('path');
const cookieParser = require('cookie-parser');
const crypto       = require('crypto');
const { v4: uuidv4 } = require('uuid');
const low           = require('lowdb');
const FileSync      = require('lowdb/adapters/FileSync');

const app = express();

// --- LowDB setup (OLD API) ---
const dbFile  = path.join(__dirname, 'db.json');
const adapter = new FileSync(dbFile);
const db      = low(adapter);
// Init defaults
db.defaults({ users: [], teams: [], tasks: [], records: [], events: [], logs: [] }).write();

// --- Utils (password hashing for users) ---
function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
  return { salt, hash };
}
function verifyPassword(password, user) {
  const test = crypto.pbkdf2Sync(password, user.salt, 100000, 64, 'sha512').toString('hex');
  return test === user.hash;
}

// --- Middleware ---
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

// --- Protect admin.html directly (before static) ---
app.get('/admin.html', (req, res) => {
  if (req.cookies.admin === 'true') return res.sendFile(path.join(__dirname, 'admin.html'));
  return res.redirect('/?needLogin=1');
});

// --- Public Routes ---
app.get('/', (req, res) => { res.sendFile(path.join(__dirname, 'index.html')); });

// First-time setup
app.get('/api/auth/hasUsers', (req, res) => {
  const hasUsers = db.get('users').size().value() > 0; res.json({ hasUsers });
});
app.post('/api/auth/setup', (req, res) => {
  const { username, password } = req.body;
  const hasUsers = db.get('users').size().value() > 0;
  if (hasUsers) return res.status(400).json({ error: 'Allerede konfigureret' });
  if (!username || !password) return res.status(400).json({ error: 'Manglende felter' });
  const { salt, hash } = hashPassword(password);
  db.get('users').push({ id: uuidv4(), username, salt, hash, created: Date.now() }).write();
  res.cookie('admin', 'true', { httpOnly: true });
  res.cookie('adminUser', username, { httpOnly: true });
  res.json({ ok: true });
});

// Login/logout
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = db.get('users').find({ username }).value();
  if (!user || !verifyPassword(password, user)) return res.redirect('/?error=1');
  res.cookie('admin', 'true', { httpOnly: true });
  res.cookie('adminUser', username, { httpOnly: true });
  res.redirect('/admin.html');
});
app.post('/logout', (req, res) => { res.clearCookie('admin'); res.clearCookie('adminUser'); res.redirect('/'); });

// Serve static files
app.use(express.static(__dirname));

// Join team (supports optional eventId in URL)
app.get('/join.html', (req, res) => {
  const { teamId, eventId } = req.query;
  const team = db.get('teams').find({ id: teamId }).value();
  if (!team) return res.status(400).send('Ugyldigt teamId');
  if (eventId) {
    const ev = db.get('events').find({ id: eventId }).value();
    if (!ev) return res.status(400).send('Ugyldigt eventId');
    if (!ev.teamIds.includes(teamId)) return res.status(403).send('Hold ikke med i event');
    res.cookie('eventId', eventId, { httpOnly: false });
  }
  res.cookie('teamId', teamId, { httpOnly: false });
  // Log JOIN action
  db.get('logs').push({ id: uuidv4(), type: 'join', teamId, eventId: eventId || null, time: Date.now() }).write();
  res.redirect('/joined.html');
});

// Scan QR (lock per task; respect event scope)
app.get('/scan', (req, res) => {
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

  // Lock: one answer per task per team
  if (db.get('records').find({ teamId, taskId }).value()) {
    return res.redirect('/joined.html?already=true');
  }

  const idx = parseInt(optionIndex, 10);
  const opt = task.options[idx];
  if (!opt) return res.status(400).send('Ugyldig svar');

  // Save record + update score
  db.get('records').push({ id: uuidv4(), teamId, taskId, optionIndex: idx, points: opt.points, eventId, time: Date.now() }).write();
  db.get('teams').find({ id: teamId }).update('score', n => n + opt.points).write();
  // Log ANSWER action
  db.get('logs').push({ id: uuidv4(), type: 'answer', teamId, taskId, optionIndex: idx, points: opt.points, eventId, time: Date.now() }).write();

  res.redirect(`/joined.html?points=${opt.points}`);
});

// --- Public API ---
app.post('/api/tasks', (req, res) => {
  const { title, options } = req.body; const id = uuidv4();
  db.get('tasks').push({ id, title, options }).write();
  res.json({ id });
});
app.get('/api/task/:id', (req, res) => {
  const task = db.get('tasks').find({ id: req.params.id }).value();
  if (!task) return res.status(404).json({ error: 'Ikke fundet' });
  res.json(task);
});

// --- Admin API Middleware ---
const adminApi = (req, res, next) => { if (req.cookies.admin === 'true') return next(); res.status(403).json({ error: 'Ikke autoriseret' }); };
app.use('/api/admin', adminApi);

// Teams
app.post('/api/admin/teams/create', (req, res) => {
  const count = parseInt(req.body.count, 10) || 1;
  const teams = [];
  for (let i = 0; i < count; i++) {
    const id = uuidv4(); const name = `Hold ${db.get('teams').size().value() + 1}`;
    db.get('teams').push({ id, name, score: 0 }).write();
    teams.push({ id, name });
  }
  res.json({ teams });
});
app.post('/api/admin/teams/reset', (req, res) => {
  db.set('teams', []).write(); db.set('records', []).write();
  res.json({ ok: true });
});

// Events
app.post('/api/admin/events', (req, res) => {
  const { name, teamIds = [], taskIds = [] } = req.body; if (!name) return res.status(400).json({ error: 'Mangler navn' });
  const id = uuidv4(); db.get('events').push({ id, name, teamIds, taskIds, created: Date.now() }).write();
  res.json({ id });
});
app.get('/api/admin/events', (req, res) => { res.json({ events: db.get('events').value() }); });

// NEW: get single event
app.get('/api/admin/events/:id', (req, res) => {
  const ev = db.get('events').find({ id: req.params.id }).value();
  if (!ev) return res.status(404).json({ error: 'Event ikke fundet' });
  res.json({ event: ev });
});

// NEW: append teams/tasks to existing event
app.post('/api/admin/events/:id/append', (req, res) => {
  const ev = db.get('events').find({ id: req.params.id }).value();
  if (!ev) return res.status(404).json({ error: 'Event ikke fundet' });

  const addTeams = Array.isArray(req.body.teamIds) ? req.body.teamIds : [];
  const addTasks = Array.isArray(req.body.taskIds) ? req.body.taskIds : [];

  const next = {
    ...ev,
    teamIds: Array.from(new Set([...(ev.teamIds || []), ...addTeams])),
    taskIds: Array.from(new Set([...(ev.taskIds || []), ...addTasks])),
  };
  db.get('events').find({ id: ev.id }).assign(next).write();
  res.json({ event: next });
});

// Users (admin creates more)
app.get('/api/admin/users', (req, res) => {
  const users = db.get('users').value().map(u => ({ id: u.id, username: u.username, created: u.created || null }));
  res.json({ users });
});
app.post('/api/admin/users', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Manglende felter' });
  if (db.get('users').find({ username }).value()) return res.status(409).json({ error: 'Brugernavn findes allerede' });
  const { salt, hash } = hashPassword(password);
  db.get('users').push({ id: uuidv4(), username, salt, hash, created: Date.now() }).write();
  res.json({ ok: true });
});

// Logs — human-readable message
app.get('/api/admin/logs', (req, res) => {
  const teamId = req.query.teamId || null;
  const logsRaw = db.get('logs').value().filter(l => !teamId || l.teamId === teamId);

  const teamsById  = Object.fromEntries(db.get('teams').value().map(t => [t.id, t]));
  const tasksById  = Object.fromEntries(db.get('tasks').value().map(t => [t.id, t]));
  const eventsById = Object.fromEntries(db.get('events').value().map(e => [e.id, e]));

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
      return {
        id: l.id, type: l.type, time: l.time, message,
        eventId: l.eventId || null, teamId: l.teamId || null, teamName,
        taskId: l.taskId || null, taskTitle, optionIndex: typeof l.optionIndex === 'number' ? l.optionIndex : null,
        points: typeof l.points === 'number' ? l.points : 0, by: l.by || null
      };
    });

  res.json({ logs });
});

// NEW: clear logs
app.post('/api/admin/logs/clear', (req, res) => {
  db.set('logs', []).write();
  res.json({ ok: true });
});

// Backup db.json
app.get('/api/admin/backup', (req, res) => {
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  res.download(dbFile, `db-backup-${stamp}.json`);
});

// Reset scores & records
app.post('/api/admin/reset', (req, res) => {
  db.set('records', []).write();
  db.get('teams').forEach(t => db.get('teams').find({ id: t.id }).assign({ score: 0 }).write()).value();
  res.json({ ok: true });
});

// Delete task
app.delete('/api/admin/tasks/:id', (req, res) => {
  const taskId = req.params.id;
  db.get('tasks').remove({ id: taskId }).write();
  db.get('records').remove({ taskId }).write();
  res.json({ ok: true });
});

// Admin state
app.get('/api/admin/state', (req, res) => {
  res.json({ teams: db.get('teams').value(), tasks: db.get('tasks').value() });
});

// Bonus points (+ log)
app.post('/api/admin/bonus', (req, res) => {
  const { teamId, extra } = req.body; const add = Number(extra) || 0;
  db.get('teams').find({ id: teamId }).update('score', n => n + add).write();
  db.get('logs').push({ id: uuidv4(), type: 'bonus', teamId, points: add, by: req.cookies.adminUser || 'admin', time: Date.now() }).write();
  res.json({ ok: true });
});

// Score API for joined.html
app.get('/api/score', (req, res) => {
  const teamId = req.cookies.teamId; if (!teamId) return res.status(400).json({ error: 'Ikke tilknyttet hold' });
  const team = db.get('teams').find({ id: teamId }).value(); if (!team) return res.status(404).json({ error: 'Hold ikke fundet' });
  res.json({ score: team.score, name: team.name });
});

// --- Start server ---
const HOST = '0.0.0.0';
const PORT = process.env.PORT || 3000;
app.listen(PORT, HOST, () => console.log(`Server kører på http://${HOST}:${PORT}`));
