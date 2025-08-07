// server.js
const express      = require('express');
const path         = require('path');
const cookieParser = require('cookie-parser');
const { v4: uuidv4 } = require('uuid');
const low           = require('lowdb');
const FileSync     = require('lowdb/adapters/FileSync');

const app = express();

// --- LowDB setup ---
const dbFile  = path.join(__dirname, 'db.json');
const adapter = new FileSync(dbFile);
const db      = low(adapter);
// Init defaults
db.defaults({ teams: [], tasks: [], records: [] }).write();

// --- Middleware ---
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

// --- Public Routes ---
// Login page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});
// Handle login
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (username === 'mago' && password === 'qyy82xpm') {
    res.cookie('admin', 'true', { httpOnly: true });
    return res.redirect('/admin.html');
  }
  res.redirect('/?error=1');
});
// Serve static files
app.use(express.static(__dirname));

// Join team
app.get('/join.html', (req, res) => {
  const { teamId } = req.query;
  if (!db.get('teams').find({ id: teamId }).value()) {
    return res.status(400).send('Ugyldigt teamId');
  }
  res.cookie('teamId', teamId, { httpOnly: false });
  res.redirect('/joined.html');
});

// Scan QR and redirect with feedback flags
app.get('/scan', (req, res) => {
  const { taskId, optionIndex } = req.query;
  const teamId = req.cookies.teamId;
  if (!teamId) return res.redirect('/join.html');
  // Already answered?
  if (db.get('records').find({ teamId, taskId }).value()) {
    return res.redirect('/joined.html?already=true');
  }
  const task = db.get('tasks').find({ id: taskId }).value();
  if (!task) return res.status(400).send('Ugyldig opgave');
  const idx = parseInt(optionIndex, 10);
  const opt = task.options[idx];
  if (!opt) return res.status(400).send('Ugyldig svar');

  // Save record and update score
  db.get('records')
    .push({ id: uuidv4(), teamId, taskId, optionIndex: idx, points: opt.points, time: Date.now() })
    .write();
  db.get('teams')
    .find({ id: teamId })
    .update('score', n => n + opt.points)
    .write();

  // Redirect with points feedback
  const feedbackParam = `?points=${opt.points}`;
  res.redirect(`/joined.html${feedbackParam}`);
});

// --- Public API ---
app.post('/api/tasks', (req, res) => {
  const { title, options } = req.body;
  const id = uuidv4();
  db.get('tasks').push({ id, title, options }).write();
  res.json({ id });
});

// --- Admin API Middleware ---
const adminApi = (req, res, next) => {
  if (req.cookies.admin === 'true') return next();
  res.status(403).json({ error: 'Ikke autoriseret' });
};
app.use('/api/admin', adminApi);

// Create teams in batch
app.post('/api/admin/teams/create', (req, res) => {
  const count = parseInt(req.body.count, 10) || 1;
  const teams = [];
  for (let i = 0; i < count; i++) {
    const id = uuidv4();
    const name = `Hold ${db.get('teams').size().value() + 1}`;
    db.get('teams').push({ id, name, score: 0 }).write();
    teams.push({ id, name });
  }
  res.json({ teams });
});
// Reset Hold: delete teams and records
app.post('/api/admin/teams/reset', (req, res) => {
  db.set('teams', []).write();
  db.set('records', []).write();
  res.json({ ok: true });
});
// Reset Event: reset scores and records
app.post('/api/admin/reset', (req, res) => {
  db.set('records', []).write();
  db.get('teams').forEach(t =>
    db.get('teams').find({ id: t.id }).assign({ score: 0 }).write()
  ).value();
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
// Bonus points
app.post('/api/admin/bonus', (req, res) => {
  const { teamId, extra } = req.body;
  db.get('teams').find({ id: teamId }).update('score', n => n + Number(extra)).write();
  res.json({ ok: true });
});

// --- Joined page score API ---
app.get('/api/score', (req, res) => {
  const teamId = req.cookies.teamId;
  if (!teamId) return res.status(400).json({ error: 'Ikke tilknyttet hold' });
  const team = db.get('teams').find({ id: teamId }).value();
  if (!team) return res.status(404).json({ error: 'Hold ikke fundet' });
  // Return both score and team name
  res.json({ score: team.score, name: team.name });
});

// --- Start server ---
const HOST = '0.0.0.0';
const PORT = process.env.PORT || 3000;
app.listen(PORT, HOST, () => console.log(`Server kører på http://${HOST}:${PORT}`));
