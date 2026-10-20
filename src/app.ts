import 'dotenv/config';
import express from 'express';
import { Pool } from 'pg';
import { auth as oidc, requiresAuth } from 'express-openid-connect';
import { auth as jwtAuth, requiredScopes } from 'express-oauth2-jwt-bearer';
import QRCode from 'qrcode';
import { randomUUID } from 'node:crypto';


const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) {
  throw new Error('DATABASE_URL is not set');
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: DATABASE_URL.includes('render.com') ? { rejectUnauthorized: false } : false,
});


const PORT = Number(process.env.PORT ?? 3000);
const BASE_URL = process.env.RENDER_EXTERNAL_URL ?? `http://localhost:${PORT}`;

const app = express();
app.set('trust proxy', true); // Render runs behind a proxy


interface PassRow {
  id: string;
  name: string;
  document: string;
  issued_at: Date; // pg returns timestamptz as a JS Date
  status: 'ACTIVE' | 'CANCELLED';
}


function escapeHtml(value: unknown): string {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
function isUuid(id: string): boolean {
  return UUID_RE.test(id);
}

function toJson(row: PassRow) {
  return {
    id: row.id,
    name: row.name,
    document: row.document,
    issuedAt: row.issued_at.toISOString(),
    status: row.status,
  };
}

app.use(
  oidc({
    authRequired: false,
    auth0Logout: true, // also end the Auth0 session on /logout
    issuerBaseURL: process.env.AUTH0_ISSUER,
    baseURL: BASE_URL,
    clientID: process.env.AUTH0_WEB_CLIENT_ID,
    secret: process.env.SESSION_SECRET,
  }),
);

const checkJwt = jwtAuth({
  audience: process.env.AUTH0_AUDIENCE,
  issuerBaseURL: process.env.AUTH0_ISSUER,
});


function page(title: string, body: string): string {
  return `<!doctype html>
<html lang="hr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(title)}</title>
  <style>
    body { font-family: system-ui, sans-serif; margin: 2rem; }
    table { border-collapse: collapse; }
    th, td { border: 1px solid #ccc; padding: .4rem .6rem; text-align: left; }
    form { display: inline; }
  </style>
</head>
<body>
${body}
</body>
</html>`;
}

// public home page with counterrs
app.get('/', async (req, res) => {
  const { rows: [counts] } = await pool.query<{ total: number; active: number }>(
    `SELECT count(*)::int AS total,
            count(*) FILTER (WHERE status = 'ACTIVE')::int AS active
       FROM passes`,
  );

  let body = `<h1>Digitalne propusnice</h1>
<p>Ukupno propusnica: <strong>${counts.total}</strong></p>
<p>Aktivnih propusnica: <strong>${counts.active}</strong></p>`;

  if (!req.oidc.isAuthenticated()) {
    body += `<p><a href="/login">Prijava</a></p>`;
    res.send(page('Propusnice', body));
    return;
  }

  const user = req.oidc.user?.email ?? req.oidc.user?.name ?? '';
  body += `<p>Prijavljeni ste kao ${escapeHtml(user)} – <a href="/logout">Odjava</a></p>`;

  const { rows } = await pool.query<PassRow>(
    'SELECT id, name, document, issued_at, status FROM passes ORDER BY issued_at DESC',
  );

  if (rows.length === 0) {
    body += '<p>Nema propusnica.</p>';
  } else {
    body += `<table>
<tr><th>ID</th><th>Ime i prezime</th><th>Dokument</th><th>Izdano</th><th>Status</th><th>Akcije</th></tr>
${rows
  .map((p) => {
    const id = escapeHtml(p.id);
    return `<tr>
  <td><a href="/info/${id}">${id}</a></td>
  <td>${escapeHtml(p.name)}</td>
  <td>${escapeHtml(p.document)}</td>
  <td>${escapeHtml(p.issued_at.toISOString())}</td>
  <td>${escapeHtml(p.status)}</td>
  <td>
    <form method="post" action="/admin/passes/${id}/cancel"><button${p.status === 'CANCELLED' ? ' disabled' : ''}>Poništi</button></form>
    <form method="post" action="/admin/passes/${id}/delete"><button>Obriši</button></form>
  </td>
</tr>`;
  })
  .join('\n')}
</table>`;
  }

  res.send(page('Propusnice', body));
});

// samo za ulogirane korisnike
app.post('/admin/passes/:id/cancel', requiresAuth(), async (req, res) => {
  const id = String(req.params.id);
  if (!isUuid(id)) {
    res.sendStatus(404);
    return;
  }
  await pool.query(`UPDATE passes SET status = 'CANCELLED' WHERE id = $1`, [id]);
  res.redirect('/');
});

// samo za ulogirane korisnike
app.post('/admin/passes/:id/delete', requiresAuth(), async (req, res) => {
  const id = String(req.params.id);
  if (!isUuid(id)) {
    res.sendStatus(404);
    return;
  }
  await pool.query('DELETE FROM passes WHERE id = $1', [id]);
  res.redirect('/');
});

// javna stranica iz qr koda
app.get('/info/:id', async (req, res) => {
  const id = String(req.params.id);
  const notFound = page('Propusnica nije pronađena', '<h1>404 – Propusnica ne postoji</h1>');
  if (!isUuid(id)) {
    res.status(404).send(notFound);
    return;
  }

  const { rows } = await pool.query<PassRow>(
    'SELECT id, name, document, issued_at, status FROM passes WHERE id = $1',
    [id],
  );
  const p = rows[0];
  if (!p) {
    res.status(404).send(notFound);
    return;
  }

  res.send(
    page(
      'Propusnica',
      `<h1>Propusnica</h1>
<p>Status: <strong>${escapeHtml(p.status)}</strong></p>
<p>Ime i prezime: ${escapeHtml(p.name)}</p>
<p>Dokument: ${escapeHtml(p.document)}</p>
<p>Vrijeme izdavanja: ${escapeHtml(p.issued_at.toISOString())}</p>`,
    ),
  );
});

// M2M api, scope read:passes
app.get('/passes/:id', checkJwt, requiredScopes('read:passes'), async (req, res) => {
  const id = String(req.params.id);
  if (!isUuid(id)) {
    res.sendStatus(404);
    return;
  }

  const { rows } = await pool.query<PassRow>(
    'SELECT id, name, document, issued_at, status FROM passes WHERE id = $1',
    [id],
  );
  if (rows.length === 0) {
    res.sendStatus(404);
    return;
  }
  res.status(200).json(toJson(rows[0]));
});

// M2M api, scope create:passes
app.post('/passes', checkJwt, requiredScopes('create:passes'), express.json(), async (req, res) => {
  const { name, document } = req.body ?? {};
  if (typeof name !== 'string' || !name.trim() || typeof document !== 'string' || !document.trim()) {
    res.sendStatus(400);
    return;
  }

  const id = randomUUID();
  await pool.query('INSERT INTO passes (id, name, document) VALUES ($1, $2, $3)', [id, name, document]);

  const png = await QRCode.toBuffer(`${BASE_URL}/info/${id}`); // QR → public page
  res
    .status(201)
    .location(`${BASE_URL}/passes/${id}`) // Location → API endpoint
    .type('image/png')
    .send(png);
});


const onError: express.ErrorRequestHandler = (err, _req, res, next) => {
  if (res.headersSent) {
    next(err);
    return;
  }

  const status =
    Number.isInteger(err?.status) && err.status >= 400 && err.status < 600 ? err.status : 500;

  if (status >= 500) {
    console.error(err);
  }

  if (err?.headers && typeof err.headers === 'object') {
    res.set(err.headers);
  }

  res.sendStatus(status);
};
app.use(onError);

// --- Startup: create the table, then start listening -------------------------

async function start(): Promise<void> {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS passes (
      id        uuid PRIMARY KEY,
      name      text NOT NULL,
      document  text NOT NULL,
      issued_at timestamptz NOT NULL DEFAULT now(),
      status    text NOT NULL DEFAULT 'ACTIVE'
    )
  `);

  app.listen(PORT, () => {
    console.log(`Server listening on port ${PORT} (${BASE_URL})`);
  });
}

start().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
