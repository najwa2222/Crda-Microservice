import express from 'express';
import mysql from 'mysql2/promise';
import cors from 'cors';
import session from 'express-session';
import bcrypt from 'bcrypt';
import helmet from 'helmet';
import methodOverride from 'method-override';
import dotenv from 'dotenv';
import MySQLStoreFactory from 'express-mysql-session';
import { registry } from './utils/metrics.js';
import { metricsMiddleware } from './utils/metricsMiddleware.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT;

if (!NODE_ENV) {
  NODE_ENV = 'development';
}

const DB_CONFIG = {
  host: process.env.MYSQL_HOST,
  user: process.env.MYSQL_USER,
  password: process.env.MYSQL_PASSWORD,
  database: process.env.MYSQL_DATABASE,
  port: process.env.MYSQL_PORT ? Number(process.env.MYSQL_PORT) : 3306
};

const MySQLStore = MySQLStoreFactory(session);
const sessionStore = new MySQLStore(DB_CONFIG);
const SESSION_SECRET = process.env.SESSION_SECRET || 'default-insecure-secret';

let connection;
async function initializeDatabase(retries = 5) {
  try {
    connection = await mysql.createConnection(DB_CONFIG);
    console.log(`Connected to MySQL (${connection.threadId})`);
  } catch (err) {
    if (retries > 0) {
      console.log(`Retrying DB connection… (${6 - retries}/5)`);
      setTimeout(() => initializeDatabase(retries - 1), 5000);
    } else {
      console.error('Could not connect to MySQL:', err.message);
      process.exit(1);
    }
  }
}

// — Middleware —
app.use(metricsMiddleware);
app.use(helmet({ contentSecurityPolicy: { useDefaults: true } }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors({ origin: process.env.CORS_ORIGIN || '*', credentials: true }));
app.use(methodOverride('_method'));
app.use(session({
  secret: SESSION_SECRET,
  resave: true,
  saveUninitialized: true,
  store: sessionStore,
  cookie: { secure: false, httpOnly: true, sameSite: 'lax', maxAge: 86400000 }
}));
app.use((req, res, next) => {
  if (!connection) return res.status(503).json({ error: 'DB not ready' });
  next();
});

// ========== Health & Metrics ==========
// Health checks
app.get('/health', async (req, res) => {
  try {
    if (process.env.NODE_ENV === 'test') return res.status(200).send('OK');
    const mysqlModule = await import('mysql2/promise');
    const conn = await mysqlModule.createConnection(process.env.DB_URL);
    await conn.query('SELECT 1');
    await conn.end();
    res.status(200).send('OK');
  } catch (err) {
    console.error('Health check failed:', err.message);
    res.status(500).send('DB query failed');
  }
});
app.get('/livez', (req, res) => res.status(200).send('CRDA backend is up'));
app.get('/health-pod', async (req, res) => {
  try {
    await pool.execute('SELECT 1');
    res.status(200).send('OK');
  } catch (err) {
    console.error('Health pod check failed:', err.message);
    res.status(500).send('DB connection failed');
  }
});

app.get('/metrics', async (req, res) => {
  try {
    res.set('Content-Type', register.contentType);
    res.end(await register.metrics());
  } catch (err) {
    console.error('Error generating metrics:', err);
    res.status(500).end();
  }
});

// — Auth Helpers —
const isAuthenticated = (req, res, next) => {
  if (req.session.user) return next();
  res.status(401).json({ error: 'Not authenticated' });
};

// ========== Authentication ==========
app.post('/login', async (req, res) => {
  try {
    const { email_user, password_user } = req.body;
    const [rows] = await connection.query(
      'SELECT * FROM utilisateur WHERE email_user = ?', [email_user]
    );
    if (!rows.length) return res.status(401).json({ error: 'Invalid credentials' });
    const user = rows[0];
    const match = await bcrypt.compare(password_user, user.password_user);
    if (!match) return res.status(401).json({ error: 'Invalid credentials' });
    if (user.status_user !== 'approved') {
      return res.status(403).json({ error: 'Account not approved' });
    }
    req.session.user = {
      id: user.id,
      email_user: user.email_user,
      role_user: user.role_user,
      nom_user: user.nom_user,
      prenom_user: user.prenom_user
    };
    res.json({ user: req.session.user });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.status(204).end());
});

app.post('/register', async (req, res) => {
  try {
    const { email_user, password_user, role_user, nom_user, prenom_user, sex_user, cin_user } = req.body;
    if (!email_user.endsWith('@crda.com')) {
      return res.status(400).json({ error: 'Invalid email domain' });
    }
    const [exist] = await connection.query(
      'SELECT id FROM utilisateur WHERE email_user = ? OR cin_user = ?', [email_user, cin_user]
    );
    if (exist.length) return res.status(409).json({ error: 'Already exists' });
    const hash = await bcrypt.hash(password_user, 10);
    await connection.query(
      `INSERT INTO utilisateur
       (email_user, password_user, role_user, status_user, nom_user, prenom_user, sex_user, cin_user)
       VALUES (?, ?, ?, 'pending', ?, ?, ?, ?)`,
      [email_user, hash, role_user, nom_user, prenom_user, sex_user, cin_user]
    );
    res.status(201).json({ message: 'Registration pending approval' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ========== Services ==========
app.get('/services', isAuthenticated, async (req, res) => {
  try {
    const [rows] = await connection.query(`
      SELECT s.*, IF(r.id IS NOT NULL,'تم','قيد الانتظار') AS status
      FROM services_utilisateur s
      LEFT JOIN rapport r ON s.cin = r.cin AND s.sujet = r.sujet
    `);
    res.json({ services: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/services', isAuthenticated, async (req, res) => {
  try {
    const {
      sujet, prenom, nom, cin, numero_transaction,
      certificat_propriete_terre, copie_piece_identite_fermier,
      copie_piece_identite_nationale, demande_but,
      copie_contrat_location_terrain, autres_documents
    } = req.body;
    await connection.query(
      `INSERT INTO services_utilisateur
       (sujet, prenom, nom, cin, numero_transaction,
        certificat_propriete_terre, copie_piece_identite_fermier,
        copie_piece_identite_nationale, demande_but,
        copie_contrat_location_terrain, autres_documents)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        sujet, prenom, nom, cin, numero_transaction,
        !!certificat_propriete_terre,
        !!copie_piece_identite_fermier,
        !!copie_piece_identite_nationale,
        !!demande_but,
        !!copie_contrat_location_terrain,
        !!autres_documents
      ]
    );
    res.status(201).json({ message: 'Service added' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/services/:id', isAuthenticated, async (req, res) => {
  try {
    const {
      sujet, prenom, nom, cin, numero_transaction,
      certificat_propriete_terre, copie_piece_identite_fermier,
      copie_piece_identite_nationale, demande_but,
      copie_contrat_location_terrain, autres_documents
    } = req.body;
    await connection.query(
      `UPDATE services_utilisateur
       SET sujet=?, prenom=?, nom=?, cin=?, numero_transaction=?,
           certificat_propriete_terre=?, copie_piece_identite_fermier=?,
           copie_piece_identite_nationale=?, demande_but=?,
           copie_contrat_location_terrain=?, autres_documents=?
       WHERE id=?`,
      [
        sujet, prenom, nom, cin, numero_transaction,
        !!certificat_propriete_terre,
        !!copie_piece_identite_fermier,
        !!copie_piece_identite_nationale,
        !!demande_but,
        !!copie_contrat_location_terrain,
        !!autres_documents,
        req.params.id
      ]
    );
    res.json({ message: 'Service updated' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/services/:id', isAuthenticated, async (req, res) => {
  try {
    await connection.query('DELETE FROM services_utilisateur WHERE id=?', [req.params.id]);
    res.json({ message: 'Service deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ========== Reports ==========
app.get('/reports', isAuthenticated, async (req, res) => {
  try {
    const [rows] = await connection.query('SELECT * FROM rapport');
    res.json({ reports: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/reports/:id', isAuthenticated, async (req, res) => {
  try {
    const [rows] = await connection.query('SELECT * FROM rapport WHERE id=?', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    res.json({ report: rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/reports', isAuthenticated, async (req, res) => {
  try {
    const { cin, sujet, nom, prenom, surface, limites_terrain,
      localisation, superficie_batiments_anciens, observations } = req.body;
    if (!cin || !sujet) {
      return res.status(400).json({ error: 'cin & sujet required' });
    }
    const [[service]] = await connection.query(
      'SELECT numero_transaction FROM services_utilisateur WHERE cin=? AND sujet=?',
      [cin, sujet]
    );
    if (!service) return res.status(404).json({ error: 'Service not found' });
    await connection.beginTransaction();
    await connection.query(
      `INSERT INTO rapport
       (cin, sujet, nom, prenom, surface, limites_terrain,
        localisation, superficie_batiments_anciens, observations, numero_transaction)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [cin, sujet, nom, prenom, surface, limites_terrain,
        localisation, superficie_batiments_anciens, observations,
        service.numero_transaction]
    );
    await connection.query(
      'UPDATE services_utilisateur SET status="تم" WHERE cin=? AND sujet=?',
      [cin, sujet]
    );
    await connection.commit();
    res.status(201).json({ message: 'Report added' });
  } catch (err) {
    await connection.rollback();
    res.status(500).json({ error: err.message });
  }
});

app.put('/reports/:id', isAuthenticated, async (req, res) => {
  try {
    const { surface, limites_terrain, localisation,
      superficie_batiments_anciens, observations } = req.body;
    await connection.query(
      `UPDATE rapport
       SET surface=?, limites_terrain=?, localisation=?,
           superficie_batiments_anciens=?, observations=?
       WHERE id=?`,
      [surface, limites_terrain, localisation,
        superficie_batiments_anciens, observations,
        req.params.id]
    );
    res.json({ message: 'Report updated' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/reports/:id', isAuthenticated, async (req, res) => {
  try {
    const [[r]] = await connection.query('SELECT cin,sujet FROM rapport WHERE id=?', [req.params.id]);
    if (!r) return res.status(404).json({ error: 'Not found' });
    await connection.beginTransaction();
    await connection.query('DELETE FROM results WHERE cin=? AND sujet=?', [r.cin, r.sujet]);
    await connection.query('DELETE FROM rapport WHERE id=?', [req.params.id]);
    await connection.commit();
    res.json({ message: 'Report deleted' });
  } catch (err) {
    await connection.rollback();
    res.status(500).json({ error: err.message });
  }
});

// ========== Results ==========
app.get('/results', isAuthenticated, async (req, res) => {
  try {
    const [rows] = await connection.query(`
      SELECT s.*, r.statut, rap.id AS report_id
      FROM services_utilisateur s
      LEFT JOIN results r ON s.cin=r.cin AND s.sujet=r.sujet
      INNER JOIN rapport rap ON s.cin=rap.cin AND s.sujet=rap.sujet
      ORDER BY s.id DESC
    `);
    res.json({ results: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/results', isAuthenticated, async (req, res) => {
  try {
    const { sujet, nom, prenom, cin, numero_transaction, statut } = req.body;
    const allowed = ['مقبول', 'مرفوض'];
    if (!allowed.includes(statut)) {
      return res.status(400).json({ error: 'Invalid status' });
    }
    await connection.query(
      `INSERT INTO results (sujet,nom,prenom,cin,numero_transaction,statut)
       VALUES (?,?,?,?,?,?)
       ON DUPLICATE KEY UPDATE statut=?`,
      [sujet, nom, prenom, cin, numero_transaction, statut, statut]
    );
    res.json({ message: 'Result saved' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/results', isAuthenticated, async (req, res) => {
  try {
    const { cin, numero_transaction } = req.body;
    await connection.query(
      'DELETE FROM results WHERE cin=? AND numero_transaction=?',
      [cin, numero_transaction]
    );
    res.json({ message: 'Result deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ========== Check-Status ==========
app.post('/check-status', async (req, res) => {
  try {
    const { cin, transaction_number } = req.body;
    if (!cin || !transaction_number) {
      return res.status(400).json({ error: 'cin & transaction_number required' });
    }
    const [[service]] = await connection.query(
      'SELECT * FROM services_utilisateur WHERE cin=? AND numero_transaction=?',
      [cin, transaction_number]
    );
    if (!service) {
      return res.status(404).json({ error: 'No matching service' });
    }
    const [[rep]] = await connection.query(
      'SELECT * FROM rapport WHERE cin=? AND numero_transaction=?',
      [cin, transaction_number]
    );
    const [[resu]] = await connection.query(
      'SELECT * FROM results WHERE cin=? AND numero_transaction=?',
      [cin, transaction_number]
    );
    let statut;
    if (resu) statut = resu.statut;
    else if (rep) statut = 'بصدد الدرس';
    else statut = 'في انتظار التقرير';

    res.json({ service, statut });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// — Global Error & Start —
app.use((err, req, res, next) => {
  console.error(err);
  res.status(err.status || 500).json({ error: 'Unexpected error' });
});

initializeDatabase().then(() => {
  app.listen(PORT, () => {
    console.log(`CRDA‐backend API listening on port ${PORT}`);
  });
});
