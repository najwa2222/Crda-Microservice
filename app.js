// CRDA-backend/app.js
import dotenv from 'dotenv';
import express from 'express';
import helmet from 'helmet';
import * as mysql from 'mysql2/promise';
import bcrypt from 'bcrypt';
import cors from 'cors';
import session from 'express-session';
import MySQLStoreFactory from 'express-mysql-session';
import Prometheus from 'prom-client';

dotenv.config();

const app = express();

// Prometheus setup
const register = new Prometheus.Registry();
Prometheus.collectDefaultMetrics({ register });

// Custom metrics
const httpCounter = new Prometheus.Counter({
  name: 'http_requests_total',
  help: 'Total number of HTTP requests',
  labelNames: ['method', 'route', 'code'],
});
const httpHistogram = new Prometheus.Histogram({
  name: 'http_request_duration_seconds',
  help: 'HTTP request duration in seconds',
  labelNames: ['method', 'route', 'code'],
  buckets: [0.01, 0.05, 0.1, 0.5, 1, 2],
});
const dbCounter = new Prometheus.Counter({
  name: 'db_query_total',
  help: 'Total number of database queries',
  labelNames: ['operation'],
});
const dbHistogram = new Prometheus.Histogram({
  name: 'db_query_duration_seconds',
  help: 'Database query duration in seconds',
  labelNames: ['operation'],
  buckets: [0.001, 0.01, 0.1, 1],
});

// Register custom metrics
register.registerMetric(httpCounter);
register.registerMetric(httpHistogram);
register.registerMetric(dbCounter);
register.registerMetric(dbHistogram);

// DB Configuration
const DB_CONFIG = process.env.NODE_ENV === 'test' 
  ? {
      // Mock configuration for testing
      host: 'localhost',
      user: 'test',
      password: 'test',
      database: 'test',
      port: 3306,
      waitForConnections: true,
      connectionLimit: 2,
    }
  : {
      host: process.env.MYSQL_HOST,
      user: process.env.MYSQL_USER,
      password: process.env.MYSQL_PASSWORD,
      database: process.env.MYSQL_DATABASE,
      port: process.env.MYSQL_PORT ? Number(process.env.MYSQL_PORT) : 3306,
      waitForConnections: true,
      connectionLimit: 10,
    };

// Create a mock pool for testing or a real one for other environments
const pool = process.env.NODE_ENV === 'test'
  ? {
      // Mock pool for testing
      query: async () => [[], []],
      execute: async () => {},
      getConnection: async () => ({
        query: async () => {},
        release: () => {}
      })
    }
  : mysql.createPool(DB_CONFIG);

// Session configuration
// Session configuration with proper database specification
const MySQLStore = MySQLStoreFactory(session);
// Use in-memory session store for testing
let sessionStore;
let sessionOptions;

if (process.env.NODE_ENV === 'test') {
  // For testing, use in-memory store instead of MySQL
  console.log('⚙️ Using in-memory session store for testing');
  sessionStore = new session.MemoryStore();
} else {
  // Check if MYSQL_DATABASE is set for non-test environments
  if (!process.env.MYSQL_DATABASE) {
    console.error('❌ MYSQL_DATABASE environment variable is required');
    console.error('Please set this in your .env file or environment variables');
    console.error('Example: MYSQL_DATABASE=crda_db');
    process.exit(1);
  }
   // Regular MySQL session store for non-test environments
   sessionOptions = {
    host: process.env.MYSQL_HOST,
    port: process.env.MYSQL_PORT ? Number(process.env.MYSQL_PORT) : 3306,
    user: process.env.MYSQL_USER,
    password: process.env.MYSQL_PASSWORD,
    database: process.env.MYSQL_DATABASE,
    createDatabaseTable: true,
    schema: {
      tableName: 'sessions',
      columnNames: {
        session_id: 'session_id',
        expires: 'expires',
        data: 'data'
      }
    }
  };
  sessionStore = new MySQLStore(sessionOptions);
}

const SESSION_SECRET = process.env.SESSION_SECRET || 'default-insecure-secret';

// Security & parsing
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'"],
      fontSrc: ["'self'"],
      imgSrc: ["'self'"],
    }
  }
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors({ origin: process.env.CORS_ORIGIN || '*', credentials: true }));
app.use(session({
  key: 'crda_session',
  secret: SESSION_SECRET,
  store: sessionStore,
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: process.env.NODE_ENV === 'production', 
    httpOnly: true, 
    sameSite: 'lax', 
    maxAge: 86400000 
  }
}));

// Middleware to collect HTTP metrics
app.use((req, res, next) => {
  const route = req.route?.path || req.path;
  const endTimer = httpHistogram.startTimer({ method: req.method, route });
  res.on('finish', () => {
    httpCounter.inc({ method: req.method, route, code: res.statusCode });
    endTimer({ code: res.statusCode });
  });
  next();
});

// DB helper with metrics
async function execWithMetrics(sql, params) {
  const operation = sql.trim().split(' ')[0];
  const endDb = dbHistogram.startTimer({ operation });
  const result = await pool.query(sql, params);
  endDb();
  dbCounter.inc({ operation });
  return result;
}

// Initialize DB with retries
async function initDatabase() {
  // Skip actual DB initialization in test environment
  if (process.env.NODE_ENV === 'test') {
    console.log('⚙️ Test environment detected - skipping database initialization');
    return;
  }

  let retries = 5;
  
  // First check if all required env variables are present
  const requiredEnvVars = ['MYSQL_HOST', 'MYSQL_USER', 'MYSQL_PASSWORD', 'MYSQL_DATABASE'];
  const missingVars = requiredEnvVars.filter(varName => !process.env[varName]);
  
  if (missingVars.length > 0) {
    console.error(`❌ Missing required environment variables: ${missingVars.join(', ')}`);
    console.error('Please check your .env file or environment configuration');
    process.exit(1);
  }
  
  while (retries) {
    try {
      const connection = await pool.getConnection();
      console.log('✅ Successfully connected to database');
      
      // Create sessions table if it doesn't exist
      await connection.query(`
        CREATE TABLE IF NOT EXISTS sessions (
          session_id VARCHAR(128) NOT NULL,
          expires INT(11) UNSIGNED NOT NULL,
          data MEDIUMTEXT,
          PRIMARY KEY (session_id)
        )
      `);
      console.log('✅ Session table verified/created');
      
      connection.release();
      break;
    } catch (err) {
      console.error(`❌ Database connection failed (${retries} retries):`, err.message);
      retries--;
      if (retries === 0) {
        console.error('❌ Maximum retries reached. Exiting application.');
        process.exit(1);
      }
      await new Promise(res => setTimeout(res, 5000));
    }
  }
}

// Auth middleware
function isAuthenticated(req, res, next) {
  if (req.session.user) return next();
  res.status(401).json({ error: 'Not authenticated' });
}

// ========== Authentication ==========
app.post('/login', async (req, res) => {
  try {
    const { email_user, password_user } = req.body;
    const [rows] = await execWithMetrics(
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
    console.error(err);
    res.status(500).json({ error: 'Login error' });
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
    const [exist] = await execWithMetrics(
      'SELECT id FROM utilisateur WHERE email_user = ? OR cin_user = ?', [email_user, cin_user]
    );
    if (exist.length) return res.status(409).json({ error: 'Already exists' });
    const hash = await bcrypt.hash(password_user, 10);
    await execWithMetrics(
      `INSERT INTO utilisateur
       (email_user, password_user, role_user, status_user, nom_user, prenom_user, sex_user, cin_user)
       VALUES (?, ?, ?, 'pending', ?, ?, ?, ?)`,
      [email_user, hash, role_user, nom_user, prenom_user, sex_user, cin_user]
    );
    res.status(201).json({ message: 'Registration pending approval' });
  } catch (err) {
    console.error(err);
    res.status(400).json({ error: 'Registration error' });
  }
});

// ========== Services ==========
app.get('/services', isAuthenticated, async (req, res) => {
  try {
    const [rows] = await execWithMetrics(`
      SELECT s.*, IF(r.id IS NOT NULL,'تم','قيد الانتظار') AS status
      FROM services_utilisateur s
      LEFT JOIN rapport r ON s.cin = r.cin AND s.sujet = r.sujet
    `);
    res.json({ services: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
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
    await execWithMetrics(
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
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
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
    await execWithMetrics(
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
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.delete('/services/:id', isAuthenticated, async (req, res) => {
  try {
    await execWithMetrics('DELETE FROM services_utilisateur WHERE id=?', [req.params.id]);
    res.json({ message: 'Service deleted' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ========== Reports ==========
app.get('/reports', isAuthenticated, async (req, res) => {
  try {
    const [rows] = await execWithMetrics('SELECT * FROM rapport');
    res.json({ reports: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/reports/:id', isAuthenticated, async (req, res) => {
  try {
    const [rows] = await execWithMetrics('SELECT * FROM rapport WHERE id=?', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    res.json({ report: rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/reports', isAuthenticated, async (req, res) => {
  try {
    const { cin, sujet, nom, prenom, surface, limites_terrain,
      localisation, superficie_batiments_anciens, observations } = req.body;
    if (!cin || !sujet) {
      return res.status(400).json({ error: 'cin & sujet required' });
    }
    const [[service]] = await execWithMetrics(
      'SELECT numero_transaction FROM services_utilisateur WHERE cin=? AND sujet=?',
      [cin, sujet]
    );
    if (!service) return res.status(404).json({ error: 'Service not found' });
    
    await pool.execute('START TRANSACTION');
    try {
      await execWithMetrics(
        `INSERT INTO rapport
         (cin, sujet, nom, prenom, surface, limites_terrain,
          localisation, superficie_batiments_anciens, observations, numero_transaction)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [cin, sujet, nom, prenom, surface, limites_terrain,
          localisation, superficie_batiments_anciens, observations,
          service.numero_transaction]
      );
      await execWithMetrics(
        'UPDATE services_utilisateur SET status="تم" WHERE cin=? AND sujet=?',
        [cin, sujet]
      );
      await pool.execute('COMMIT');
      res.status(201).json({ message: 'Report added' });
    } catch (err) {
      await pool.execute('ROLLBACK');
      throw err;
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.put('/reports/:id', isAuthenticated, async (req, res) => {
  try {
    const { surface, limites_terrain, localisation,
      superficie_batiments_anciens, observations } = req.body;
    await execWithMetrics(
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
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.delete('/reports/:id', isAuthenticated, async (req, res) => {
  try {
    const [[r]] = await execWithMetrics('SELECT cin,sujet FROM rapport WHERE id=?', [req.params.id]);
    if (!r) return res.status(404).json({ error: 'Not found' });
    
    await pool.execute('START TRANSACTION');
    try {
      await execWithMetrics('DELETE FROM results WHERE cin=? AND sujet=?', [r.cin, r.sujet]);
      await execWithMetrics('DELETE FROM rapport WHERE id=?', [req.params.id]);
      await pool.execute('COMMIT');
      res.json({ message: 'Report deleted' });
    } catch (err) {
      await pool.execute('ROLLBACK');
      throw err;
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ========== Results ==========
app.get('/results', isAuthenticated, async (req, res) => {
  try {
    const [rows] = await execWithMetrics(`
      SELECT s.*, r.statut, rap.id AS report_id
      FROM services_utilisateur s
      LEFT JOIN results r ON s.cin=r.cin AND s.sujet=r.sujet
      INNER JOIN rapport rap ON s.cin=rap.cin AND s.sujet=rap.sujet
      ORDER BY s.id DESC
    `);
    res.json({ results: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/results', isAuthenticated, async (req, res) => {
  try {
    const { sujet, nom, prenom, cin, numero_transaction, statut } = req.body;
    const allowed = ['مقبول', 'مرفوض'];
    if (!allowed.includes(statut)) {
      return res.status(400).json({ error: 'Invalid status' });
    }
    await execWithMetrics(
      `INSERT INTO results (sujet,nom,prenom,cin,numero_transaction,statut)
       VALUES (?,?,?,?,?,?)
       ON DUPLICATE KEY UPDATE statut=?`,
      [sujet, nom, prenom, cin, numero_transaction, statut, statut]
    );
    res.json({ message: 'Result saved' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.delete('/results', isAuthenticated, async (req, res) => {
  try {
    const { cin, numero_transaction } = req.body;
    await execWithMetrics(
      'DELETE FROM results WHERE cin=? AND numero_transaction=?',
      [cin, numero_transaction]
    );
    res.json({ message: 'Result deleted' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ========== Check-Status ==========
app.post('/check-status', async (req, res) => {
  try {
    const { cin, transaction_number } = req.body;
    if (!cin || !transaction_number) {
      return res.status(400).json({ error: 'cin & transaction_number required' });
    }
    const [[service]] = await execWithMetrics(
      'SELECT * FROM services_utilisateur WHERE cin=? AND numero_transaction=?',
      [cin, transaction_number]
    );
    if (!service) {
      return res.status(404).json({ error: 'No matching service' });
    }
    const [[rep]] = await execWithMetrics(
      'SELECT * FROM rapport WHERE cin=? AND numero_transaction=?',
      [cin, transaction_number]
    );
    const [[resu]] = await execWithMetrics(
      'SELECT * FROM results WHERE cin=? AND numero_transaction=?',
      [cin, transaction_number]
    );
    let statut;
    if (resu) statut = resu.statut;
    else if (rep) statut = 'بصدد الدرس';
    else statut = 'في انتظار التقرير';

    res.json({ service, statut });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

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

// Metrics endpoint
app.get('/metrics', async (req, res) => {
  try {
    res.set('Content-Type', register.contentType);
    res.end(await register.metrics());
  } catch (err) {
    console.error('Error generating metrics:', err);
    res.status(500).end();
  }
});

// Start server
initDatabase().then(() => {
  app.listen(process.env.PORT || 3000, () => {
    console.log(`🚀 CRDA app started on port ${process.env.PORT || 3000}`);
  });
});

export default app;