const dns = require('dns');
dns.setServers(['8.8.8.8', '8.8.4.4']);
const express = require('express');
const app = express();
const cors = require('cors');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { AsyncLocalStorage } = require('async_hooks');
const tenantStore = new AsyncLocalStorage();
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { initializeApp, cert } = require('firebase-admin/app');
const { getAuth } = require('firebase-admin/auth');
const { MongoClient, ServerApiVersion, ObjectId, } = require('mongodb');
require('dotenv').config();
const REQUIRED_ENV = [
  'FIREBASE_SERVICE_ACCOUNT',
  'DB_USER',
  'DB_PASS',
  'ACCESS_TOKEN_SECRET',
  'CLIENT_ACCESS_TOKEN_SECRET',
  'GATE_TOKEN_SECRET',
  'ADMIN_ACTION_TOKEN_SECRET',
  'GATE_PASSWORD',
  'ADMIN_ACTION_PASSWORD',
];
const missingEnv = REQUIRED_ENV.filter((k) => !process.env[k]);
if (missingEnv.length > 0) {
  console.error('.env তে এই ভ্যালুগুলো নেই:', missingEnv.join(', '));
  process.exit(1);
}
const secretValues = [
  process.env.ACCESS_TOKEN_SECRET,
  process.env.CLIENT_ACCESS_TOKEN_SECRET,
  process.env.GATE_TOKEN_SECRET,
  process.env.ADMIN_ACTION_TOKEN_SECRET,
];
if (new Set(secretValues).size !== secretValues.length) {
  console.error('চারটা secret (ACCESS, CLIENT_ACCESS, GATE_TOKEN, ADMIN_ACTION_TOKEN) আলাদা আলাদা হতে হবে!');
  process.exit(1);
}
// লাইভ সার্ভারে (NODE_ENV=production) দুর্বল secret/password হলে চালুই হবে না
const IS_PROD = process.env.NODE_ENV === 'production';
const weakSecret = secretValues.some((s) => String(s).length < 48);
const weakPass = [process.env.GATE_PASSWORD, process.env.ADMIN_ACTION_PASSWORD].some((s) => String(s).length < 10);
if (weakSecret || weakPass) {
  if (IS_PROD) {
    console.error('Production এ secret কমপক্ষে ৪৮ অক্ষর এবং GATE_PASSWORD / ADMIN_ACTION_PASSWORD কমপক্ষে ১০ অক্ষর হতে হবে!');
    process.exit(1);
  }
  console.warn('⚠️ দুর্বল secret/password (লোকালে চলবে, কিন্তু লাইভে চলবে না)');
}
initializeApp({
  credential: cert(JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT)),
});
const port = process.env.PORT || 5000;
process.on('unhandledRejection', (e) => console.error('unhandledRejection:', e));
process.on('uncaughtException', (e) => console.error('uncaughtException:', e));

// middleware
app.set('trust proxy', 1);

// সব route এর async error নিজে ধরবে (ভুল ID দিলে request ঝুলে না থেকে error response যাবে)
['get', 'post', 'put', 'patch', 'delete'].forEach((m) => {
  const orig = app[m].bind(app);
  app[m] = (path, ...handlers) => {
    if (handlers.length === 0) return orig(path); // app.get('setting') এর জন্য
    return orig(
      path,
      ...handlers.map((h) =>
        typeof h === 'function'
          ? (req, res, next) => {
            try {
              const r = h(req, res, next);
              if (r && typeof r.catch === 'function') r.catch(next);
            } catch (e) {
              next(e);
            }
          }
          : h
      )
    );
  };
});
const ORIGIN_PATTERNS = [
  /^https:\/\/([a-z0-9-]+\.)?bashaybazar\.com$/,
];
if (!IS_PROD) {
  ORIGIN_PATTERNS.push(
    /^https?:\/\/([a-z0-9-]+\.)?localhost(:\d+)?$/,
    /^http:\/\/127\.0\.0\.1(:\d+)?$/
  );
}
app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin) return cb(null, true);
      const extra = (process.env.CORS_ORIGINS || '').split(',').map((s) => s.trim()).filter(Boolean);
      if (extra.includes(origin) || ORIGIN_PATTERNS.some((r) => r.test(origin))) return cb(null, true);
      cb(null, false);
    },
  })
);
app.use(express.json({ limit: '1mb' }));

// body তে '$' দিয়ে শুরু বা '.' যুক্ত key থাকলে বাতিল (NoSQL injection / অন্য field overwrite ঠেকাতে)
const hasBadKey = (v, depth = 0) => {
  if (depth > 12) return true;
  if (Array.isArray(v)) return v.some((x) => hasBadKey(x, depth + 1));
  if (v && typeof v === 'object') {
    return Object.keys(v).some((k) => k.startsWith('$') || k.includes('.') || hasBadKey(v[k], depth + 1));
  }
  return false;
};
app.use((req, res, next) => {
  if (req.body && hasBadKey(req.body)) return res.status(400).send({ message: 'Invalid data' });
  next();
});

// unsetFields থেকে স্পর্শকাতর field বাদ
const BLOCKED_UNSET = ['_id', 'createdAt', 'stockAllocations', 'stockCreated', 'orderSnapshot', 'invoiceNo', 'orderNo'];
const cleanUnset = (list) =>
  Array.isArray(list)
    ? list.filter((f) => typeof f === 'string' && !f.startsWith('$') && !f.includes('.') && !BLOCKED_UNSET.includes(f))
    : list;

// ===== security headers + rate limit =====
app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));
const mkLimiter = (windowMs, limit, message) =>
  rateLimit({ windowMs, limit, standardHeaders: true, legacyHeaders: false, message: { message } });
app.use(mkLimiter(60 * 1000, 6000, 'Too many requests, please slow down.'));
app.use('/client/login', mkLimiter(15 * 60 * 1000, 30, 'Too many login attempts. Try again later.'));
app.use('/client/change-password', mkLimiter(15 * 60 * 1000, 20, 'Too many attempts. Try again later.'));
app.use('/jwt', mkLimiter(15 * 60 * 1000, 60, 'Too many attempts. Try again later.'));
app.use('/gate', mkLimiter(15 * 60 * 1000, 60, 'Too many attempts. Try again later.'));
app.use('/users/verify-admin-password', mkLimiter(15 * 60 * 1000, 20, 'Too many attempts. Try again later.'));

// data change track (sob device er jonno)
const CI_OPT = { collation: { locale: 'en', strength: 2 } };

// dealer এর staff (SR / Manager / Delivery Man) এর session যাচাই (dealer active + staff active + session মিলতে হবে)
const loadStaff = async (c, d) => {
  if (!c || c.isActive !== true || !c.dbName) return null;
  if (!d?.staffId || !ObjectId.isValid(d.staffId)) return null;
  const s = await client.db(c.dbName).collection('user').findOne({ _id: new ObjectId(d.staffId) });
  if (!s || s.isActive !== true || !s.sessionId || s.sessionId !== d.sid) return null;
  return s;
};

// token দেখে কে এসেছে: client (নিজের database সহ) না admin
const resolveCaller = async (req) => {
  const token = (req.headers.authorization || '').split(' ')[1];
  if (!token) return null;
  const control = client.db("squirrelDb");
  try {
    const d = jwt.verify(token, process.env.CLIENT_ACCESS_TOKEN_SECRET, { algorithms: ['HS256'] });
    if (d?.clientId && ObjectId.isValid(d.clientId)) {
      const c = await control.collection('client').findOne({ _id: new ObjectId(d.clientId) });
      if (d.kind === 'staff') {
        const s = await loadStaff(c, d);
        if (s) return { type: 'client', client: c, dbName: c.dbName, staff: s };
        return null;
      }
      if (c && c.isActive === true && c.login === 'yes' && c.sessionId && c.sessionId === d.sid && c.dbName && !d.staffId) {
        return { type: 'client', client: c, dbName: c.dbName };
      }
    }
  } catch (e) { }
  try {
    const d = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, { algorithms: ['HS256'] });
    const u = await control.collection('users').findOne({ email: d.email }, CI_OPT);
    if (u?.role === 'admin' && d.sid && u.sessionId === d.sid) return { type: 'admin', decoded: d };
  } catch (e) { }
  return null;
};
app.use((req, res, next) => {
  if (req.method === 'GET') res.set('Cache-Control', 'no-store');
  if (req.method !== 'GET' && req.method !== 'OPTIONS' && req.path !== '/jwt' && req.path !== '/client/login' && req.path !== '/client/logout' && req.path !== '/users/verify-admin-password' && !req.path.startsWith('/gate')) {
    res.on('finish', () => {
      if (res.statusCode < 400) {
        if (req.versionDb) client.db(req.versionDb).collection('auditLog').insertOne({ at: new Date(), by: req.staff ? { type: 'staff', id: String(req.staff._id), name: req.staff.name, role: req.staff.role } : { type: 'dealer', id: String(req.client?._id || '') }, method: req.method, path: String(req.originalUrl || '').split('?')[0], ip: req.ip }).catch(() => { });
        client.db(req.versionDb || "squirrelDb").collection("meta")
          .updateOne({ _id: 'dataVersion' }, { $inc: { version: 1 } }, { upsert: true })
          .catch(() => { });
      }
    });
  }
  next();
});
app.get('/data-version', async (req, res) => {
  res.set('Cache-Control', 'no-store');
  try {
    const who = await resolveCaller(req);
    if (!who) return res.send({ version: 0 });
    const dbName = who.type === 'client' ? who.dbName : 'squirrelDb';
    const doc = await client.db(dbName).collection('meta').findOne({ _id: 'dataVersion' });
    res.send({ version: doc?.version || 0 });
  } catch (e) {
    res.status(500).send({ error: 'version failed' });
  }
});


const uri = `mongodb+srv://${encodeURIComponent(process.env.DB_USER)}:${encodeURIComponent(process.env.DB_PASS)}@cluster0.3wtib.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    await client.connect();
    // Send a ping to confirm a successful connection

    // ===== control database (শুধু তোমার): admin, client তালিকা, website contact =====
    const controlDb = client.db("squirrelDb");
    const usersCollection = controlDb.collection("users");
    const clientCollection = controlDb.collection("client");
    const contactCollection = controlDb.collection("contact");

    // ===== client এর business data: প্রতি request এ token অনুযায়ী নিজের আলাদা database =====
    // tenant না পেলে error দেয় (কখনো অন্যের data খোলে না)
    // কোন method এ options কত নম্বর argument (transaction session ঢোকানোর জন্য)
    const SESSION_ARG = {
      find: 1, findOne: 1, countDocuments: 1, aggregate: 1,
      insertOne: 1, insertMany: 1, deleteOne: 1, deleteMany: 1, findOneAndDelete: 1,
      updateOne: 2, updateMany: 2, replaceOne: 2, findOneAndUpdate: 2, findOneAndReplace: 2, distinct: 2,
    };
    const tenantCol = (name) =>
      new Proxy({}, {
        get(_t, prop) {
          if (typeof prop === 'symbol' || prop === 'then') return undefined;
          const store = tenantStore.getStore();
          if (!store || !store.dbName) throw new Error('TENANT_NOT_SET');
          const col = client.db(store.dbName).collection(name);
          const v = col[prop];
          if (typeof v !== 'function') return v;
          const idx = SESSION_ARG[prop];
          if (idx === undefined) return v.bind(col);
          return (...args) => {
            if (store.session) args[idx] = { ...(args[idx] || {}), session: store.session };
            return v.apply(col, args);
          };
        },
      });

    const productCollection = tenantCol("product");
    const unitCollection = tenantCol("unit");
    const categoryCollection = tenantCol("category");
    const companyCollection = tenantCol("company");
    const customerCollection = tenantCol("customer");
    const routeCollection = tenantCol("route");
    const userCollection = tenantCol("user");
    const userRoleCollection = tenantCol("userRole");
    const investmentCollection = tenantCol("investment");
    const adjustmentCollection = tenantCol("adjustment");
    const incomeCollection = tenantCol("income");
    const expenseCollection = tenantCol("expense");
    const routeExpenseCollection = tenantCol("routeExpense");
    const transferCollection = tenantCol("transfer");
    const purchaseCollection = tenantCol("purchase");
    const stockPurchaseCollection = tenantCol("stock-purchase");
    const stockAdjustmentCollection = tenantCol("stockAdjustment");
    const salesCollection = tenantCol("sales");
    const featureCollection = tenantCol("feature");
    const purchaseBulkReturnCollection = tenantCol("purchaseBulkReturn");
    const salesBulkReturnCollection = tenantCol("salesBulkReturn");
    const salesDamageCollection = tenantCol("salesDamage");
    const damageReturnCollection = tenantCol("damageReturn");
    const PurchaseDuePaymentCollection = tenantCol("purchaseDuePayment");
    const SalesDuePaymentCollection = tenantCol("salesDuePayment");
    const SalesSrTargetCollection = tenantCol("salesSrTarget");


    // ===== secret gate (burger -> burger-sos -> password -> login) =====
    const GATE_SECRET = process.env.GATE_TOKEN_SECRET;
    const gateStep1 = new Map(); // ip -> time
    const gateStep2 = new Map(); // ip -> time
    const gateFails = new Map(); // ip -> { count, lockUntil }
    const GATE_STEP_WINDOW = 10 * 60 * 1000;
    const GATE_MODAL_WINDOW = 5 * 60 * 1000;
    const GATE_MAX_FAILS = 5;
    const GATE_LOCK_TIME = 15 * 60 * 1000;

    const getIp = (req) => {
      const raw = req.ip || req.socket.remoteAddress || 'unknown';
      return String(raw).replace(/^::ffff:/, '').replace(/^::1$/, '127.0.0.1');
    };
    const safeEqual = (a, b) => {
      const ha = crypto.createHash('sha256').update(String(a)).digest();
      const hb = crypto.createHash('sha256').update(String(b)).digest();
      return crypto.timingSafeEqual(ha, hb);
    };

    setInterval(() => {
      const now = Date.now();
      for (const [k, t] of gateStep1) if (now - t > GATE_STEP_WINDOW) gateStep1.delete(k);
      for (const [k, t] of gateStep2) if (now - t > GATE_MODAL_WINDOW) gateStep2.delete(k);
      for (const [k, v] of gateFails) if (v.lockUntil && now > v.lockUntil) gateFails.delete(k);
    }, 60 * 1000).unref();

    app.post('/gate/step1', (req, res) => {
      gateStep1.set(getIp(req), Date.now());
      res.send({ ok: true });
    });

    app.post('/gate/step2', (req, res) => {
      const ip = getIp(req);
      const t = gateStep1.get(ip);
      if (!t || Date.now() - t > GATE_STEP_WINDOW) {
        return res.status(403).send({ ok: false });
      }
      gateStep1.delete(ip);
      gateStep2.set(ip, Date.now());
      res.send({ ok: true });
    });

    app.post('/gate/verify', (req, res) => {
      const ip = getIp(req);
      const fail = gateFails.get(ip);
      if (fail && fail.lockUntil && Date.now() < fail.lockUntil) {
        return res.status(429).send({ ok: false });
      }

      const t = gateStep2.get(ip);
      if (!t || Date.now() - t > GATE_MODAL_WINDOW) {
        return res.status(403).send({ ok: false });
      }
      gateStep2.delete(ip);

      const secretPass = process.env.GATE_PASSWORD;
      const input = req.body?.password;
      if (!secretPass || typeof input !== 'string' || !safeEqual(input, secretPass)) {
        const cur = gateFails.get(ip) || { count: 0, lockUntil: 0 };
        cur.count += 1;
        if (cur.count >= GATE_MAX_FAILS) {
          cur.lockUntil = Date.now() + GATE_LOCK_TIME;
          cur.count = 0;
        }
        gateFails.set(ip, cur);
        return res.status(403).send({ ok: false });
      }

      gateFails.delete(ip);
      const token = jwt.sign({ gate: true }, GATE_SECRET, { expiresIn: '30m' });
      res.send({ ok: true, token });
    });

    app.post('/gate/check', (req, res) => {
      const token = req.body?.token;
      if (!token || typeof token !== 'string') return res.status(403).send({ ok: false });
      jwt.verify(token, GATE_SECRET, { algorithms: ['HS256'] }, (err, decoded) => {
        if (err || !decoded?.gate) return res.status(403).send({ ok: false });
        res.send({ ok: true });
      });
    });

    // jwt related api

    app.post('/jwt', async (req, res) => {
      try {
        const idToken = req.body?.idToken;
        if (!idToken || typeof idToken !== 'string') {
          return res.status(401).send({ message: 'unauthorized access' });
        }
        const decodedFirebase = await getAuth().verifyIdToken(idToken);
        if (!decodedFirebase.email) {
          return res.status(401).send({ message: 'unauthorized access' });
        }
        const sid = crypto.randomUUID();
        await usersCollection.updateOne(
          { email: decodedFirebase.email },
          { $set: { sessionId: sid } },
          { collation: { locale: 'en', strength: 2 } }
        );
        const token = jwt.sign({ email: decodedFirebase.email, sid }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '1h' });
        res.send({ token });
      } catch (error) {
        console.error('JWT ERROR:', error.code, error.message);
        res.status(401).send({ message: 'unauthorized access' });
      }
    })

    // middlewares 
    const verifyToken = (req, res, next) => {
      // console.log('inside verify token', req.headers.authorization);
      if (!req.headers.authorization) {
        return res.status(401).send({ message: 'unauthorized access' });
      }
      const token = req.headers.authorization.split(' ')[1];
      jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, { algorithms: ['HS256'] }, (err, decoded) => {
        if (err) {
          return res.status(401).send({ message: 'unauthorized access' })
        }
        usersCollection
          .findOne({ email: decoded.email }, { collation: { locale: 'en', strength: 2 } })
          .then((u) => {
            if (!decoded.sid || !u || !u.sessionId || u.sessionId !== decoded.sid) {
              return res.status(401).send({ message: 'unauthorized access' });
            }
            req.decoded = decoded;
            next();
          })
          .catch(() => res.status(401).send({ message: 'unauthorized access' }));
        return;
        next();
      })
    }

    // use verify admin after verifyToken
    const verifyAdmin = async (req, res, next) => {
      const email = req.decoded.email;
      const user = await usersCollection.findOne(
        { email },
        { collation: { locale: 'en', strength: 2 } }
      );
      const isAdmin = user?.role === 'admin';
      if (!isAdmin) {
        return res.status(403).send({ message: 'forbidden access' });
      }
      next();
    }


    // // ক্লায়েন্ট ভেরিফিকেশন মিডলওয়্যার
    // const verifyClientToken = (req, res, next) => {
    //   const authHeader = req.headers.authorization;
    //   if (!authHeader) {
    //     return res.status(401).send({ message: 'unauthorized access' });
    //   }

    //   const token = authHeader.split(' ')[1];
    //   jwt.verify(token, process.env.CLIENT_ACCESS_TOKEN_SECRET || 'client_secret_key_here', (err, decoded) => {
    //     if (err) {
    //       return res.status(401).send({ message: 'token expired or invalid' });
    //     }
    //     req.client = decoded; // এখানে এখন decoded ইনফোর ভেতরে clientId আছে
    //     next();
    //   });
    // };



    // ------------------------------------------



    // users related api

    app.get('/users', verifyToken, verifyAdmin, async (req, res) => {
      const result = await usersCollection.find({}, { projection: { sessionId: 0 } }).toArray();
      res.send(result);
    });

    app.get('/users/admin/:email', verifyToken, async (req, res) => {
      const email = req.params.email;

      if (String(email).toLowerCase() !== String(req.decoded.email).toLowerCase()) {
        return res.status(403).send({ message: 'forbidden access' })
      }

      const user = await usersCollection.findOne(
        { email: req.decoded.email },
        { collation: { locale: 'en', strength: 2 } }
      );
      let admin = false;
      if (user) {
        admin = user?.role === 'admin';
      }
      res.send({ admin });
    })

    app.post('/users', async (req, res) => {
      try {
        const idToken = (req.headers.authorization || '').split(' ')[1];
        try {
          const g = jwt.verify(String(req.headers['x-gate-token'] || ''), GATE_SECRET, { algorithms: ['HS256'] });
          if (!g?.gate) throw new Error('no gate');
        } catch (e) {
          return res.status(403).send({ message: 'forbidden access' });
        }
        const decoded = await getAuth().verifyIdToken(idToken);
        const email = decoded.email;
        if (!email) return res.status(401).send({ message: 'unauthorized access' });
        const existingUser = await usersCollection.findOne({ email });
        if (existingUser) {
          return res.send({ message: 'user already exists', insertedId: null })
        }
        const result = await usersCollection.insertOne({ name: String(req.body?.name || '').slice(0, 100), email, role: 'user' });
        res.send(result);
      } catch (e) {
        res.status(401).send({ message: 'unauthorized access' });
      }
    });

    const adminPassFails = new Map();
    const checkAdminPassword = (req, res) => {
      const key = req.decoded.email;
      const f = adminPassFails.get(key);
      if (f && f.lockUntil && Date.now() < f.lockUntil) {
        res.status(429).send({ message: 'Too many attempts' });
        return false;
      }
      const input = req.body?.password;
      const real = process.env.ADMIN_ACTION_PASSWORD;
      if (!real || typeof input !== 'string' || !safeEqual(input, real)) {
        const cur = f || { count: 0, lockUntil: 0 };
        cur.count += 1;
        if (cur.count >= 5) {
          cur.lockUntil = Date.now() + 15 * 60 * 1000;
          cur.count = 0;
        }
        adminPassFails.set(key, cur);
        res.status(400).send({ message: 'Incorrect password' });
        return false;
      }
      adminPassFails.delete(key);
      return true;
    };

    // ===== admin action token (password verify korar por 2 min er single-use token) =====
    const ACTION_SECRET = process.env.ADMIN_ACTION_TOKEN_SECRET;
    const usedActionTokens = new Map(); // jti -> expiry(ms)
    setInterval(() => {
      const now = Date.now();
      for (const [k, exp] of usedActionTokens) if (now > exp) usedActionTokens.delete(k);
    }, 60 * 1000).unref();

    // Step 1: password verify -> action token
    app.post('/users/verify-admin-password', verifyToken, verifyAdmin, (req, res) => {
      if (!checkAdminPassword(req, res)) return;
      const jti = crypto.randomUUID();
      const actionToken = jwt.sign(
        { email: req.decoded.email, purpose: 'admin-action', jti },
        ACTION_SECRET,
        { expiresIn: '2m' }
      );
      res.send({ ok: true, actionToken });
    });

    // Step 2: action korar somoy token check (ekbar e use hobe)
    const requireActionToken = (req, res) => {
      const t = req.headers['x-action-token'];
      if (!t || typeof t !== 'string') {
        res.status(403).send({ message: 'Password verification required' });
        return false;
      }
      try {
        const d = jwt.verify(t, ACTION_SECRET, { algorithms: ['HS256'] });
        if (d.purpose !== 'admin-action' || d.email !== req.decoded.email || usedActionTokens.has(d.jti)) {
          throw new Error('invalid');
        }
        usedActionTokens.set(d.jti, d.exp * 1000);
        return true;
      } catch (e) {
        res.status(403).send({ message: 'Verification expired, try again' });
        return false;
      }
    };

    app.delete('/users/:id', verifyToken, verifyAdmin, async (req, res) => {
      const query = { _id: new ObjectId(req.params.id) };
      const target = await usersCollection.findOne(query);
      if (!target) return res.status(404).send({ message: 'User not found' });
      if (target.role === 'admin' && !requireActionToken(req, res)) return;
      const result = await usersCollection.deleteOne(query);
      res.send(result);
    });

    app.patch('/users/admin/:id', verifyToken, verifyAdmin, async (req, res) => {
      if (!requireActionToken(req, res)) return;
      const id = req.params.id;
      const filter = { _id: new ObjectId(id) };
      const updatedDoc = {
        $set: {
          role: 'admin'
        }
      }
      const result = await usersCollection.updateOne(filter, updatedDoc);
      res.send(result);
    })

    app.patch('/users/remove-admin/:id', verifyToken, verifyAdmin, async (req, res) => {
      if (!requireActionToken(req, res)) return;
      const id = req.params.id;
      const filter = { _id: new ObjectId(id) };
      const updatedDoc = {
        $set: {
          role: 'user'
        }
      };
      const result = await usersCollection.updateOne(filter, updatedDoc);
      res.send(result);
    });




    // client related api

    // ===== client password security (scrypt hash, plain password kothao save hobe na) =====
    const scryptAsync = require('util').promisify(crypto.scrypt);
    const CI = { collation: { locale: 'en', strength: 2 } };

    const hashPassword = async (plain) => {
      const salt = crypto.randomBytes(16);
      const hash = await scryptAsync(String(plain), salt, 64);
      return `scrypt$${salt.toString('hex')}$${hash.toString('hex')}`;
    };

    const verifyPasswordHash = async (plain, stored) => {
      try {
        const [algo, saltHex, hashHex] = String(stored).split('$');
        if (algo !== 'scrypt' || !saltHex || !hashHex) return false;
        const expected = Buffer.from(hashHex, 'hex');
        const actual = await scryptAsync(String(plain), Buffer.from(saltHex, 'hex'), expected.length);
        return crypto.timingSafeEqual(expected, actual);
      } catch (e) {
        return false;
      }
    };

    const PASSWORD_RULE = /^(?=.*[A-Za-z])(?=.*\d).{8,128}$/;
    const PASSWORD_MESSAGE = 'Password must be 8-128 characters and include letters and numbers';

    // ===== subdomain (slug) =====
    const SLUG_RULE = /^[a-z0-9][a-z0-9-]{1,28}[a-z0-9]$/;
    const SLUG_MESSAGE = 'Subdomain must be 3-30 characters: small letters, numbers and hyphen only';
    const RESERVED_SLUGS = ['www', 'api', 'admin', 'app', 'mail', 'ftp', 'smtp', 'static', 'assets', 'cdn', 'staging', 'dev', 'login', 'dashboard', 'panel', 'burger', 'support', 'help', 'blog', 'shop'];
    const isValidSlug = (s) => SLUG_RULE.test(s) && !RESERVED_SLUGS.includes(s);
    // database নাম unique (delete করা client এর slug নতুন কেউ নিলেও পুরোনো data পাবে না)
    const makeDbName = (slug) => `tenant_${slug}_${crypto.randomBytes(3).toString('hex')}`;

    // frontend e kokhono password / hash pathano hobe na
    const parseUserLimit = (v) => {
      const n = Number(v);
      return Number.isInteger(n) && n >= 1 && n <= 1000 ? n : null;
    };
    const cleanWhatsapp = (v) => String(v || '').replace(/\D/g, '').slice(0, 20);
    // staff সংখ্যা + dealer ১ জন > userLimit হলে limitExceeded
    const getLimitInfo = async (c) => {
      const limit = Number.isInteger(c.userLimit) && c.userLimit >= 1 ? c.userLimit : 10;
      const staffCount = await client.db(c.dbName).collection('user').countDocuments({});
      const excess = Math.max(staffCount + 1 - limit, 0);
      return { userLimit: limit, staffCount, excess, limitExceeded: excess > 0 };
    };
    const publicClient = (c) => {
      const { password, passwordHash, sessionId, dbName, ...rest } = c;
      return { ...rest, login: rest.login || 'no', userLimit: Number.isInteger(rest.userLimit) && rest.userLimit >= 1 ? rest.userLimit : 10 };
    };

    app.get('/client', verifyToken, verifyAdmin, async (req, res) => {
      const clients = await clientCollection.find().toArray();
      res.send(clients.map(publicClient));
    });

    // নতুন ক্লায়েন্ট যোগ করার রাউট
    app.post('/client', verifyToken, verifyAdmin, async (req, res) => {
      try {
        const body = req.body || {};
        const name = String(body.name || '').trim().slice(0, 100);
        const phone = String(body.phone || '').replace(/\D/g, '').slice(0, 20);
        const email = String(body.email || '').trim().toLowerCase().slice(0, 150);
        const address = String(body.address || '').trim().slice(0, 300);
        const password = String(body.password || '');

        if (!name || !phone || !email || !address) {
          return res.status(400).json({ message: 'All fields are required!' });
        }
        if (parseUserLimit(body.userLimit) === null) {
          return res.status(400).json({ error: true, field: 'userLimit', message: 'User limit must be a whole number (minimum 1)' });
        }
        if (!PASSWORD_RULE.test(password)) {
          return res.status(400).json({ message: PASSWORD_MESSAGE });
        }
        const slug = String(body.slug || '').trim().toLowerCase();
        if (!isValidSlug(slug)) {
          return res.status(400).json({ error: true, field: 'slug', message: SLUG_MESSAGE });
        }

        const existingClient = await clientCollection.findOne(
          { $or: [{ phone }, { email }, { slug }] },
          CI
        );
        if (existingClient) {
          const field = existingClient.phone === phone ? 'phone' : existingClient.email === email ? 'email' : 'slug';
          return res.status(400).json({
            error: true,
            field,
            message: `This ${field} is already registered!`
          });
        }

        const result = await clientCollection.insertOne({
          name,
          phone,
          email,
          address,
          isActive: body.isActive === true,
          slug,
          dbName: makeDbName(slug),
          whatsapp: cleanWhatsapp(body.whatsapp),
          userLimit: parseUserLimit(body.userLimit),
          passwordHash: await hashPassword(password),
          login: 'no',
          createdAt: new Date()
        });
        res.send({ acknowledged: true, insertedId: result.insertedId });
      } catch (error) {
        console.error('Error adding client:', error);
        res.status(500).json({ message: 'Failed to add client' });
      }
    });

    // ক্লায়েন্ট আপডেট করার রাউট
    app.put('/client/:id', verifyToken, verifyAdmin, async (req, res) => {
      try {
        const id = req.params.id;
        if (!ObjectId.isValid(id)) return res.status(404).json({ message: 'Client not found' });

        const body = req.body || {};
        const name = String(body.name || '').trim().slice(0, 100);
        const phone = String(body.phone || '').replace(/\D/g, '').slice(0, 20);
        const email = String(body.email || '').trim().toLowerCase().slice(0, 150);
        const address = String(body.address || '').trim().slice(0, 300);
        const password = String(body.password || '');

        if (!name || !phone || !email || !address) {
          return res.status(400).json({ message: 'All fields are required!' });
        }
        if (parseUserLimit(body.userLimit) === null) {
          return res.status(400).json({ error: true, field: 'userLimit', message: 'User limit must be a whole number (minimum 1)' });
        }
        if (password && !PASSWORD_RULE.test(password)) {
          return res.status(400).json({ message: PASSWORD_MESSAGE });
        }

        const existingClient = await clientCollection.findOne(
          { _id: { $ne: new ObjectId(id) }, $or: [{ phone }, { email }] },
          CI
        );
        if (existingClient) {
          const field = existingClient.phone === phone ? 'phone' : 'email';
          return res.status(400).json({
            error: true,
            field,
            message: `This ${field} is already used by another client!`
          });
        }

        const current = await clientCollection.findOne({ _id: new ObjectId(id) });
        if (!current) return res.status(404).json({ message: 'Client not found' });

        const setDoc = { name, phone, email, address, isActive: body.isActive === true, whatsapp: cleanWhatsapp(body.whatsapp), userLimit: parseUserLimit(body.userLimit) };

        // slug/database একবার ঠিক হলে আর বদলানো যাবে না (data হারানো ঠেকাতে)
        if (!current.slug) {
          const slug = String(body.slug || '').trim().toLowerCase();
          if (!isValidSlug(slug)) {
            return res.status(400).json({ error: true, field: 'slug', message: SLUG_MESSAGE });
          }
          const slugTaken = await clientCollection.findOne({ slug, _id: { $ne: current._id } });
          if (slugTaken) {
            return res.status(400).json({ error: true, field: 'slug', message: 'This subdomain is already taken!' });
          }
          setDoc.slug = slug;
          setDoc.dbName = makeDbName(slug);
        }
        const updateDoc = { $set: setDoc };

        // password blank thakle purano password ei thakbe; notun dile hash hobe ar client force logout hobe
        const unsetDoc = {};
        if (password) {
          setDoc.passwordHash = await hashPassword(password);
          setDoc.login = 'no';
          unsetDoc.password = '';
          unsetDoc.sessionId = '';
        }
        // inactive korle sathe sathe logout
        if (!setDoc.isActive) {
          setDoc.login = 'no';
          unsetDoc.sessionId = '';
        }
        if (Object.keys(unsetDoc).length > 0) updateDoc.$unset = unsetDoc;

        const result = await clientCollection.updateOne({ _id: new ObjectId(id) }, updateDoc);
        res.send(result);
      } catch (error) {
        console.error('Error updating client:', error);
        res.status(500).json({ message: 'Failed to update client' });
      }
    });

    // ৪. ক্লায়েন্ট ডিলিট করার জন্য
    app.delete('/client/:id', verifyToken, verifyAdmin, async (req, res) => {
      try {
        const id = req.params.id;
        if (!ObjectId.isValid(id)) return res.status(404).json({ message: 'Client not found' });
        if (!requireActionToken(req, res)) return;
        const result = await clientCollection.deleteOne({ _id: new ObjectId(id) });
        res.send(result);
      } catch (error) {
        console.error('Error deleting client:', error);
        res.status(500).json({ message: 'Failed to delete client' });
      }
    });

    // ক্লায়েন্টের লগইন স্ট্যাটাস আপডেট বা ফোর্সড লগআউট করার জন্য PATCH রুট
    app.patch('/client/login-status/:id', verifyToken, verifyAdmin, async (req, res) => {
      try {
        const { id } = req.params;
        const { login } = req.body; // 'yes' বা 'no'

        const result = await clientCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { login: 'no' }, $unset: { sessionId: '' } }
        );

        res.send(result);
      } catch (error) {
        res.status(500).send({ message: "Failed to update login status" });
      }
    });

    // ==========================================
    // নতুন যোগ করা: ক্লায়েন্ট লগইন এপিআই
    // ==========================================
    // ----- client login brute force protection -----
    const clientLoginFails = new Map(); // ip|email -> { count, lockUntil }
    const CLIENT_MAX_FAILS = 5;
    const CLIENT_LOCK_TIME = 15 * 60 * 1000;
    setInterval(() => {
      const now = Date.now();
      for (const [k, v] of clientLoginFails) if (v.lockUntil && now > v.lockUntil) clientLoginFails.delete(k);
    }, 60 * 1000).unref();
    const dummyHashPromise = hashPassword(crypto.randomBytes(8).toString('hex'));

    // ----- client token verify (inactive / force logout hole token sathe sathe bondho) -----
    const verifyClientToken = async (req, res, next) => {
      try {
        const token = (req.headers.authorization || '').split(' ')[1];
        if (!token) return res.status(401).send({ message: 'unauthorized access' });
        const decoded = jwt.verify(token, process.env.CLIENT_ACCESS_TOKEN_SECRET, { algorithms: ['HS256'] });
        if (!decoded?.clientId || !ObjectId.isValid(decoded.clientId)) {
          return res.status(401).send({ message: 'unauthorized access' });
        }
        const c = await clientCollection.findOne({ _id: new ObjectId(decoded.clientId) });
        if (decoded.kind === 'staff') {
          const s = await loadStaff(c, decoded);
          if (!s) return res.status(401).send({ message: 'unauthorized access' });
          req.client = c;
          req.staff = s;
          return next();
        }
        if (decoded.staffId) return res.status(401).send({ message: 'unauthorized access' });
        if (!c || c.isActive !== true || c.login !== 'yes' || !c.sessionId || c.sessionId !== decoded.sid) {
          return res.status(401).send({ message: 'unauthorized access' });
        }
        req.client = c;
        next();
      } catch (e) {
        res.status(401).send({ message: 'unauthorized access' });
      }
    };

    // client nijer live status (password chhara)
    app.get('/client/me', verifyClientToken, async (req, res) => {
      const limitInfo = await getLimitInfo(req.client);
      if (req.staff) {
        const s = req.staff;
        return res.send({
          _id: s._id,
          name: s.name,
          email: s.email,
          phone: s.phone || '',
          address: s.address || '',
          role: s.role,
          isActive: true,
          login: 'yes',
          isStaff: true,
          slug: req.client.slug,
          dealerName: req.client.name,
          permissions: s.permissions || {},
          limitExceeded: limitInfo.limitExceeded,
          userLimit: limitInfo.userLimit,
          excess: limitInfo.excess,
        });
      }
      res.send({ ...publicClient(req.client), ...limitInfo });
    });

    // admin ek client er details (password/hash/session kokhono jabe na)
    app.get('/client/:id', verifyToken, verifyAdmin, async (req, res) => {
      try {
        const id = req.params.id;
        if (!ObjectId.isValid(id)) return res.status(404).json({ message: 'Client not found' });
        const c = await clientCollection.findOne({ _id: new ObjectId(id) });
        if (!c) return res.status(404).json({ message: 'Client not found' });
        res.send(publicClient(c));
      } catch (error) {
        res.status(500).json({ message: 'Failed to fetch client' });
      }
    });

    // client nijer password change (shudhu nijer, token theke id ashe; body theke kono id newa hoy na)
    const changePassFails = new Map(); // clientId -> { count, lockUntil }
    setInterval(() => {
      const now = Date.now();
      for (const [k, v] of changePassFails) if (v.lockUntil && now > v.lockUntil) changePassFails.delete(k);
    }, 60 * 1000).unref();

    app.post('/client/change-password', verifyClientToken, async (req, res) => {
      try {
        if (req.staff) return res.status(403).json({ message: 'Only the dealer can change the password.' });
        const key = String(req.client._id);
        const fail = changePassFails.get(key);
        if (fail && fail.lockUntil && Date.now() < fail.lockUntil) {
          return res.status(429).json({ message: 'Too many attempts. Try again later.' });
        }

        const body = req.body || {};
        const currentPassword = typeof body.currentPassword === 'string' ? body.currentPassword : '';
        const newPassword = typeof body.newPassword === 'string' ? body.newPassword : '';
        const confirmPassword = typeof body.confirmPassword === 'string' ? body.confirmPassword : '';

        if (!currentPassword || !newPassword || !confirmPassword) {
          return res.status(400).json({ message: 'All fields are required!' });
        }
        if (currentPassword.length > 128) {
          return res.status(400).json({ message: 'Current password is incorrect!' });
        }
        if (newPassword !== confirmPassword) {
          return res.status(400).json({ message: 'New password and confirm password do not match!' });
        }
        if (!PASSWORD_RULE.test(newPassword)) {
          return res.status(400).json({ message: PASSWORD_MESSAGE });
        }

        let ok = false;
        if (req.client.passwordHash) {
          ok = await verifyPasswordHash(currentPassword, req.client.passwordHash);
        } else if (typeof req.client.password === 'string') {
          ok = safeEqual(currentPassword, req.client.password);
        }

        if (!ok) {
          const cur = fail || { count: 0, lockUntil: 0 };
          cur.count += 1;
          if (cur.count >= 5) {
            cur.lockUntil = Date.now() + 15 * 60 * 1000;
            cur.count = 0;
          }
          changePassFails.set(key, cur);
          return res.status(400).json({ message: 'Current password is incorrect!' });
        }
        changePassFails.delete(key);

        if (currentPassword === newPassword) {
          return res.status(400).json({ message: 'New password must be different from current password!' });
        }

        // notun hash save + session bondho (force logout)
        await clientCollection.updateOne(
          { _id: req.client._id },
          {
            $set: { passwordHash: await hashPassword(newPassword), login: 'no' },
            $unset: { password: '', sessionId: '' },
          }
        );

        res.send({ success: true });
      } catch (error) {
        console.error('Change password error:', error);
        res.status(500).json({ message: 'Failed to update password' });
      }
    });

    // client nijer logout
    app.post('/client/logout', verifyClientToken, async (req, res) => {
      if (req.staff) {
        await client.db(req.client.dbName).collection('user').updateOne({ _id: req.staff._id }, { $unset: { sessionId: '' } });
        return res.send({ success: true });
      }
      await clientCollection.updateOne({ _id: req.client._id }, { $set: { login: 'no' }, $unset: { sessionId: '' } });
      res.send({ success: true });
    });

    // ===== dealer এর staff login (একই /client/login endpoint থেকে ডাকা হয়) =====
    const staffLogin = async (req, res, { email, password, slug, key, fail }) => {
      const invalid = () => res.status(400).json({ message: 'Invalid email or password!' });
      const tenant = slug ? await clientCollection.findOne({ slug }) : null;
      let staff = null;
      if (tenant && tenant.dbName) {
        staff = await client.db(tenant.dbName).collection('user').findOne({ email }, CI);
      }

      let ok = false;
      if (staff && staff.passwordHash) {
        ok = await verifyPasswordHash(password, staff.passwordHash);
      } else {
        await verifyPasswordHash(password, await dummyHashPromise); // timing same রাখার জন্য
      }

      if (!ok) {
        const cur = fail || { count: 0, lockUntil: 0 };
        cur.count += 1;
        if (cur.count >= CLIENT_MAX_FAILS) {
          cur.lockUntil = Date.now() + CLIENT_LOCK_TIME;
          cur.count = 0;
        }
        clientLoginFails.set(key, cur);
        return invalid();
      }
      clientLoginFails.delete(key);

      if (tenant.isActive !== true) return res.status(403).json({ message: 'Your company account is inactive!' });
      if (staff.isActive !== true) return res.status(403).json({ message: 'Your account is inactive! Contact your dealer.' });

      const sid = crypto.randomUUID();
      await client.db(tenant.dbName).collection('user').updateOne(
        { _id: staff._id },
        { $set: { sessionId: sid, lastLoginAt: new Date() } }
      );
      const token = jwt.sign(
        { clientId: String(tenant._id), staffId: String(staff._id), email: staff.email, sid, kind: 'staff' },
        process.env.CLIENT_ACCESS_TOKEN_SECRET,
        { expiresIn: '12h', algorithm: 'HS256' }
      );
      res.send({
        success: true,
        token,
        client: {
          _id: staff._id,
          name: staff.name,
          email: staff.email,
          phone: staff.phone || '',
          address: staff.address || '',
          role: staff.role,
          isActive: true,
          isStaff: true,
          permissions: staff.permissions || {},
        },
      });
    };

    app.post('/client/login', async (req, res) => {
      try {
        const email = String(req.body?.email || '').trim().toLowerCase();
        const password = String(req.body?.password || '');
        const invalid = () => res.status(400).json({ message: 'Invalid email or password!' });

        if (!email || !password || password.length > 128) return invalid();

        const key = `${getIp(req)}|${email}`;
        const fail = clientLoginFails.get(key);
        if (fail && fail.lockUntil && Date.now() < fail.lockUntil) {
          return res.status(429).json({ message: 'Too many attempts. Try again later.' });
        }

        const reqSlugEarly = String(req.body?.slug || '').trim().toLowerCase();
        const client = await clientCollection.findOne({ email }, CI);

        // dealer না হলে (বা অন্য subdomain এর হলে) এই company এর staff হিসেবে চেষ্টা
        if (!client || client.slug !== reqSlugEarly) {
          return staffLogin(req, res, { email, password, slug: reqSlugEarly, key, fail });
        }

        let ok = false;
        if (client) {
          if (client.passwordHash) {
            ok = await verifyPasswordHash(password, client.passwordHash);
          } else if (typeof client.password === 'string') {
            // purano plain password: match korle sathe sathe hash e upgrade
            ok = safeEqual(password, client.password);
            if (ok) {
              await clientCollection.updateOne(
                { _id: client._id },
                { $set: { passwordHash: await hashPassword(password) }, $unset: { password: '' } }
              );
            }
          }
        } else {
          await verifyPasswordHash(password, await dummyHashPromise); // timing same rakhar jonno
        }

        if (!ok) {
          const cur = fail || { count: 0, lockUntil: 0 };
          cur.count += 1;
          if (cur.count >= CLIENT_MAX_FAILS) {
            cur.lockUntil = Date.now() + CLIENT_LOCK_TIME;
            cur.count = 0;
          }
          clientLoginFails.set(key, cur);
          return invalid();
        }

        clientLoginFails.delete(key);

        if (!client.slug || !client.dbName) {
          return res.status(403).json({ message: 'This account has no subdomain yet. Contact admin.' });
        }
        const reqSlug = String(req.body?.slug || '').trim().toLowerCase();
        if (client.slug !== reqSlug) return invalid();

        if (client.isActive !== true) {
          return res.status(403).json({ message: 'Your account is inactive!' });
        }

        const sid = crypto.randomUUID();
        await clientCollection.updateOne(
          { _id: client._id },
          { $set: { login: 'yes', sessionId: sid } }
        );

        const tokenPayload = { clientId: String(client._id), email: client.email, sid };
        const token = jwt.sign(
          tokenPayload,
          process.env.CLIENT_ACCESS_TOKEN_SECRET,
          { expiresIn: '12h', algorithm: 'HS256' }
        );

        // ৫. সফলভাবে রেসপন্স পাঠানো
        res.send({
          success: true,
          token,
          client: {
            _id: client._id,
            name: client.name,
            email: client.email,
            phone: client.phone,
            address: client.address,
            isActive: client.isActive
          }
        });

      } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Internal server error' });
      }
    });



    // ===== বাকি সব API সুরক্ষিত (PROTECT_API=true হলে চালু হবে) =====
    const requireApiAuth = async (req, res, next) => {
      if (req.method === 'OPTIONS') return next();
      if (req.method === 'POST' && req.path === '/contact') return next();

      const isFeatureRead = req.method === 'GET' && (req.path === '/feature' || req.path.startsWith('/feature/'));
      const who = await resolveCaller(req);

      // client: শুধু নিজের database এ ঢুকবে
      if (who?.type === 'client') {
        req.client = who.client;
        req.staff = who.staff || null;
        req.versionDb = who.dbName;
        return tenantStore.run({ dbName: who.dbName }, () => next());
      }

      // login এর আগে (বা admin) feature চাইলে ডিফল্ট (কোনো data যায় না)
      if (isFeatureRead) {
        return res.send(
          req.path === '/feature'
            ? {}
            : { key: req.path.slice('/feature/'.length), enabled: false, value: null }
        );
      }

      // admin: শুধু নিজের control route (contact); client এর business data নয়
      if (who?.type === 'admin') {
        req.decoded = who.decoded;
        if (req.path === '/contact' || req.path.startsWith('/contact/')) return next();
        return res.status(403).send({ message: 'forbidden access' });
      }

      return res.status(401).send({ message: 'unauthorized access' });
    };
    app.use(requireApiAuth);

    // ===== user limit ছাড়িয়ে গেলে dealer ও staff এর সব কাজ বন্ধ =====
    // চলবে শুধু: GET /user, DELETE /user/:id, GET /feature
    const isReservedRole = (n) => String(n || '').toLowerCase().replace(/[\s_-]+/g, '') === 'superadmin';
    app.use(async (req, res, next) => {
      if (!req.client || req.method === 'OPTIONS') return next();
      const info = await getLimitInfo(req.client);
      if (!info.limitExceeded) return next();
      const ok =
        (req.method === 'GET' && (req.path === '/user' || req.path === '/feature' || req.path.startsWith('/feature/'))) ||
        (req.method === 'DELETE' && /^\/user\/[^/]+$/.test(req.path));
      if (ok) return next();
      return res.status(403).send({
        limitExceeded: true,
        message: req.staff
          ? 'ডিলারের user limit পূর্ণ হয়েছে। ডিলারকে জানান।'
          : `User limit পূর্ণ! আগে ${info.excess} জন user delete করুন।`,
      });
    });

    // ===== /user ও /userRole শুধু dealer (client token) এর জন্য =====
    const dealerOnly = (req, res, next) => {
      if (!req.client) return res.status(403).send({ message: 'forbidden access' });
      // staff শুধু তালিকা পড়তে (GET) পারবে, কিছু বদলাতে পারবে না
      // (v1.7q) staff এখন module permission (user_list / user_assign / user_role) দিয়ে চলে, নিচের guard middleware দেখুন
      next();
    };
    app.use('/user', dealerOnly);
    app.use('/userRole', dealerOnly);

    // ===== শুধু dealer নিজে (staff কখনোই নয়) =====
    const dealerStrict = (req, res, next) => {
      if (!req.client || req.staff) return res.status(403).send({ message: 'forbidden access' });
      next();
    };
    app.use('/user-permission', dealerOnly);

    // ===== Permission system: কোন module এর জন্য কোন API =====
    // apis  = permission অনুযায়ী (get/post/put/delete) ব্যবহার করা যাবে
    // reads = module এর View permission থাকলে শুধু GET করা যাবে (পেজ দেখানোর জন্য দরকারি ডাটা)
    // কোনো পেজে 403 আসলে ওই module এর apis/reads এ প্রয়োজনীয় path যোগ করুন
    const PERM_ACTIONS = ['get', 'post', 'put', 'delete'];
    const METHOD_ACTION = { GET: 'get', POST: 'post', PUT: 'put', PATCH: 'put', DELETE: 'delete' };
    const pathMatch = (path, list = []) => list.some((p) => path === p || path.startsWith(p + '/'));

    const FREE_READ = ['/feature'];

    // staff শুধু এই "Save ..." feature গুলো PUT করতে পারবে (সংশ্লিষ্ট module এ Add বা Edit থাকলে)
    const STAFF_FEATURE_KEYS = {
      orderSaveRoute: ['create_order', 'wholesale'],
      orderSaveSr: ['create_order', 'wholesale'],
      orderSaveDsr: ['create_order', 'wholesale'],
      orderDirectSales: ['create_order', 'wholesale'],
      orderPaymentMethod: ['create_order', 'wholesale'],
      purchasePaymentMethod: ['purchase_add', 'purchase_all'],
    };
    const LOOKUP_READ = ['/product', '/category', '/unit', '/company', '/customer', '/route', '/user', '/userRole'];
    const FIN_READ = [
      '/income', '/expense', '/investment', '/adjustment', '/transfer', '/routeExpense',
      '/sales', '/purchase', '/sales-due-payment', '/purchase-due-payment',
      '/sales-bulk-return', '/purchase-bulk-return', '/sales-damage', '/damage-return',
      '/stock-purchase', '/stock-adjustment',
    ];

    // Purchase form পেজগুলোর (balance / stock হিসাব) জন্য দরকারি GET
    const PURCHASE_FORM_READ = [...FIN_READ, '/bulk-return-stock'];

    // Sales form পেজগুলোর (balance / credit limit / stock হিসাব) জন্য দরকারি GET
    const SALES_FORM_READ = [...FIN_READ, '/bulk-return-stock'];

    const PERMISSION_MODULES = {
      dashboard: { reads: [...FIN_READ, '/sales-sr-target'] },
      wholesale: { apis: ['/sales'], reads: [...SALES_FORM_READ, '/sales-sr-target'] },
      create_order: { apis: ['/sales'], reads: SALES_FORM_READ },
      sales_return: { apis: ['/sales'], reads: SALES_FORM_READ },
      sales_bulk_return: { apis: ['/sales-bulk-return', '/sales-bulk-return-resync'], reads: SALES_FORM_READ },
      sales_due_payment: { apis: ['/sales-due-payment'], reads: SALES_FORM_READ },
      sales_sr_target: { apis: ['/sales-sr-target'], reads: ['/sales'] },
      purchase_add: { apis: ['/purchase'], reads: PURCHASE_FORM_READ },
      purchase_all: { apis: ['/purchase'], reads: PURCHASE_FORM_READ },
      purchase_return: { apis: ['/purchase'], reads: PURCHASE_FORM_READ },
      purchase_bulk_return: { apis: ['/purchase-bulk-return', '/bulk-return-stock'], reads: PURCHASE_FORM_READ },
      purchase_due_payment: { apis: ['/purchase-due-payment'], reads: FIN_READ },
      product: { apis: ['/product'], reads: ['/stock-purchase'] },
      category: { apis: ['/category'] },
      units: { apis: ['/unit'] },
      customers: { apis: ['/customer'], reads: ['/sales', '/sales-due-payment', '/sales-bulk-return', '/sales-damage'] },
      company: { apis: ['/company'], reads: ['/purchase', '/purchase-due-payment', '/purchase-bulk-return', '/damage-return'] },
      company_account: { reads: ['/purchase', '/purchase-due-payment', '/purchase-bulk-return', '/damage-return'] },
      customer_account: { reads: ['/sales', '/sales-due-payment', '/sales-bulk-return', '/sales-damage'] },
      routes: { apis: ['/route'] },
      stock_purchase: { apis: ['/stock-purchase'], reads: FIN_READ },
      stock_products: { reads: FIN_READ },
      stock_alert: { reads: FIN_READ },
      stock_adjustment: {
        apis: ['/stock-adjustment', '/adjustment-stock'],
        reads: FIN_READ,
      },
      damage_stock_invoice: { apis: ['/sales-damage'], reads: SALES_FORM_READ },
      damage_single_invoice: { reads: SALES_FORM_READ },
      damage_stock_products: { reads: SALES_FORM_READ },
      damage_return_products: { reads: SALES_FORM_READ },
      damage_return_invoice: {
        apis: ['/damage-return'],
        reads: SALES_FORM_READ,
      },
      account_balance: { reads: FIN_READ },
      account_investment: { apis: ['/investment', '/adjustment'], reads: FIN_READ },
      account_income: { apis: ['/income'], reads: FIN_READ },
      account_expense: { apis: ['/expense'], reads: FIN_READ },
      account_route_expense: { apis: ['/routeExpense'], reads: FIN_READ },
      account_transfer: { apis: ['/transfer'], reads: FIN_READ },
      account_sales: { reads: FIN_READ },
      account_sales_return: { reads: FIN_READ },
      account_sales_bulk_return: { reads: FIN_READ },
      account_sales_damage_return: { reads: FIN_READ },
      account_sales_due: { reads: FIN_READ },
      account_purchase: { reads: FIN_READ },
      account_purchase_return: { reads: FIN_READ },
      account_purchase_bulk_return: { reads: FIN_READ },
      account_purchase_damage_return: { reads: FIN_READ },
      account_purchase_due: { reads: FIN_READ },
      profit_sales_wise: { reads: FIN_READ },
      profit_income: { reads: FIN_READ },
      profit_expense: { reads: FIN_READ },
      profit_route_expense: { reads: FIN_READ },
      profit_others: { reads: FIN_READ },
      ...Object.fromEntries(
        [
          'sales_report_wholesales', 'sales_report_todays', 'sales_report_customer_invoice',
          'sales_report_product_wise', 'sales_report_date_top', 'sales_report_net_delivery',
          'sales_report_top_sheet', 'sales_report_customer_ledger', 'sales_report_customer_due',
          'sales_report_sr_dsr_due', 'sales_report_return',
        ].map((k) => [k, { reads: FIN_READ }])
      ),
      ...Object.fromEntries(
        [
          'purchase_report_invoice', 'purchase_report_product', 'purchase_report_vs_rec_date',
          'purchase_report_vs_rec_sum', 'purchase_report_top_chart', 'purchase_report_ledger',
          'purchase_report_due', 'purchase_report_return',
        ].map((k) => [k, { reads: FIN_READ }])
      ),
      ...Object.fromEntries(
        [
          'stock_report_current', 'stock_report_damage_daily', 'stock_report_damage_summery',
          'stock_report_dam_return', 'stock_report_dam_return_summery',
        ].map((k) => [k, { reads: FIN_READ }])
      ),
      ...Object.fromEntries(
        [
          'account_report_daybook', 'account_report_cashbook', 'account_report_mobile', 'account_report_bank',
          'account_report_income', 'account_report_expense', 'account_report_route_expense', 'account_report_transfer',
          'account_report_top_buy', 'account_report_top_sell', 'account_report_sales_profit',
          'account_report_over_under', 'account_report_daily_statement', 'account_report_income_statement',
        ].map((k) => [k, { reads: FIN_READ }])
      ),
      user_list: { apis: ['/user'], reads: ['/userRole'] },
      user_assign: { apis: ['/user-permission'], reads: ['/user'] },
      user_role: { apis: ['/userRole'] },
      features: { apis: ['/feature'] },
    };

    // শুধু জানা module key ও জানা action গ্রহণ করে; Add/Edit/Delete থাকলে View নিজে থেকে যোগ হয়
    const sanitizePermissions = (input) => {
      const out = {};
      if (!input || typeof input !== 'object' || Array.isArray(input)) return out;
      for (const key of Object.keys(PERMISSION_MODULES)) {
        const raw = input[key];
        if (!Array.isArray(raw)) continue;
        const acts = PERM_ACTIONS.filter((a) => raw.includes(a));
        if (acts.length === 0) continue;
        if (!acts.includes('get')) acts.unshift('get');
        out[key] = acts;
      }
      return out;
    };

    // staff এর প্রতিটা request এ permission চেক (default: বন্ধ)
    app.use((req, res, next) => {
      if (!req.staff) return next(); // dealer এর সব access
      const deny = () => res.status(403).send({ message: 'You do not have permission for this action' });
      const action = METHOD_ACTION[req.method];
      if (!action) return deny();
      if (action === 'get' && pathMatch(req.path, FREE_READ)) return next();

      // order / purchase এর "Save ..." feature: সংশ্লিষ্ট module এ Add বা Edit থাকলে staff পারবে
      if (req.method === 'PUT') {
        const fm = req.path.match(/^\/feature\/([^/]+)$/);
        const need = fm && STAFF_FEATURE_KEYS[fm[1]];
        if (need) {
          const sp = req.staff.permissions || {};
          const okFeature = need.some((k) => Array.isArray(sp[k]) && (sp[k].includes('post') || sp[k].includes('put')));
          if (okFeature) return next();
        }
      }

      // পুরো purchase delete শুধু purchase_all এর Delete permission দিয়ে
      if (action === 'delete' && /^\/purchase\/[^/]+$/.test(req.path)) {
        const pa = (req.staff.permissions || {}).purchase_all;
        return Array.isArray(pa) && pa.includes('delete') ? next() : deny();
      }

      // পুরো order delete শুধু wholesale এর Delete permission দিয়ে
      if (action === 'delete' && /^\/sales\/[^/]+$/.test(req.path)) {
        const w = (req.staff.permissions || {}).wholesale;
        return Array.isArray(w) && w.includes('delete') ? next() : deny();
      }

      const sperm = req.staff.permissions || {};
      const hasP = (k, a) => Array.isArray(sperm[k]) && sperm[k].includes(a);

      // নতুন purchase তৈরি: শুধু purchase_add এর Add দিয়ে
      if (action === 'post' && /^\/purchase\/?$/.test(req.path)) {
        return hasP('purchase_add', 'post') ? next() : deny();
      }
      // নতুন order তৈরি: শুধু create_order এর Add দিয়ে
      if (action === 'post' && /^\/sales\/?$/.test(req.path)) {
        return hasP('create_order', 'post') ? next() : deny();
      }
      // purchase edit: পুরো body শুধু purchase_all Edit দিয়ে.
      // শুধু purchase_return Edit থাকলে body কেটে শুধু returnHistory রাখা হয়
      if (action === 'put' && req.method === 'PUT' && /^\/purchase\/[^/]+$/.test(req.path)) {
        if (hasP('purchase_all', 'put')) return next();
        if ((hasP('purchase_return', 'put') || hasP('purchase_return', 'post')) && Array.isArray(req.body?.returnHistory)) {
          req.body = { returnHistory: req.body.returnHistory };
          return next();
        }
        return deny();
      }
      // order edit: পুরো body শুধু wholesale Edit দিয়ে.
      // শুধু sales_return Edit থাকলে body কেটে শুধু returnHistory রাখা হয়
      if (action === 'put' && req.method === 'PUT' && /^\/sales\/[^/]+$/.test(req.path)) {
        if (hasP('wholesale', 'put')) return next();
        if ((hasP('sales_return', 'put') || hasP('sales_return', 'post')) && Array.isArray(req.body?.returnHistory)) {
          req.body = { returnHistory: req.body.returnHistory };
          return next();
        }
        return deny();
      }

      const perms = req.staff.permissions || {};
      let granted = false;
      let hasAny = false;
      for (const key of Object.keys(perms)) {
        const mod = PERMISSION_MODULES[key];
        const acts = Array.isArray(perms[key]) ? perms[key] : [];
        if (!mod || !acts.includes('get')) continue;
        hasAny = true;
        if (acts.includes(action) && pathMatch(req.path, mod.apis)) { granted = true; break; }
        if (action === 'get' && pathMatch(req.path, mod.reads)) { granted = true; break; }
      }
      if (!granted && hasAny && action === 'get' && pathMatch(req.path, LOOKUP_READ)) granted = true;
      return granted ? next() : deny();
    });

    // ===== Users module guard (v1.7q): staff নিজের চেয়ে সমান / বেশি permission এর user বদলাতে পারবে না =====
    // permSubset(a, b): a এর সব module + action b তেও আছে?
    const permSubset = (a, b) => {
      const pa = sanitizePermissions(a);
      const pb = sanitizePermissions(b);
      return Object.keys(pa).every((k) => pa[k].every((x) => (pb[k] || []).includes(x)));
    };
    // target শুধু তখনই বদলানো যাবে যখন actor এর permission তার চেয়ে কঠোরভাবে বেশি
    const permStrictlyLess = (target, actor) => permSubset(target, actor) && !permSubset(actor, target);

    app.use(async (req, res, next) => {
      if (!req.staff) return next(); // dealer (Super Admin) এর সব access
      if (req.method !== 'PUT' && req.method !== 'DELETE') return next();
      const m = req.path.match(/^\/(user|user-permission)\/([^/]+)$/);
      if (!m) return next();
      const kind = m[1];
      const targetId = m[2];
      const deny = (message) => res.status(403).send({ message });

      if (!ObjectId.isValid(targetId)) return res.status(404).send({ message: 'User not found' });
      // নিজেকে delete / inactive / edit / permission বদল করা যাবে না
      if (String(req.staff._id) === String(targetId)) {
        return deny('নিজের user নিজে বদলানো বা delete করা যাবে না!');
      }
      const target = await userCollection.findOne({ _id: new ObjectId(targetId) }, { projection: { permissions: 1 } });
      if (!target) return res.status(404).send({ message: 'User not found' });
      // নিজের সমান বা বেশি permission এর user কে বদলানো যাবে না
      if (!permStrictlyLess(target.permissions, req.staff.permissions)) {
        return deny('আপনার সমান বা বেশি permission এর user কে বদলানো যাবে না!');
      }
      // যে permission নিজের নেই তা অন্যকে দেওয়া যাবে না (privilege escalation বন্ধ)
      if (kind === 'user-permission') {
        const clean = sanitizePermissions(req.body?.permissions);
        if (!permSubset(clean, req.staff.permissions)) {
          return deny('যে permission আপনার নিজের নেই তা অন্যকে দেওয়া যাবে না!');
        }
      }
      next();
    });

    // ===== user permission API (শুধু dealer) =====
    app.get('/user-permission/:userId', async (req, res) => {
      const { userId } = req.params;
      if (!ObjectId.isValid(userId)) return res.status(404).send({ message: 'User not found' });
      const u = await userCollection.findOne(
        { _id: new ObjectId(userId) },
        { projection: { name: 1, email: 1, role: 1, isActive: 1, permissions: 1 } }
      );
      if (!u) return res.status(404).send({ message: 'User not found' });
      res.send({
        _id: u._id,
        name: u.name,
        email: u.email,
        role: u.role,
        isActive: u.isActive,
        permissions: sanitizePermissions(u.permissions),
      });
    });

    app.put('/user-permission/:userId', async (req, res) => {
      const { userId } = req.params;
      if (!ObjectId.isValid(userId)) return res.status(404).send({ message: 'User not found' });
      const target = await userCollection.findOne({ _id: new ObjectId(userId) }, { projection: { _id: 1 } });
      if (!target) return res.status(404).send({ message: 'User not found' });
      const clean = sanitizePermissions(req.body?.permissions);
      await userCollection.updateOne(
        { _id: target._id },
        { $set: { permissions: clean, permissionsUpdatedAt: new Date() } }
      );
      res.send({ success: true, permissions: clean });
    });

    // ===== dealer এর user (SR / Manager / Delivery Man) validate + password hash =====
    const EMAIL_RULE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    const PHONE_RULE = /^[0-9+\-\s()]{6,20}$/;
    const cleanStr = (v, max) => (typeof v === 'string' ? v.trim().slice(0, max) : '');

    const buildUserDoc = async (body, { requirePassword = false, excludeId = null } = {}) => {
      const b = body || {};
      const name = cleanStr(b.name, 100);
      const email = cleanStr(b.email, 150).toLowerCase();
      const phone = cleanStr(b.phone, 20);
      const address = cleanStr(b.address, 300);
      const roleInput = cleanStr(b.role, 50);
      const password = typeof b.password === 'string' ? b.password : '';

      if (!name) return { error: 'Name is required!' };
      if (!email || !EMAIL_RULE.test(email)) return { error: 'A valid email is required!' };
      if (phone && !PHONE_RULE.test(phone)) return { error: 'Invalid phone number!' };
      if (!roleInput) return { error: 'Role is required!' };

      // role অবশ্যই এই dealer এর নিজের role list এ থাকতে হবে
      const roleDoc = await userRoleCollection.findOne({ role: roleInput }, CI);
      if (!roleDoc) return { error: 'Invalid role selected!' };

      const notSelf = excludeId ? { _id: { $ne: excludeId } } : {};
      const emailDup = await userCollection.findOne({ email, ...notSelf }, CI);
      if (emailDup) return { error: 'This email already exists!' };
      if (phone) {
        const phoneDup = await userCollection.findOne({ phone, ...notSelf });
        if (phoneDup) return { error: 'This phone number already exists!' };
      }

      let passwordHash = null;
      if (password) {
        if (!PASSWORD_RULE.test(password)) return { error: PASSWORD_MESSAGE };
        passwordHash = await hashPassword(password);
      } else if (requirePassword) {
        return { error: 'Password is required!' };
      }

      return {
        doc: { name, email, phone, address, role: roleDoc.role, isActive: b.isActive === true },
        passwordHash,
      };
    };

    // ===== Stock / টাকার কাজ: হয় সব হবে, নাহলে কিছুই হবে না (transaction) =====
    // একই client এর এই ধরনের কাজ লাইন ধরে একটার পর একটা চলবে (দুজন একসাথে একই স্টক বেচতে পারবে না)
    const tenantLocks = new Map();
    const acquireTenantLock = async (key) => {
      const prev = tenantLocks.get(key) || Promise.resolve();
      let release;
      const gate = new Promise((r) => (release = r));
      const tail = prev.then(() => gate);
      tenantLocks.set(key, tail);
      await prev;
      return () => {
        release();
        if (tenantLocks.get(key) === tail) tenantLocks.delete(key);
      };
    };

    const stockTx = async (req, res, next) => {
      const store = tenantStore.getStore();
      if (!store || !store.dbName) return next();

      const release = await acquireTenantLock(store.dbName);
      const session = client.startSession();
      let done = false;
      let sending = false;
      let timer = null;

      const finish = async (commit) => {
        if (done) return true;
        done = true;
        clearTimeout(timer);
        let ok = true;
        try {
          if (commit) await session.commitTransaction();
          else await session.abortTransaction();
        } catch (e) {
          ok = false;
          console.error('Transaction end failed:', e.message);
          try { await session.abortTransaction(); } catch (e2) { }
        }
        try { await session.endSession(); } catch (e) { }
        release();
        return ok;
      };

      try {
        session.startTransaction({ writeConcern: { w: 'majority' } });
      } catch (e) {
        await finish(false);
        return res.status(500).send({ message: 'Server error' });
      }
      store.session = session;

      // response পাঠানোর ঠিক আগে: সফল হলে commit, error হলে সব বাতিল (rollback)
      const origSend = res.send.bind(res);
      res.send = function (body) {
        if (sending) return origSend(body);
        sending = true;
        const commit = res.statusCode < 400;
        finish(commit).then((ok) => {
          if (commit && !ok) {
            res.status(500);
            return origSend({ message: 'Save failed, nothing was changed. Please try again.' });
          }
          return origSend(body);
        });
        return res;
      };

      timer = setTimeout(() => {
        if (!sending) res.status(500).send({ message: 'Request timed out, nothing was changed.' });
      }, 55 * 1000);
      res.on('close', () => { finish(false); });

      next();
    };

    // কোন কোন route এ transaction লাগবে
    const STOCK_TX_RULES = [
      { methods: ['POST'], re: /^\/(stock-adjustment|sales-damage|sales-bulk-return|sales-bulk-return-resync|purchase-bulk-return|sales)$/ },
      { methods: ['PUT', 'DELETE'], re: /^\/(stock-adjustment|purchase|sales)\/[^/]+$/ },
      { methods: ['PUT'], re: /^\/(sales-damage|sales-bulk-return|purchase-bulk-return)\/[^/]+$/ },
      { methods: ['PATCH'], re: /^\/stock-purchase\/[^/]+\/sell-price$/ },
    ];
    app.use((req, res, next) => {
      const hit = STOCK_TX_RULES.some((r) => r.methods.includes(req.method) && r.re.test(req.path));
      return hit ? stockTx(req, res, next) : next();
    });

    // contact related api


    app.get('/contact', verifyToken, verifyAdmin, async (req, res) => {
      const result = await contactCollection.find().toArray();
      res.send(result);
    });

    app.post('/contact', mkLimiter(15 * 60 * 1000, 10, 'Too many messages. Try again later.'), async (req, res) => {
      const clean = {};
      Object.entries(req.body || {}).slice(0, 12).forEach(([k, v]) => {
        if ((typeof v === 'string' || typeof v === 'number') && !k.startsWith('$') && !k.includes('.')) {
          clean[k] = typeof v === 'string' ? v.slice(0, 2000) : v;
        }
      });
      if (Object.keys(clean).length === 0) return res.status(400).send({ message: 'Invalid data' });
      req.body = clean;
      const item = req.body;
      const result = await contactCollection.insertOne(item);
      res.send(result);
    });

    app.delete('/contact/:id', verifyToken, verifyAdmin, async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await contactCollection.deleteOne(query);
      res.send(result);
    });


    // feature (software settings) related api

    // সব feature এর অবস্থা একসাথে: { saveDraft: true, ... }
    app.get('/feature', async (req, res) => {
      try {
        const list = await featureCollection.find().toArray();
        const result = {};
        list.forEach((f) => {
          result[f.key] = f.enabled === true;
        });
        res.send(result);
      } catch (error) {
        res.status(500).send({ error: 'Failed to fetch features' });
      }
    });

    // একটা feature এর enabled + value (যেমন saved route / delivery man)
    app.get('/feature/:key', async (req, res) => {
      try {
        const doc = await featureCollection.findOne({ key: req.params.key });
        res.send({
          key: req.params.key,
          enabled: doc ? doc.enabled === true : false,
          value: doc && doc.value !== undefined ? doc.value : null,
        });
      } catch (error) {
        res.status(500).send({ error: 'Failed to fetch feature' });
      }
    });

    // যেকোনো feature ON/OFF করা (নতুন feature এর জন্য নতুন key দিলেই হবে)    

    app.put('/feature/:key', async (req, res) => {
      try {
        const key = req.params.key;
        const enabled = req.body.enabled === true;
        const setFields = { key: key, enabled: enabled, updatedAt: new Date() };
        // value পাঠালে সেটাও save হবে (যেমন route / delivery man)
        if (req.body.value !== undefined) setFields.value = req.body.value;
        const result = await featureCollection.updateOne(
          { key: key },
          { $set: setFields },
          { upsert: true }
        );
        res.send(result);
      } catch (error) {
        res.status(500).send({ error: 'Failed to update feature' });
      }
    });

    // একটা feature এর key database থেকে মুছে ফেলা
    app.delete('/feature/:key', async (req, res) => {
      try {
        const result = await featureCollection.deleteOne({ key: req.params.key });
        res.send(result);
      } catch (error) {
        res.status(500).send({ error: 'Failed to delete feature' });
      }
    });


    // transfer related api

    app.get('/transfer', async (req, res) => {
      const result = await transferCollection.find().toArray();
      res.send(result);
    });

    app.post('/transfer', async (req, res) => {
      const item = req.body;
      const result = await transferCollection.insertOne(item);
      res.send(result);
    });

    app.put('/transfer/:id', async (req, res) => {
      try {
        const { id } = req.params;
        const { _id: _ignoreId, createdAt: _ignoreCreated, ...updatedData } = req.body;

        const result = await transferCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: updatedData }
        );

        if (result.matchedCount === 0) {
          return res.status(404).json({ error: 'Transfer record not found' });
        }

        res.status(200).json({ message: 'Transfer updated successfully' });
      } catch (error) {
        console.error('Error updating transfer:', error);
        res.status(500).json({ error: 'Internal Server Error' });
      }
    });

    app.delete('/transfer/:id', async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await transferCollection.deleteOne(query);
      res.send(result);
    });




    // route expense related api


    app.get('/routeExpense', async (req, res) => {
      const result = await routeExpenseCollection.find().toArray();
      res.send(result);
    });

    app.post('/routeExpense', async (req, res) => {
      const item = req.body;
      const result = await routeExpenseCollection.insertOne(item);
      res.send(result);
    });

    app.delete('/routeExpense/:id', async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await routeExpenseCollection.deleteOne(query);
      res.send(result);
    });

    app.put('/routeExpense/:id', async (req, res) => {
      try {
        const { id } = req.params;
        const updatedData = req.body;

        const result = await routeExpenseCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: updatedData }
        );

        if (result.matchedCount === 0) {
          return res.status(404).json({ error: 'Route Expense record not found' });
        }

        res.status(200).json({ message: 'Route Expense updated successfully' });
      } catch (error) {
        console.error('Error updating route expense:', error);
        res.status(500).json({ error: 'Internal Server Error' });
      }
    });




    // income related api

    app.get('/income', async (req, res) => {
      const result = await incomeCollection.find().toArray();
      res.send(result);
    });

    app.post('/income', async (req, res) => {
      const item = req.body;
      const result = await incomeCollection.insertOne(item);
      res.send(result);
    });

    app.delete('/income/:id', async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await incomeCollection.deleteOne(query);
      res.send(result);
    });

    app.put('/income/:id', async (req, res) => {
      try {
        const { id } = req.params;
        const updatedData = req.body;

        const result = await incomeCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: updatedData }
        );

        if (result.matchedCount === 0) {
          return res.status(404).json({ error: 'Income record not found' });
        }

        res.status(200).json({ message: 'Income updated successfully' });
      } catch (error) {
        console.error('Error updating income:', error);
        res.status(500).json({ error: 'Internal Server Error' });
      }
    })



    // expense related api


    app.get('/expense', async (req, res) => {
      const result = await expenseCollection.find().toArray();
      res.send(result);
    });

    app.post('/expense', async (req, res) => {
      const item = req.body;
      const result = await expenseCollection.insertOne(item);
      res.send(result);
    });

    app.delete('/expense/:id', async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await expenseCollection.deleteOne(query);
      res.send(result);
    });

    app.put('/expense/:id', async (req, res) => {
      try {
        const { id } = req.params;
        const updatedData = req.body;

        const result = await expenseCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: updatedData }
        );

        if (result.matchedCount === 0) {
          return res.status(404).json({ error: 'Expense record not found' });
        }

        res.status(200).json({ message: 'Expense updated successfully' });
      } catch (error) {
        console.error('Error updating expense:', error);
        res.status(500).json({ error: 'Internal Server Error' });
      }
    });






    // Investment related APIs

    app.get('/investment', async (req, res) => {
      try {
        const result = await investmentCollection.find().toArray();
        res.send(result);
      } catch (error) {
        res.status(500).send({ error: 'Failed to fetch investments' });
      }
    });


    app.post('/investment', async (req, res) => {
      try {
        const item = req.body;
        const result = await investmentCollection.insertOne(item);
        res.send(result);
      } catch (error) {
        res.status(500).send({ error: 'Failed to add investment' });
      }
    });


    app.put('/investment/:id', async (req, res) => {
      try {
        const { id } = req.params;
        const { _id: _ignoreId, createdAt: _ignoreCreated, ...updatedData } = req.body;

        const result = await investmentCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: updatedData }
        );

        if (result.matchedCount === 0) {
          return res.status(404).json({ error: 'Investment record not found' });
        }

        res.status(200).json({ message: 'Investment updated successfully' });
      } catch (error) {
        console.error('Error updating investment:', error);
        res.status(500).json({ error: 'Internal Server Error' });
      }
    });


    app.delete('/investment/:id', async (req, res) => {
      try {
        const id = req.params.id;
        const query = { _id: new ObjectId(id) };
        const result = await investmentCollection.deleteOne(query);
        res.send(result);
      } catch (error) {
        res.status(500).send({ error: 'Failed to delete investment' });
      }
    });



    // adjustment related api

    app.get('/adjustment', async (req, res) => {
      try {
        const result = await adjustmentCollection.find().toArray();
        res.send(result);
      } catch (error) {
        res.status(500).send({ error: 'Failed to fetch adjustments' });
      }
    });

    // নির্দিষ্ট investment-এর adjustment history আনার জন্য (investmentId দিয়ে filter)
    app.get('/adjustment/:investmentId', async (req, res) => {
      try {
        const investmentId = req.params.investmentId;
        const result = await adjustmentCollection
          .find({ adjustmentID: investmentId })
          .toArray();
        res.send(result);
      } catch (error) {
        res.status(500).send({ error: 'Failed to fetch adjustment history' });
      }
    });

    app.post('/adjustment', async (req, res) => {
      try {
        const item = req.body;
        const result = await adjustmentCollection.insertOne(item);
        res.send(result);
      } catch (error) {
        res.status(500).send({ error: 'Failed to add adjustment' });
      }
    });

    app.put('/adjustment/:id', async (req, res) => {
      try {
        const { id } = req.params;
        const { _id: _ignoreId, createdAt: _ignoreCreated, ...updatedData } = req.body;

        const result = await adjustmentCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: updatedData }
        );

        if (result.matchedCount === 0) {
          return res.status(404).json({ error: 'Adjustment record not found' });
        }

        res.status(200).json({ message: 'Adjustment updated successfully' });
      } catch (error) {
        console.error('Error updating adjustment:', error);
        res.status(500).json({ error: 'Internal Server Error' });
      }
    });

    app.delete('/adjustment/:id', async (req, res) => {
      try {
        const id = req.params.id;
        const query = { _id: new ObjectId(id) };
        const result = await adjustmentCollection.deleteOne(query);
        res.send(result);
      } catch (error) {
        res.status(500).send({ error: 'Failed to delete adjustment' });
      }
    });


    // user related api

    // --- User Routes (Node.js & Express) ---

    // Get all users
    app.get('/user', async (req, res) => {
      try {
        const result = await userCollection
          .find({}, { projection: req.staff && !(req.staff.permissions?.user_assign || []).includes('get') ? { password: 0, passwordHash: 0, sessionId: 0, permissions: 0 } : { password: 0, passwordHash: 0, sessionId: 0 } })
          .toArray();
        res.send(result);
      } catch (error) {
        res.status(500).send({ error: 'Failed to fetch users' });
      }
    });

    // Add new user (POST)
    app.post('/user', async (req, res) => {
      try {
        const user = req.body;
        const limit = Number.isInteger(req.client?.userLimit) && req.client.userLimit >= 1 ? req.client.userLimit : 10;
        const staffCount = await userCollection.countDocuments({});
        if (staffCount + 1 >= limit) {
          return res.status(400).send({ message: `User limit reached (${limit} including you). Delete a user or ask admin to increase the limit.` });
        }
        // আপনি চাইলে এখানে পাসওয়ার্ড হাশ করে নিতে পারেন
        const built = await buildUserDoc(user, { requirePassword: true });
        if (built.error) return res.status(400).send({ message: built.error });
        const result = await userCollection.insertOne({
          ...built.doc,
          passwordHash: built.passwordHash,
          createdAt: new Date().toLocaleString('en-GB', { timeZone: 'Asia/Dhaka', hour12: true }),
        });
        res.send(result);
      } catch (error) {
        res.status(500).send({ error: 'Failed to create user' });
      }
    });

    // Update a user (PUT)
    app.put('/user/:id', async (req, res) => {
      try {
        const { id } = req.params;
        const { _id: _ignoreId, createdAt: _ignoreCreated, ...updatedData } = req.body;

        if (!ObjectId.isValid(id)) return res.status(404).json({ error: 'User record not found' });
        const existing = await userCollection.findOne({ _id: new ObjectId(id) });
        if (!existing) return res.status(404).json({ error: 'User record not found' });

        const built = await buildUserDoc(updatedData, { requirePassword: false, excludeId: existing._id });
        if (built.error) return res.status(400).json({ message: built.error });

        const setDoc = { ...built.doc };
        const unsetDoc = {};
        if (built.passwordHash) {
          // dealer নতুন password দিলে: নতুন hash + পুরোনো session বন্ধ
          setDoc.passwordHash = built.passwordHash;
          setDoc.passwordChangedAt = new Date();
          unsetDoc.password = '';
          unsetDoc.sessionId = '';
        } else if (!existing.passwordHash && typeof existing.password === 'string' && existing.password) {
          // আগের plain password থাকলে edit এর সময়ই hash এ রূপান্তর
          setDoc.passwordHash = await hashPassword(existing.password);
          unsetDoc.password = '';
        }
        if (!setDoc.isActive) unsetDoc.sessionId = '';

        const updateDoc = { $set: setDoc };
        if (Object.keys(unsetDoc).length > 0) updateDoc.$unset = unsetDoc;
        const result = await userCollection.updateOne({ _id: existing._id }, updateDoc);

        if (result.matchedCount === 0) {
          return res.status(404).json({ error: 'User record not found' });
        }

        res.status(200).json({ message: 'User updated successfully' });
      } catch (error) {
        console.error('Error updating user:', error);
        res.status(500).json({ error: 'Internal Server Error' });
      }
    });

    // Delete user
    app.delete('/user/:id', async (req, res) => {
      try {
        const id = req.params.id;
        const query = { _id: new ObjectId(id) };
        const result = await userCollection.deleteOne(query);
        res.send(result);
      } catch (error) {
        res.status(500).send({ error: 'Failed to delete user' });
      }
    });




    // userRole related api

    // ১. সকল ইউজার রোল ফেচ করা (GET)
    app.get('/userRole', async (req, res) => {
      const result = await userRoleCollection.find().toArray();
      res.send(result);
    });

    // ২. নতুন ইউজার রোল যোগ করা (POST)
    app.post('/userRole', async (req, res) => {
      const item = req.body;
      const roleName = typeof item.role === 'string' ? item.role.trim() : '';
      if (roleName.length < 2 || roleName.length > 50) {
        return res.status(400).send({ message: 'Role name must be 2-50 characters!' });
      }
      if (isReservedRole(roleName)) return res.status(400).send({ message: '"Super Admin" নামে role বানানো যাবে না!' });
      const roleDup = await userRoleCollection.findOne({ role: roleName }, CI);
      if (roleDup) return res.status(400).send({ message: 'This role already exists!' });
      const result = await userRoleCollection.insertOne({ role: roleName, createdAt: new Date().toISOString() });
      res.send(result);
    });

    app.put('/userRole/:id', async (req, res) => {
      try {
        const { id } = req.params;
        const { _id: _ignoreId, createdAt: _ignoreCreated, ...updatedData } = req.body;

        const roleName = typeof updatedData.role === 'string' ? updatedData.role.trim() : '';
        if (roleName.length < 2 || roleName.length > 50) {
          return res.status(400).json({ message: 'Role name must be 2-50 characters!' });
        }
        if (!ObjectId.isValid(id)) return res.status(404).json({ error: 'Role record not found' });
        const existingRole = await userRoleCollection.findOne({ _id: new ObjectId(id) });
        if (!existingRole) return res.status(404).json({ error: 'Role record not found' });

        if (isReservedRole(roleName)) return res.status(400).json({ message: '"Super Admin" নামে role বানানো যাবে না!' });
        const roleDup = await userRoleCollection.findOne({ role: roleName, _id: { $ne: existingRole._id } }, CI);
        if (roleDup) return res.status(400).json({ message: 'This role already exists!' });

        const result = await userRoleCollection.updateOne(
          { _id: existingRole._id },
          { $set: { role: roleName } }
        );
        // role এর নাম বদলালে ওই role এর সব user এর role ও বদলে যাবে
        if (existingRole.role && existingRole.role !== roleName) {
          await userCollection.updateMany({ role: existingRole.role }, { $set: { role: roleName } });
        }

        if (result.matchedCount === 0) {
          return res.status(404).json({ error: 'Role record not found' });
        }

        res.status(200).json({ message: 'Role updated successfully' });
      } catch (error) {
        console.error('Error updating role:', error);
        res.status(500).json({ error: 'Internal Server Error' });
      }
    });

    // ৪. ইউজার রোল ডিলিট করা (DELETE)
    app.delete('/userRole/:id', async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const roleToDelete = await userRoleCollection.findOne(query);
      if (roleToDelete?.role) {
        const inUse = await userCollection.countDocuments({ role: roleToDelete.role });
        if (inUse > 0) {
          return res.status(400).send({ message: `This role is used by ${inUse} user(s). Change or delete those users first.` });
        }
      }
      const result = await userRoleCollection.deleteOne(query);
      res.send(result);
    });






    // Company related APIs

    // Get all companies
    app.get('/company', async (req, res) => {
      const result = await companyCollection.find().toArray();
      res.send(result);
    });

    // Post a new company
    app.post('/company', async (req, res) => {
      const item = req.body;
      const result = await companyCollection.insertOne(item);
      res.send(result);
    });

    // Update a company (PUT)
    app.put('/company/:id', async (req, res) => {
      try {
        const { id } = req.params;
        const { _id: _ignoreId, createdAt: _ignoreCreated, ...updatedData } = req.body;

        const result = await companyCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: updatedData }
        );

        if (result.matchedCount === 0) {
          return res.status(404).json({ error: 'Company record not found' });
        }

        res.status(200).json({ message: 'Company updated successfully' });
      } catch (error) {
        console.error('Error updating company:', error);
        res.status(500).json({ error: 'Internal Server Error' });
      }
    });

    // Delete a company
    app.delete('/company/:id', async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await companyCollection.deleteOne(query);
      res.send(result);
    });




    // Purchase Due Payment related APIs

    // Fallback invoice no (YYMMDDHHMMSS, Asia/Dhaka time)
    const generateInvoiceNo = () => {
      const parts = new Intl.DateTimeFormat('en-GB', {
        timeZone: 'Asia/Dhaka',
        year: '2-digit',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hourCycle: 'h23',
      }).formatToParts(new Date());
      const get = (t) => parts.find((p) => p.type === t).value;
      return `${get('year')}${get('month')}${get('day')}${get('hour')}${get('minute')}${get('second')}`;
    };

    // Get all due payments (newest first)
    app.get('/purchase-due-payment', async (req, res) => {
      const list = await PurchaseDuePaymentCollection.find().sort({ _id: -1 }).toArray();
      // invoiceNo na thakle _id er timestamp theke generate
      const result = list.map((p) => {
        if (p.invoiceNo) return p;
        const parts = new Intl.DateTimeFormat('en-GB', {
          timeZone: 'Asia/Dhaka',
          year: '2-digit',
          month: '2-digit',
          day: '2-digit',
          hour: '2-digit',
          minute: '2-digit',
          second: '2-digit',
          hourCycle: 'h23',
        }).formatToParts(new ObjectId(p._id).getTimestamp());
        const get = (t) => parts.find((x) => x.type === t).value;
        return { ...p, invoiceNo: `${get('year')}${get('month')}${get('day')}${get('hour')}${get('minute')}${get('second')}` };
      });
      res.send(result);
    });

    // Post a new due payment
    app.post('/purchase-due-payment', async (req, res) => {
      const item = req.body;
      const amount = Math.round((Number(item.amount) || 0) * 100) / 100;

      if (!item.company || !item.date || !item.paymentMethod || !item.paymentAccount || amount <= 0) {
        return res.status(400).send({ message: 'Company, date, payment method, account and amount are required' });
      }

      const doc = {
        company: item.company,
        companyId: item.companyId || '',
        companyContact: item.companyContact || '',
        date: item.date, // YYYY-MM-DD
        paymentMethod: item.paymentMethod,
        paymentAccount: item.paymentAccount,
        amount,
        note: item.note || '',
        type: item.type === 'Get' || item.status === 'Get' ? 'Get' : 'Pay',
        status: item.type === 'Get' || item.status === 'Get' ? 'Get' : 'Pay',
        invoiceNo: item.invoiceNo || generateInvoiceNo(),
        createdAt: item.createdAt || new Date().toLocaleString('en-GB', { timeZone: 'Asia/Dhaka' }),
      };

      const result = await PurchaseDuePaymentCollection.insertOne(doc);
      res.send(result);
    });

    // Delete a due payment
    app.delete('/purchase-due-payment/:id', async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await PurchaseDuePaymentCollection.deleteOne(query);
      res.send(result);
    });




    // Sales Due Payment related APIs

    // Get all sales due payments (newest first)
    app.get('/sales-due-payment', async (req, res) => {
      const list = await SalesDuePaymentCollection.find().sort({ _id: -1 }).toArray();
      const result = list.map((p) => {
        if (p.invoiceNo) return p;
        const parts = new Intl.DateTimeFormat('en-GB', {
          timeZone: 'Asia/Dhaka',
          year: '2-digit',
          month: '2-digit',
          day: '2-digit',
          hour: '2-digit',
          minute: '2-digit',
          second: '2-digit',
          hourCycle: 'h23',
        }).formatToParts(new ObjectId(p._id).getTimestamp());
        const get = (t) => parts.find((x) => x.type === t).value;
        return { ...p, invoiceNo: `${get('year')}${get('month')}${get('day')}${get('hour')}${get('minute')}${get('second')}` };
      });
      res.send(result);
    });

    // Post a new sales due payment
    app.post('/sales-due-payment', async (req, res) => {
      const item = req.body;
      const amount = Math.round((Number(item.amount) || 0) * 100) / 100;

      if (!item.customer || !item.date || !item.paymentMethod || !item.paymentAccount || amount <= 0) {
        return res.status(400).send({ message: 'Customer, date, payment method, account and amount are required' });
      }

      const doc = {
        customer: item.customer,
        customerId: item.customerId || '',
        customerContact: item.customerContact || '',
        srId: item.srId || '',
        sr: item.sr || '',
        deliveredById: item.deliveredById || '',
        deliveredBy: item.deliveredBy || '',
        date: item.date, // YYYY-MM-DD
        paymentMethod: item.paymentMethod,
        paymentAccount: item.paymentAccount,
        amount,
        note: item.note || '',
        type: item.type === 'Pay' || item.status === 'Pay' ? 'Pay' : 'Get',
        status: item.type === 'Pay' || item.status === 'Pay' ? 'Pay' : 'Get',
        invoiceNo: item.invoiceNo || generateInvoiceNo(),
        createdAt: item.createdAt || new Date().toLocaleString('en-GB', { timeZone: 'Asia/Dhaka' }),
      };

      const result = await SalesDuePaymentCollection.insertOne(doc);
      res.send(result);
    });

    // Delete a sales due payment
    app.delete('/sales-due-payment/:id', async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await SalesDuePaymentCollection.deleteOne(query);
      res.send(result);
    });




    // Sales SR Target related APIs

    // Get all SR targets (newest first)
    app.get('/sales-sr-target', async (req, res) => {
      try {
        const result = await SalesSrTargetCollection.find().sort({ _id: -1 }).toArray();
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: 'Failed to fetch SR targets' });
      }
    });

    // Post a new SR target
    app.post('/sales-sr-target', async (req, res) => {
      try {
        const item = req.body;
        const amount = Math.round((Number(item.targetAmount) || 0) * 100) / 100;

        if (!item.srId || !item.sr || !item.targetMonth || amount <= 0) {
          return res.status(400).send({ message: 'SR, target month and target amount are required' });
        }

        const duplicate = await SalesSrTargetCollection.findOne({
          srId: item.srId,
          targetMonth: item.targetMonth,
        });
        if (duplicate) {
          return res.status(400).send({ message: 'This SR already has a target for this month!' });
        }

        const doc = {
          srId: item.srId,
          sr: item.sr,
          targetMonth: item.targetMonth, // YYYY-MM
          targetAmount: amount,
          note: item.note || '',
          createdAt: item.createdAt || new Date().toLocaleString('en-GB', { timeZone: 'Asia/Dhaka' }),
        };

        const result = await SalesSrTargetCollection.insertOne(doc);
        res.send(result);
      } catch (error) {
        console.error('Error adding SR target:', error);
        res.status(500).send({ message: 'Failed to add SR target' });
      }
    });

    // Update an SR target
    app.put('/sales-sr-target/:id', async (req, res) => {
      try {
        const { id } = req.params;
        const { _id: _ignoreId, createdAt: _ignoreCreated, ...updatedData } = req.body;

        const amount = Math.round((Number(updatedData.targetAmount) || 0) * 100) / 100;
        if (!updatedData.srId || !updatedData.sr || !updatedData.targetMonth || amount <= 0) {
          return res.status(400).send({ message: 'SR, target month and target amount are required' });
        }

        const duplicate = await SalesSrTargetCollection.findOne({
          srId: updatedData.srId,
          targetMonth: updatedData.targetMonth,
          _id: { $ne: new ObjectId(id) },
        });
        if (duplicate) {
          return res.status(400).send({ message: 'This SR already has a target for this month!' });
        }

        updatedData.targetAmount = amount;
        updatedData.note = updatedData.note || '';

        const result = await SalesSrTargetCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: updatedData }
        );

        if (result.matchedCount === 0) {
          return res.status(404).send({ message: 'SR target not found' });
        }

        res.status(200).send({ message: 'SR target updated successfully' });
      } catch (error) {
        console.error('Error updating SR target:', error);
        res.status(500).send({ message: 'Internal Server Error' });
      }
    });

    // Delete an SR target
    app.delete('/sales-sr-target/:id', async (req, res) => {
      try {
        const id = req.params.id;
        const query = { _id: new ObjectId(id) };
        const result = await SalesSrTargetCollection.deleteOne(query);
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: 'Failed to delete SR target' });
      }
    });




    // Product Related APIs

    // Get all products
    app.get('/product', async (req, res) => {
      const result = await productCollection.find().toArray();
      res.send(result);
    });

    // Add a product
    app.post('/product', async (req, res) => {
      const item = req.body;
      const result = await productCollection.insertOne(item);
      res.send(result);
    });

    // Delete a product
    app.delete('/product/:id', async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await productCollection.deleteOne(query);
      res.send(result);
    });

    // Update/Edit a product
    app.put('/product/:id', async (req, res) => {
      const id = req.params.id;
      const updatedProduct = req.body;

      // যদি _id রিকোয়েস্ট বডিতে চলে আসে, তবে সেটি বাদ দেওয়া ভালো যাতে MongoDB তে _id আপডেট করার সময় Immutable ফিল্ডের এরর না আসে
      delete updatedProduct._id;

      // createdAt যেন Edit এ কখনো না বদলায়
      delete updatedProduct.createdAt;

      const filter = { _id: new ObjectId(id) };
      const updateDoc = { $set: updatedProduct };

      try {
        const result = await productCollection.updateOne(filter, updateDoc);
        res.send(result);
      } catch (error) {
        console.error('Error updating product:', error);
        res.status(500).send({ error: 'Failed to update product' });
      }
    });







    // Customer related APIs

    // Get all customers
    app.get('/customer', async (req, res) => {
      const result = await customerCollection.find().toArray();
      res.send(result);
    });

    // Post a new customer
    app.post('/customer', async (req, res) => {
      const item = req.body;
      const result = await customerCollection.insertOne(item);
      res.send(result);
    });

    // Update a customer (PUT)
    app.put('/customer/:id', async (req, res) => {
      try {
        const { id } = req.params;
        const { _id: _ignoreId, createdAt: _ignoreCreated, ...updatedData } = req.body;

        const result = await customerCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: updatedData }
        );

        if (result.matchedCount === 0) {
          return res.status(404).json({ error: 'Customer record not found' });
        }

        res.status(200).json({ message: 'Customer updated successfully' });
      } catch (error) {
        console.error('Error updating customer:', error);
        res.status(500).json({ error: 'Internal Server Error' });
      }
    });

    // Delete a customer
    app.delete('/customer/:id', async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await customerCollection.deleteOne(query);
      res.send(result);
    });




    // Unit related API 

    // ১. সব ইউনিট একসাথে রিভার্স অর্ডারে পাওয়ার জন্য (পেজিনেশন ছাড়া)
    app.get('/unit', async (req, res) => {
      try {
        const result = await unitCollection.find()
          .sort({ order: -1 }) // নতুনগুলো আগে দেখাবে
          .toArray();

        res.send(result);
      } catch (error) {
        res.status(500).send({ message: "Error fetching units", error });
      }
    });

    // ২. নতুন ইউনিট যোগ করার সময় (সর্বোচ্চ অর্ডার হিসাব করে যুক্ত করা)
    app.post('/unit', async (req, res) => {
      try {
        const item = req.body;

        // সবচেয়ে বড় order ভ্যালু বের করে তার সাথে ১ যোগ করা, যাতে নতুনটি সবার উপরে থাকে
        const lastUnit = await unitCollection.findOne({}, { sort: { order: -1 } });
        const nextOrder = lastUnit ? (lastUnit.order + 1) : 1;

        const newUnit = {
          name: item.name,
          isActive: item.isActive !== undefined ? item.isActive : true,
          order: nextOrder,
          createdAt: new Date().toLocaleString("en-GB", {
            day: "2-digit",
            month: "2-digit",
            year: "numeric",
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit",
            hour12: true
          }).replace(',', '')
        };

        const result = await unitCollection.insertOne(newUnit);
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: "Error adding unit", error });
      }
    });

    // ৩. নির্দিষ্ট ইউনিট আপডেট করার জন্য
    app.put('/unit/:id', async (req, res) => {
      try {
        const { id } = req.params;
        const { _id: _ignoreId, createdAt: _ignoreCreated, order: _ignoreOrder, ...updatedData } = req.body;

        const result = await unitCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: updatedData }
        );

        if (result.matchedCount === 0) {
          return res.status(404).json({ error: 'Unit record not found' });
        }

        res.status(200).json({ message: 'Unit updated successfully' });
      } catch (error) {
        console.error('Error updating unit:', error);
        res.status(500).json({ error: 'Internal Server Error' });
      }
    });

    // ৪. নির্দিষ্ট ইউনিট ডিলিট করার জন্য
    app.delete('/unit/:id', async (req, res) => {
      try {
        const id = req.params.id;
        const query = { _id: new ObjectId(id) };
        const result = await unitCollection.deleteOne(query);
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: "Error deleting unit", error });
      }
    });





    // Route related API 

    // ১. সব রাউট একসাথে রিভার্স অর্ডারে পাওয়ার জন্য (পেজিনেশন ছাড়া)
    app.get('/route', async (req, res) => {
      try {
        const result = await routeCollection.find()
          .sort({ order: -1 }) // নতুনগুলো আগে দেখাবে
          .toArray();

        res.send(result);
      } catch (error) {
        res.status(500).send({ message: "Error fetching routes", error });
      }
    });

    // ২. নতুন রাউট যোগ করার সময়
    app.post('/route', async (req, res) => {
      try {
        const item = req.body;

        // সবচেয়ে বড় order ভ্যালু বের করে তার সাথে ১ যোগ করা
        const duplicate = await routeCollection.findOne(
          { name: String(item.name || '').trim() },
          { collation: { locale: 'en', strength: 2 } }
        );
        if (duplicate) {
          return res.status(400).send({ message: 'This route name already exists!' });
        }

        const lastroute = await routeCollection.findOne({}, { sort: { order: -1 } });
        const nextOrder = lastroute ? (lastroute.order + 1) : 1;

        const newroute = {
          name: item.name,
          isActive: item.isActive !== undefined ? item.isActive : true,
          order: nextOrder,
          createdAt: new Date().toLocaleString("en-GB", {
            day: "2-digit",
            month: "2-digit",
            year: "numeric",
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit",
            hour12: true
          }).replace(',', '')
        };

        const result = await routeCollection.insertOne(newroute);
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: "Error adding route", error });
      }
    });

    // ৩. নির্দিষ্ট রাউট আপডেট করার জন্য
    app.put('/route/:id', async (req, res) => {
      try {
        const { id } = req.params;
        const { _id: _ignoreId, createdAt: _ignoreCreated, order: _ignoreOrder, ...updatedData } = req.body;

        if (updatedData.name !== undefined) {
          updatedData.name = String(updatedData.name || '').trim();

          const duplicate = await routeCollection.findOne(
            { name: updatedData.name, _id: { $ne: new ObjectId(id) } },
            { collation: { locale: 'en', strength: 2 } }
          );
          if (duplicate) {
            return res.status(400).json({ message: 'This route name already exists!' });
          }
        }

        const result = await routeCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: updatedData, $unset: { code: "" } }
        );

        if (result.matchedCount === 0) {
          return res.status(404).json({ error: 'Route record not found' });
        }

        res.status(200).json({ message: 'Route updated successfully' });
      } catch (error) {
        console.error('Error updating route:', error);
        res.status(500).json({ error: 'Internal Server Error' });
      }
    });

    // ৪. নির্দিষ্ট রাউট ডিলিট করার জন্য
    app.delete('/route/:id', async (req, res) => {
      try {
        const id = req.params.id;
        const query = { _id: new ObjectId(id) };
        const result = await routeCollection.deleteOne(query);
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: "Error deleting route", error });
      }
    });




    // Category related API 

    // ১. সব ক্যাটাগরি একসাথে রিভার্স অর্ডারে পাওয়ার জন্য (পেজিনেশন ছাড়া)
    app.get('/category', async (req, res) => {
      try {
        const result = await categoryCollection.find()
          .sort({ order: -1 }) // নতুনগুলো আগে দেখাবে
          .toArray();

        res.send(result);
      } catch (error) {
        res.status(500).send({ message: "Error fetching categories", error });
      }
    });

    // ২. নতুন ক্যাটাগরি যোগ করার সময় (সর্বোচ্চ অর্ডার হিসাব করে যুক্ত করা)
    app.post('/category', async (req, res) => {
      try {
        const item = req.body;

        // সবচেয়ে বড় order ভ্যালু বের করে তার সাথে ১ যোগ করা, যাতে নতুনটি সবার উপরে থাকে
        const lastCategory = await categoryCollection.findOne({}, { sort: { order: -1 } });
        const nextOrder = lastCategory ? (lastCategory.order + 1) : 1;

        const options = { timeZone: 'Asia/Dhaka', hour12: true };
        const now = new Date();
        const formattedDate = now.toLocaleDateString('en-GB', options) + ' ' + now.toLocaleTimeString('en-US', options).toLowerCase();

        const newCategory = {
          name: item.name,
          isActive: item.isActive !== undefined ? item.isActive : true,
          order: nextOrder,
          createdAt: formattedDate
        };

        const result = await categoryCollection.insertOne(newCategory);
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: "Error adding category", error });
      }
    });

    // ৩. নির্দিষ্ট ক্যাটাগরি আপডেট করার জন্য
    app.put('/category/:id', async (req, res) => {
      try {
        const { id } = req.params;
        const { _id: _ignoreId, createdAt: _ignoreCreated, order: _ignoreOrder, ...updatedData } = req.body;

        const result = await categoryCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: updatedData }
        );

        if (result.matchedCount === 0) {
          return res.status(404).json({ error: 'Category record not found' });
        }

        res.status(200).json({ message: 'Category updated successfully' });
      } catch (error) {
        console.error('Error updating category:', error);
        res.status(500).json({ error: 'Internal Server Error' });
      }
    });

    // ৪. নির্দিষ্ট ক্যাটাগরি ডিলিট করার জন্য
    app.delete('/category/:id', async (req, res) => {
      try {
        const id = req.params.id;
        const query = { _id: new ObjectId(id) };
        const result = await categoryCollection.deleteOne(query);
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: "Error deleting category", error });
      }
    });


















































    // stock adjustment related api

    app.get('/damage-return', async (req, res) => {
      const result = await damageReturnCollection.find().toArray();
      res.send(result);
    });

    app.get('/damage-return/:id', async (req, res) => {
      const result = await damageReturnCollection.findOne({ _id: new ObjectId(req.params.id) });
      res.send(result);
    });

    app.post('/damage-return', async (req, res) => {
      const item = req.body;
      item.createdAt = new Date().toISOString();
      if (item.payment && Number(item.payment.amount) > 0) {
        item.status = 'Approved';
        item.approvedAt = item.createdAt;
      } else {
        item.status = 'Pending';
      }
      const result = await damageReturnCollection.insertOne(item);
      res.send(result);
    });

    app.put('/damage-return/:id', async (req, res) => {
      const { _id: _ignoreId, ...updatedData } = req.body;
      if (updatedData.payment && Number(updatedData.payment.amount) > 0) {
        updatedData.status = 'Approved';
        updatedData.approvedAt = new Date().toISOString();
      }
      const result = await damageReturnCollection.updateOne(
        { _id: new ObjectId(req.params.id) },
        { $set: updatedData }
      );
      res.send(result);
    });

    app.delete('/damage-return/:id', async (req, res) => {
      const result = await damageReturnCollection.deleteOne({ _id: new ObjectId(req.params.id) });
      res.send(result);
    });

    // ===== Stock adjustment (In = stock PLUS, Out = stock MINUS) =====
    const applyAdjustmentsToUsed = async (used, excludeId = null) => {
      const list = await stockAdjustmentCollection.find({ 'stockAllocations.0': { $exists: true } }).toArray();
      list.forEach((r) => {
        if (excludeId && String(r._id) === String(excludeId)) return;
        (r.stockAllocations || []).forEach((a) => {
          const k = String(a.batchId);
          const cur = used.get(k) || { paid: 0, free: 0 };
          cur[a.pool === 'paid' ? 'paid' : 'free'] += a.direction === 'out' ? toNum(a.qty) : -toNum(a.qty);
          used.set(k, cur);
        });
      });
    };

    const buildAdjustmentPlan = async (items = [], excludeId = null) => {
      const pools = await loadStockPools({ excludeAdjustmentId: excludeId });
      const map = new Map(pools.map((x) => [String(x.b._id), x]));
      const shortages = [];
      const allocations = [];
      items.forEach((it) => {
        const x = map.get(String(it.batchId));
        if (!x) {
          shortages.push({ productName: it.productName, need: 0, available: 0 });
          return;
        }
        [['paid', 'Main', it.mainType, it.totalQty], ['free', 'Free', it.freeType, it.freeQty]].forEach(([pool, label, type, qtyRaw]) => {
          const q = toNum(qtyRaw);
          if (q <= 0) return;
          const dir = type === 'out' ? 'out' : 'in';
          if (pool === 'paid' && x.b.isFreeProduct) {
            shortages.push({ productName: `${it.productName} (Main)`, need: q, available: 0 });
            return;
          }
          if (dir === 'out') {
            if (x[pool] < q) {
              shortages.push({ productName: `${it.productName} (${label})`, need: q, available: x[pool] });
              return;
            }
            x[pool] -= q;
          }
          allocations.push({
            batchId: String(x.b._id),
            batchNo: x.b.batchNo,
            invoiceNo: x.b.invoiceNo,
            productId: it.productId,
            pool,
            direction: dir,
            qty: q,
          });
        });
      });
      return { ok: shortages.length === 0, shortages, allocations };
    };

    // purano allocation soriye notun boshale kono batch minus hoye jabe kina
    const adjustmentBreaksStock = async (oldAllocs = [], newAllocs = []) => {
      const pools = await loadStockPools();
      const batchToProduct = new Map(pools.map((x) => [String(x.b._id), String(x.b.productId)]));
      const totals = new Map();
      pools.forEach((x) => {
        const pid = String(x.b.productId);
        const cur = totals.get(pid) || { paid: 0, free: 0 };
        cur.paid += x.paid;
        cur.free += x.free;
        totals.set(pid, cur);
      });
      const delta = new Map();
      const add = (a, sign) => {
        const pid = batchToProduct.get(String(a.batchId)) || String(a.productId);
        const k = `${pid}|${a.pool === 'paid' ? 'paid' : 'free'}`;
        delta.set(k, (delta.get(k) || 0) + sign * (a.direction === 'out' ? -1 : 1) * toNum(a.qty));
      };
      oldAllocs.forEach((a) => add(a, -1));
      newAllocs.forEach((a) => add(a, 1));
      for (const [k, d] of delta) {
        if (d >= 0) continue;
        const sep = k.lastIndexOf('|');
        const pid = k.slice(0, sep);
        const pool = k.slice(sep + 1);
        const cur = totals.get(pid);
        if (cur && cur[pool] + d < 0) return true;
      }
      return false;
    };

    // stock adjustment related api

    app.get('/adjustment-stock', async (req, res) => {
      try {
        const pools = await loadStockPools({ excludeAdjustmentId: req.query.excludeId || null });
        res.send(
          pools.map((x) => {
            const paidQ = toNum(x.b.paidQty);
            return {
              batchId: String(x.b._id),
              batchNo: x.b.batchNo,
              invoiceNo: x.b.invoiceNo,
              productId: x.b.productId,
              productName: x.b.productName,
              company: x.b.company,
              isFreeProduct: x.b.isFreeProduct === true,
              cost: x.b.isFreeProduct || paidQ <= 0 ? 0 : Math.round((toNum(x.b.netCost) / paidQ) * 100) / 100,
              paid: x.paid,
              free: x.free,
              date: x.b.receiveDate || x.b.purchaseDate || '',
            };
          })
        );
      } catch (err) {
        res.status(500).send({ message: 'Stock load failed' });
      }
    });

    app.get('/stock-adjustment', async (req, res) => {
      const result = await stockAdjustmentCollection.find().toArray();
      res.send(result);
    });

    app.get('/stock-adjustment/:id', async (req, res) => {
      if (!ObjectId.isValid(req.params.id)) return res.status(404).send({ message: 'Not found' });
      const result = await stockAdjustmentCollection.findOne({ _id: new ObjectId(req.params.id) });
      res.send(result);
    });

    app.post('/stock-adjustment', async (req, res) => {
      const { stockAllocations: _ignore, ...item } = req.body;
      item.createdAt = new Date().toISOString();
      const plan = await buildAdjustmentPlan(item.items || []);
      if (!plan.ok) return res.status(400).send({ message: 'স্টকে পণ্য নেই!', shortages: plan.shortages });
      item.stockAllocations = plan.allocations;
      const result = await stockAdjustmentCollection.insertOne(item);
      res.send(result);
    });

    app.put('/stock-adjustment/:id', async (req, res) => {
      try {
        const id = req.params.id;
        const { _id: _ignoreId, stockAllocations: _ignoreAlloc, createdAt: _ignoreCreated, ...updatedData } = req.body;
        const old = await stockAdjustmentCollection.findOne({ _id: new ObjectId(id) });
        if (!old) return res.status(404).send({ message: 'Adjustment not found!' });
        const plan = await buildAdjustmentPlan(updatedData.items || [], id);
        if (!plan.ok) return res.status(400).send({ message: 'স্টকে পণ্য নেই!', shortages: plan.shortages });
        if (await adjustmentBreaksStock(old.stockAllocations || [], plan.allocations)) {
          return res.status(400).send({ message: 'এই পরিবর্তনে স্টক মাইনাস হয়ে যাবে!', shortages: [] });
        }
        updatedData.stockAllocations = plan.allocations;
        const result = await stockAdjustmentCollection.updateOne({ _id: new ObjectId(id) }, { $set: updatedData });
        res.send(result);
      } catch (err) {
        console.error(err);
        res.status(500).send({ message: 'Update failed' });
      }
    });

    app.delete('/stock-adjustment/:id', async (req, res) => {
      try {
        const id = req.params.id;
        const old = await stockAdjustmentCollection.findOne({ _id: new ObjectId(id) });
        if (!old) return res.status(404).send({ message: 'Adjustment not found!' });
        if (await adjustmentBreaksStock(old.stockAllocations || [], [])) {
          return res.status(400).send({ message: 'Delete korle stock minus hoye jabe!', shortages: [] });
        }
        const result = await stockAdjustmentCollection.deleteOne({ _id: new ObjectId(id) });
        res.send(result);
      } catch (err) {
        console.error(err);
        res.status(500).send({ message: 'Delete failed' });
      }
    });

    // sales damage (standalone damage form) related api

    app.get('/sales-damage', async (req, res) => {
      const result = await salesDamageCollection.find().toArray();
      res.send(result);
    });

    app.get('/sales-damage/:id', async (req, res) => {
      const result = await salesDamageCollection.findOne({ _id: new ObjectId(req.params.id) });
      res.send(result);
    });

    app.post('/sales-damage', async (req, res) => {
      const { stockAllocations: _ignore, ...item } = req.body;
      item.createdAt = new Date().toISOString();
      item.stockAllocations = [];
      if (!item.customerId) {
        const plan = await buildDamagePlan(item.items || []);
        if (!plan.ok) return res.status(400).send({ message: 'স্টকে পণ্য নেই!', shortages: plan.shortages });
        item.stockAllocations = plan.allocations;
      }
      const result = await salesDamageCollection.insertOne(item);
      res.send(result);
    });

    app.put('/sales-damage/:id', async (req, res) => {
      const { _id: _ignoreId, stockAllocations: _ignoreAlloc, ...updatedData } = req.body;
      updatedData.editedAt = new Date().toISOString();
      if (!updatedData.customerId) {
        const plan = await buildDamagePlan(updatedData.items || [], req.params.id);
        if (!plan.ok) return res.status(400).send({ message: 'স্টকে পণ্য নেই!', shortages: plan.shortages });
        updatedData.stockAllocations = plan.allocations;
      }
      const result = await salesDamageCollection.updateOne(
        { _id: new ObjectId(req.params.id) },
        { $set: updatedData }
      );
      res.send(result);
    });

    app.delete('/sales-damage/:id', async (req, res) => {
      const result = await salesDamageCollection.deleteOne({ _id: new ObjectId(req.params.id) });
      res.send(result);
    });

    // sales bulk related api

    app.get('/sales-bulk-return', async (req, res) => {
      const result = await salesBulkReturnCollection.find().toArray();
      res.send(result);
    });

    app.get('/sales-bulk-return/:id', async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await salesBulkReturnCollection.findOne(query);
      res.send(result);
    });

    app.post('/sales-bulk-return', async (req, res) => {
      const { stockAllocations: _ignore, ...item } = req.body;
      item.createdAt = new Date().toISOString();
      const plan = await buildSalesBulkReturnPlan(item.items || []);
      item.stockAllocations = plan.allocations;
      const result = await salesBulkReturnCollection.insertOne(item);
      res.send(result);
    });

    app.post('/sales-bulk-return-resync', async (req, res) => {
      const all = await salesBulkReturnCollection.find().toArray();
      for (const r of all) {
        const plan = await buildSalesBulkReturnPlan(r.items || [], r._id);
        await salesBulkReturnCollection.updateOne({ _id: r._id }, { $set: { stockAllocations: plan.allocations } });
      }
      res.send({ ok: true, count: all.length });
    });

    app.put('/sales-bulk-return/:id', async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const { _id: _ignoreId, stockAllocations: _ignoreAlloc, ...updatedData } = req.body;
      const plan = await buildSalesBulkReturnPlan(updatedData.items || [], id);
      updatedData.stockAllocations = plan.allocations;
      const result = await salesBulkReturnCollection.updateOne(query, { $set: updatedData });
      res.send(result);
    });

    app.delete('/sales-bulk-return/:id', async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await salesBulkReturnCollection.deleteOne(query);
      res.send(result);
    });


    // ===== Sales bulk return (customer return) => stock PLUS =====
    const applySalesBulkReturnsToUsed = async (used, excludeBulkId = null) => {
      const list = await salesBulkReturnCollection.find({ 'stockAllocations.0': { $exists: true } }).toArray();
      list.forEach((r) => {
        if (excludeBulkId && String(r._id) === String(excludeBulkId)) return;
        (r.stockAllocations || []).forEach((a) => {
          const k = String(a.batchId);
          const cur = used.get(k) || { paid: 0, free: 0 };
          cur[a.pool === 'paid' ? 'paid' : 'free'] -= toNum(a.qty); // used theke minus = stock plus
          used.set(k, cur);
        });
      });
    };

    // Return qty ke notun batch theke shuru kore (jekhane sold ache sekhane) ferot dey
    const buildSalesBulkReturnPlan = async (items = [], excludeId = null) => {
      const pools = await loadStockPools({ excludeSalesBulkId: excludeId });
      const need = new Map();
      items.forEach((it) => {
        const k = String(it.productId);
        if (!need.has(k)) need.set(k, { name: it.productName, paid: 0, free: 0 });
        const n = need.get(k);
        n.paid += toNum(it.totalQty);
        n.free += toNum(it.freeQty);
      });

      const allocations = [];
      for (const [pid, n] of need) {
        let list = pools.filter((x) => String(x.b.productId) === pid);
        if (!list.length) list = pools.filter((x) => x.b.productName === n.name);
        list = list.slice().reverse(); // notun batch age
        if (!list.length) continue;

        const push = (x, pool, qty) =>
          allocations.push({
            batchId: String(x.b._id),
            batchNo: x.b.batchNo,
            invoiceNo: x.b.invoiceNo,
            productId: pid,
            pool,
            qty,
          });

        for (const [pool, want] of [['paid', n.paid], ['free', n.free]]) {
          let remaining = want;
          const capKey = pool === 'paid' ? 'paidCap' : 'freeCap';
          for (const x of list) {
            if (remaining <= 0) break;
            const t = Math.min(x[capKey], remaining);
            if (t <= 0) continue;
            x[capKey] -= t;
            push(x, pool, t);
            remaining -= t;
          }
          if (remaining > 0) {
            const target = pool === 'paid' ? list.find((x) => !x.b.isFreeProduct) : list[0];
            if (target) push(target, pool, remaining);
            else push(list[0], 'free', remaining);
          }
        }
      }
      return { ok: true, allocations };
    };

    // ===== Bulk return stock helpers =====
    // ===== Damage (customer chhara) => stock MINUS =====
    const applyDamageToUsed = async (used, excludeDamageId = null) => {
      const list = await salesDamageCollection.find({ 'stockAllocations.0': { $exists: true } }).toArray();
      list.forEach((r) => {
        if (excludeDamageId && String(r._id) === String(excludeDamageId)) return;
        (r.stockAllocations || []).forEach((a) => {
          const k = String(a.batchId);
          const cur = used.get(k) || { paid: 0, free: 0 };
          cur[a.pool === 'paid' ? 'paid' : 'free'] += toNum(a.qty);
          used.set(k, cur);
        });
      });
    };

    const buildDamagePlan = async (items = [], excludeDamageId = null) => {
      const pools = await loadStockPools({ excludeDamageId });
      const need = new Map();
      items.forEach((it) => {
        const k = String(it.productId);
        if (!need.has(k)) need.set(k, { name: it.productName, paid: 0, free: 0 });
        const n = need.get(k);
        n.paid += toNum(it.totalQty);
        n.free += toNum(it.freeQty);
      });

      const shortages = [];
      const allocations = [];

      for (const [pid, n] of need) {
        let list = pools.filter((x) => String(x.b.productId) === pid);
        if (!list.length) list = pools.filter((x) => x.b.productName === n.name);
        const totalPaid = list.reduce((s, x) => s + x.paid, 0);
        const totalFree = list.reduce((s, x) => s + x.free, 0);

        let short = false;
        if (totalPaid < n.paid) {
          shortages.push({ productName: `${n.name} (Main)`, need: n.paid, available: totalPaid });
          short = true;
        }
        if (totalFree < n.free) {
          shortages.push({ productName: `${n.name} (Free)`, need: n.free, available: totalFree });
          short = true;
        }
        if (short) continue;

        for (const [poolKey, want] of [['paid', n.paid], ['free', n.free]]) {
          let remaining = want;
          for (const x of list) {
            if (remaining <= 0) break;
            const t = Math.min(x[poolKey], remaining);
            if (t <= 0) continue;
            x[poolKey] -= t;
            allocations.push({
              batchId: String(x.b._id),
              batchNo: x.b.batchNo,
              invoiceNo: x.b.invoiceNo,
              productId: pid,
              pool: poolKey,
              qty: t,
            });
            remaining -= t;
          }
        }
      }
      return { ok: shortages.length === 0, shortages, allocations };
    };

    const loadStockPools = async ({ excludeBulkId = null, excludeSalesBulkId = null, excludeDamageId = null, excludeAdjustmentId = null } = {}) => {
      const batches = await stockPurchaseCollection.find().toArray();
      batches.sort((a, b) => {
        const diff = batchTime(a) - batchTime(b);
        if (diff !== 0) return diff;
        return new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime();
      });

      const purchaseIds = [...new Set(batches.map((b) => b.purchaseId).filter(Boolean))]
        .map((i) => { try { return new ObjectId(i); } catch (e) { return null; } })
        .filter(Boolean);
      const purchases = purchaseIds.length
        ? await purchaseCollection.find({ _id: { $in: purchaseIds } }).toArray()
        : [];
      const pMap = new Map(purchases.map((p) => [String(p._id), p]));

      const poolOf = (a) => a.pool || ((a.kind || 'main') === 'main' ? 'paid' : 'free');
      const used = new Map();
      const addUsed = (batchId, pool, qty) => {
        const k = String(batchId);
        const cur = used.get(k) || { paid: 0, free: 0 };
        cur[pool] += qty;
        used.set(k, cur);
      };

      const usedSales = await salesCollection.find({ 'stockAllocations.0': { $exists: true } }).toArray();
      usedSales.forEach((s) => {
        (s.stockAllocations || []).forEach((a) => {
          addUsed(a.batchId, poolOf(a), Math.max(toNum(a.qty) - toNum(a.returned), 0));
        });
      });

      const usedBulk = await purchaseBulkReturnCollection.find({ 'stockAllocations.0': { $exists: true } }).toArray();
      usedBulk.forEach((r) => {
        if (excludeBulkId && String(r._id) === String(excludeBulkId)) return;
        (r.stockAllocations || []).forEach((a) => addUsed(a.batchId, a.pool === 'paid' ? 'paid' : 'free', toNum(a.qty)));
      });

      await applySalesBulkReturnsToUsed(used, excludeSalesBulkId);
      await applyDamageToUsed(used, excludeDamageId);
      await applyAdjustmentsToUsed(used, excludeAdjustmentId);

      return batches.map((b) => {
        const ret = getBatchReturnedSplit(b, pMap.get(String(b.purchaseId)));
        const u = used.get(String(b._id)) || { paid: 0, free: 0 };
        if (b.isFreeProduct) {
          const free = Math.max(toNum(b.freeQty) - ret.free - (u.paid + u.free), 0);
          return { b, paid: 0, free, paidCap: 0, freeCap: Math.max(toNum(b.freeQty) - ret.free - free, 0) };
        }
        const paid = Math.max(toNum(b.paidQty) - ret.paid - u.paid, 0);
        const free = Math.max(toNum(b.freeQty) - ret.free - u.free, 0);
        return {
          b,
          paid,
          free,
          paidCap: Math.max(toNum(b.paidQty) - ret.paid - paid, 0),
          freeCap: Math.max(toNum(b.freeQty) - ret.free - free, 0),
        };
      });
    };

    const buildBulkReturnPlan = async (items = [], excludeBulkId = null) => {
      const pools = await loadStockPools({ excludeBulkId });
      const need = new Map();
      items.forEach((it) => {
        const k = String(it.productId);
        if (!need.has(k)) need.set(k, { name: it.productName, paid: 0, free: 0, bm: false, bf: false });
        const n = need.get(k);
        n.paid += toNum(it.totalPcs);
        n.free += toNum(it.freeTotalQty);
        if (it.borrowMain === true) n.bm = true;
        if (it.borrowFree === true) n.bf = true;
      });

      const shortages = [];
      const allocations = [];

      const take = (list, poolKey, kind, pid, want) => {
        let remaining = want;
        for (const x of list) {
          if (remaining <= 0) break;
          const t = Math.min(x[poolKey], remaining);
          if (t <= 0) continue;
          x[poolKey] -= t;
          allocations.push({
            batchId: String(x.b._id),
            batchNo: x.b.batchNo,
            invoiceNo: x.b.invoiceNo,
            productId: pid,
            pool: poolKey,
            kind,
            qty: t,
          });
          remaining -= t;
        }
      };

      for (const [pid, n] of need) {
        let list = pools.filter((x) => String(x.b.productId) === pid);
        if (!list.length) list = pools.filter((x) => x.b.productName === n.name);
        const totalPaid = list.reduce((s, x) => s + x.paid, 0);
        const totalFree = list.reduce((s, x) => s + x.free, 0);

        const mainShort = Math.max(n.paid - totalPaid, 0);
        const freeShort = Math.max(n.free - totalFree, 0);
        const surplusFree = Math.max(totalFree - n.free, 0);
        const surplusPaid = Math.max(totalPaid - n.paid, 0);

        let mainFromFree = 0;
        let freeFromMain = 0;
        let short = false;

        if (mainShort > 0) {
          if (surplusFree >= mainShort) mainFromFree = mainShort;
          else {
            shortages.push({ productName: `${n.name} (Main)`, need: n.paid, available: totalPaid });
            short = true;
          }
        }
        if (freeShort > 0) {
          if (surplusPaid >= freeShort) freeFromMain = freeShort;
          else {
            shortages.push({ productName: `${n.name} (Free)`, need: n.free, available: totalFree });
            short = true;
          }
        }
        if (short) continue;

        take(list, 'paid', 'main', pid, n.paid - mainFromFree);
        take(list, 'free', 'free', pid, n.free - freeFromMain);
        if (mainFromFree > 0) take(list, 'free', 'main', pid, mainFromFree);
        if (freeFromMain > 0) take(list, 'paid', 'free', pid, freeFromMain);
      }
      return { ok: shortages.length === 0, shortages, allocations };
    };

    // (purano version, ar use hocche na)
    const buildBulkReturnPlanOld = async (items = [], excludeBulkId = null) => {
      const pools = await loadStockPools({ excludeBulkId });
      const need = new Map();
      items.forEach((it) => {
        const k = String(it.productId);
        if (!need.has(k)) need.set(k, { name: it.productName, paid: 0, free: 0 });
        const n = need.get(k);
        n.paid += toNum(it.totalPcs);
        n.free += toNum(it.freeTotalQty);
      });

      const shortages = [];
      const allocations = [];

      for (const [pid, n] of need) {
        let list = pools.filter((x) => String(x.b.productId) === pid);
        if (!list.length) list = pools.filter((x) => x.b.productName === n.name);
        const totalPaid = list.reduce((s, x) => s + x.paid, 0);
        const totalFree = list.reduce((s, x) => s + x.free, 0);

        let short = false;
        if (totalPaid < n.paid) {
          shortages.push({ productName: `${n.name} (Main)`, need: n.paid, available: totalPaid });
          short = true;
        }
        if (totalFree < n.free) {
          shortages.push({ productName: `${n.name} (Free)`, need: n.free, available: totalFree });
          short = true;
        }
        if (short) continue;

        for (const [poolKey, want] of [['paid', n.paid], ['free', n.free]]) {
          let remaining = want;
          for (const x of list) {
            if (remaining <= 0) break;
            const t = Math.min(x[poolKey], remaining);
            if (t <= 0) continue;
            x[poolKey] -= t;
            allocations.push({
              batchId: String(x.b._id),
              batchNo: x.b.batchNo,
              invoiceNo: x.b.invoiceNo,
              productId: pid,
              pool: poolKey,
              qty: t,
            });
            remaining -= t;
          }
        }
      }
      return { ok: shortages.length === 0, shortages, allocations };
    };




    // purchase bulk return related api

    app.get('/bulk-return-stock', async (req, res) => {
      try {
        const pools = await loadStockPools({
          excludeBulkId: req.query.excludeId || null,
          excludeDamageId: req.query.excludeDamageId || null,
        });
        const map = {};
        pools.forEach((x) => {
          const paidQ = toNum(x.b.paidQty);
          const cost = x.b.isFreeProduct || paidQ <= 0 ? 0 : Math.round((toNum(x.b.netCost) / paidQ) * 100) / 100;
          const batch = {
            batchId: String(x.b._id),
            batchNo: x.b.batchNo,
            invoiceNo: x.b.invoiceNo,
            cost,
            paid: x.paid,
            free: x.free,
          };
          [String(x.b.productId), `name:${x.b.productName}`].forEach((k) => {
            if (!map[k]) map[k] = { paid: 0, free: 0, batches: [] };
            map[k].paid += x.paid;
            map[k].free += x.free;
            map[k].batches.push(batch);
          });
        });
        res.send(map);
      } catch (err) {
        res.status(500).send({ message: 'Stock load failed' });
      }
    });

    app.get('/purchase-bulk-return', async (req, res) => {
      const result = await purchaseBulkReturnCollection.find().toArray();
      res.send(result);
    });

    app.post('/purchase-bulk-return', async (req, res) => {
      const { stockAllocations: _ignore, ...item } = req.body;
      item.createdAt = new Date().toISOString();
      const plan = await buildBulkReturnPlan(item.items || []);
      if (!plan.ok) return res.status(400).send({ message: 'স্টকে পণ্য নেই!', shortages: plan.shortages });
      item.stockAllocations = plan.allocations;
      if (item.payment && Number(item.payment.amount) > 0) {
        item.status = 'Approved';
        item.approvedAt = item.createdAt;
      } else {
        item.status = 'Pending';
      }
      const result = await purchaseBulkReturnCollection.insertOne(item);
      res.send(result);
    });

    app.get('/purchase-bulk-return/:id', async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await purchaseBulkReturnCollection.findOne(query);
      res.send(result);
    });

    app.put('/purchase-bulk-return/:id', async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const { _id: _ignoreId, stockAllocations: _ignoreAlloc, ...updatedData } = req.body;
      updatedData.editedAt = new Date().toISOString();
      if (updatedData.payment && Number(updatedData.payment.amount) > 0) {
        updatedData.status = 'Approved';
        updatedData.approvedAt = new Date().toISOString();
      } else {
        delete updatedData.status;
        delete updatedData.approvedAt;
      }
      const plan = await buildBulkReturnPlan(updatedData.items || [], id);
      if (!plan.ok) return res.status(400).send({ message: 'স্টকে পণ্য নেই!', shortages: plan.shortages });
      updatedData.stockAllocations = plan.allocations;
      const result = await purchaseBulkReturnCollection.updateOne(query, { $set: updatedData });
      res.send(result);
    });

    app.patch('/purchase-bulk-return/:id/approve', async (req, res) => {
      try {
        const result = await purchaseBulkReturnCollection.updateOne(
          { _id: new ObjectId(req.params.id) },
          { $set: { status: 'Approved', approvedAt: new Date().toISOString() } }
        );
        res.send(result);
      } catch (err) {
        res.status(500).send({ message: 'Approve failed' });
      }
    });

    app.delete('/purchase-bulk-return/:id', async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await purchaseBulkReturnCollection.deleteOne(query);
      res.send(result);
    });

    // purchase related api

    // return entry te exact time (createdAt) boshiye dey, age thakle sheta e rakhe
    const stampReturns = (newList = [], oldList = [], withStatus = false) => {
      const oldMap = new Map((oldList || []).map((r) => [String(r.returnId), r]));
      const sig = (r) =>
        JSON.stringify([r.items, r.freeItems, r.totalReturnPcs, r.totalReturnFreeQty, r.totalReturnFreeItemsQty, r.totalReturnAmount]);
      const now = new Date().toISOString();
      return (newList || []).map((r) => {
        const old = oldMap.get(String(r.returnId));
        const out = { ...r, createdAt: r.createdAt || old?.createdAt || now };
        if (withStatus) {
          const hasPay = r.payment && Number(r.payment.amount) > 0;
          const wasApproved = old ? (old.status || 'Approved') === 'Approved' : false;
          const nowApproved = wasApproved || hasPay || r.status === 'Approved';
          out.status = nowApproved ? 'Approved' : 'Pending';
          if (nowApproved && !wasApproved) out.approvedAt = now;
          else if (old?.approvedAt) out.approvedAt = old.approvedAt;
        }
        if (old) {
          if (sig(old) !== sig(r)) out.editedAt = now;
          else if (old.editedAt) out.editedAt = old.editedAt;
        }
        return out;
      });
    };

    // stock-purchase related api
    app.get('/stock-purchase', async (req, res) => {
      const result = await stockPurchaseCollection.find().toArray();
      res.send(result);
    });

    app.get('/stock-purchase/:id', async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await stockPurchaseCollection.findOne(query);
      res.send(result);
    });

    // batch er sell price update (shudhu sellPrice)
    app.patch('/stock-purchase/:id/sell-price', async (req, res) => {
      try {
        const id = req.params.id;
        const price = Number(req.body.sellPrice);
        if (isNaN(price) || price < 0) {
          return res.status(400).send({ message: 'Invalid sell price' });
        }
        const rounded = Math.round(price * 100) / 100;
        const batch = await stockPurchaseCollection.findOne({ _id: new ObjectId(id) });
        if (!batch) return res.status(404).send({ message: 'Batch not found' });

        const result = await stockPurchaseCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { sellPrice: rounded } }
        );

        // Purchase er item er sellPrice o update, jate purchase edit korle ei price ashe
        if (batch.purchaseId) {
          if (batch.isFreeProduct) {
            await purchaseCollection.updateOne(
              { _id: new ObjectId(batch.purchaseId), 'freeItems.productId': batch.productId },
              { $set: { 'freeItems.$.sellPricePcs': rounded } }
            );
          } else {
            await purchaseCollection.updateOne(
              { _id: new ObjectId(batch.purchaseId), 'items.productId': batch.productId },
              { $set: { 'items.$.sellPrice': rounded } }
            );
          }
        }
        res.send(result);
      } catch (err) {
        res.status(500).send({ message: 'Update failed' });
      }
    });



    app.get('/purchase', async (req, res) => {
      const result = await purchaseCollection.find().toArray();
      res.send(result);
    });

    app.get('/purchase/:id', async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await purchaseCollection.findOne(query);
      res.send(result);
    });

    const recentKeys = new Set();
    app.post('/purchase', async (req, res) => {
      const item = req.body;
      if (toNum(item.paidAmount) > 0 && item.paymentMethod) {
        item.paymentDate = new Date().toISOString();
      }
      if (item.invoiceNo) {
        const key = `p:${tenantStore.getStore()?.dbName}:${item.invoiceNo}`;
        if (recentKeys.has(key)) return res.send({ acknowledged: true, duplicate: true });
        recentKeys.add(key);
        setTimeout(() => recentKeys.delete(key), 15000);
        res.on('finish', () => { if (res.statusCode >= 400) recentKeys.delete(key); });
      }
      const result = await purchaseCollection.insertOne(item);
      res.send(result);
    });

    app.delete('/purchase/:id', async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await purchaseCollection.deleteOne(query);

      // purchase delete hole tar stock-purchase batch gulo o delete hobe
      await stockPurchaseCollection.deleteMany({ purchaseId: id });
      await purchaseBulkReturnCollection.deleteMany({ purchaseId: id });
      res.send(result);
    });

    app.put('/purchase/:id', async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const { unsetFields: unsetFieldsRaw, returnOnly, stockCreated: _ignoreStockCreated, _id: _ignoreId, createdAt: _ignoreCreated, ...updatedData } = req.body;
      const unsetFields = cleanUnset(unsetFieldsRaw);

      const updateDoc = {
        $set: updatedData,
      };

      if (Array.isArray(unsetFields) && unsetFields.length > 0) {
        updateDoc.$unset = {};
        unsetFields.forEach((field) => {
          updateDoc.$unset[field] = "";
        });
      }

      // Already Received purchase edit hole purana batch muche notun kore banano hobe
      const oldPurchase = await purchaseCollection.findOne(query);
      if (Array.isArray(updatedData.returnHistory)) {
        updatedData.returnHistory = stampReturns(updatedData.returnHistory, oldPurchase?.returnHistory, true);
      }
      const wasReceived = oldPurchase?.receiveStatus === 'Received' || oldPurchase?.receiveStatus === 'Yes';

      // damageItems notun add/change hole exact time (damageAt) boshiye dey
      if (Array.isArray(updatedData.damageItems) && updatedData.damageItems.length > 0) {
        const dSig = (list) =>
          JSON.stringify(
            (list || []).map((i) => [String(i.productId), toNum(i.totalQty), toNum(i.freeQty), toNum(i.buyPrice)])
          );
        if (!oldPurchase?.damageAt || dSig(oldPurchase?.damageItems) !== dSig(updatedData.damageItems)) {
          updatedData.damageAt = new Date().toISOString();
        }
      }

      // Payment date / payment edit date track kora (Company Ledger er jonno)
      const hadPaid =
        oldPurchase &&
        oldPurchase.paidAmount !== undefined &&
        oldPurchase.paidAmount !== null &&
        oldPurchase.paidAmount !== '';
      const hasNewPaid =
        updatedData.paidAmount !== undefined &&
        updatedData.paidAmount !== null &&
        updatedData.paidAmount !== '';
      if (hasNewPaid && toNum(updatedData.paidAmount) > 0 && returnOnly !== true) {
        if (!hadPaid) {
          updatedData.paymentDate = new Date().toISOString();
        } else if (
          Number(oldPurchase.paidAmount) !== Number(updatedData.paidAmount) ||
          (oldPurchase.paymentMethod || '') !== (updatedData.paymentMethod || '') ||
          JSON.stringify(oldPurchase.paymentAccount || {}) !== JSON.stringify(updatedData.paymentAccount || {})
        ) {
          updatedData.paymentEditedAt = new Date().toISOString();
        }
      }
      if (Array.isArray(unsetFields) && unsetFields.includes('paidAmount')) {
        updateDoc.$unset.paymentDate = "";
        updateDoc.$unset.paymentEditedAt = "";
      }

      // Prothom bar receive hole, original ORDER data orderSnapshot e save thakbe (items = receive data)
      if (oldPurchase && !wasReceived && updatedData.receiveStatus === 'Received' && !oldPurchase.orderSnapshot) {
        updatedData.orderSnapshot = {
          items: oldPurchase.items || [],
          freeItems: oldPurchase.freeItems || [],
          subTotal: oldPurchase.subTotal ?? oldPurchase.grandTotal,
          productWiseDiscount: oldPurchase.productWiseDiscount,
          productWiseDiscountPercent: oldPurchase.productWiseDiscountPercent,
          overallDiscount: oldPurchase.overallDiscount,
          overallDiscountType: oldPurchase.overallDiscountType,
          overallDiscountValue: oldPurchase.overallDiscountValue,
          adjustment: oldPurchase.adjustment,
          payableAmount: oldPurchase.payableAmount,
        };
      }
      if (wasReceived && updatedData.receiveStatus === 'Received' && !Array.isArray(updatedData.returnHistory) && returnOnly !== true) {
        await stockPurchaseCollection.deleteMany({ purchaseId: id });
        await purchaseCollection.updateOne(query, { $unset: { stockCreated: "" } });
      }

      const result = await purchaseCollection.updateOne(query, updateDoc);


      // Receive hole purchase theke stock-purchase a batch toiri hobe (purchase thakbei)
      if (updatedData.receiveStatus === 'Received') {
        // atomic lock: ek shathe 2ta request ashleo shudhu ekta e pass korbe
        const claim = await purchaseCollection.updateOne(
          { _id: new ObjectId(id), stockCreated: { $ne: true } },
          { $set: { stockCreated: true } }
        );
        const alreadyInStock = await stockPurchaseCollection.findOne({ purchaseId: id });

        if (claim.modifiedCount === 1 && !alreadyInStock) {
          const purchase = await purchaseCollection.findOne(query);

          if (purchase) {
            const round2 = (n) => Math.round((Number(n) || 0) * 100) / 100;
            const round4 = (n) => Math.round((Number(n) || 0) * 10000) / 10000;

            const items = purchase.items || [];
            const freeItems = purchase.freeItems || [];
            const itemsSubtotalSum = items.reduce((s, it) => s + (Number(it.itemTotal ?? it.subtotal) || 0), 0);
            // Return Adjustment ও Damage Adjustment cost হিসাব থেকে বাদ (আবার যোগ করে আগের payable বের করা হলো)
            // Cost shudhu product subtotal - overall discount +/- adjustment theke hisab hobe
            // (Return / Damage / Previous Due / Get adjustment ar payable clamp er kono effect nai)
            const overallVal =
              purchase.overallDiscountValue !== undefined && purchase.overallDiscountValue !== null
                ? toNum(purchase.overallDiscountValue)
                : purchase.overallDiscountType === 'percent'
                  ? (itemsSubtotalSum * toNum(purchase.overallDiscount)) / 100
                  : toNum(purchase.overallDiscount);
            const adjAmt = toNum(purchase.adjustment?.amount);
            const payable = Math.max(
              itemsSubtotalSum - overallVal + (purchase.adjustment?.type === '-' ? -adjAmt : adjAmt),
              0
            );

            // Common info (protita batch a thakbe)
            const common = {
              purchaseId: id,
              invoiceNo: purchase.invoiceNo,
              company: purchase.company,
              purchaseDate: purchase.purchaseDate,
              receiveDate: purchase.receiveDate,
              createdAt: new Date(),
            };

            // Main product batch
            const mainBatches = items.map((it, idx) => {
              const paidQty = Number(it.totalPcs) || 0;
              const freeQty = Number(it.freeTotalQty) || 0;
              const stockQty = paidQty + freeQty;
              const buyPrice = Number(it.buyPrice) || 0;
              const grossAmount = round2(buyPrice * paidQty);
              const itemSubtotal = Number(it.itemTotal ?? it.subtotal) || 0;
              const itemDiscount = round2(grossAmount - itemSubtotal);

              // Overall discount + adjustment, subtotal onujayi bhag kore nilam
              const netCost = itemsSubtotalSum > 0
                ? round2((payable * itemSubtotal) / itemsSubtotalSum)
                : 0;

              return {
                ...common,
                batchNo: `${purchase.invoiceNo}-${idx + 1}`,
                isFreeProduct: false,
                parentMode: it.parentMode === true,
                subUnit: it.subUnit || '',
                pcsPerUnit: Number(it.pcsPerUnit) || 1,
                pcsPerSub: Number(it.pcsPerSub) || 0,
                subQty: Number(it.subQty) || 0,
                freeSubQty: Number(it.freeSubQty) || 0,
                productId: it.productId,
                productName: it.productName,
                unit: it.unit,
                unitQty: Number(it.unitQty) || 0,
                pcsQty: Number(it.pcsQty) || 0,
                buyPrice,                       // list buy price (per pcs)
                sellPrice: Number(it.sellPrice) || 0, // sell price (per pcs)
                grossAmount,                    // discount er age
                itemDiscount,                   // product wise discount
                netCost,                        // sob discount/adjustment er por total kotho porse
                paidQty,                        // kena qty
                freeQty,                        // free pawa qty
                freeUnitQty: Number(it.freeUnitQty) || 0,
                freePcsQty: Number(it.freePcsQty) || 0,
                stockQty,                       // ei batch a mot qty
                availableQty: stockQty,         // ekhon stock a koto ase
                costPerPcs: paidQty > 0 ? round4(netCost / paidQty) : 0, // per pcs cost (free qty hisabe dhora hoy na)
              };
            });

            // Others Free product batch (cost 0)
            const freeBatches = freeItems.map((it, idx) => {
              const qty = Number(it.totalQty) || 0;
              return {
                ...common,
                batchNo: `${purchase.invoiceNo}-F${idx + 1}`,
                isFreeProduct: true,
                parentMode: it.parentMode === true,
                subUnit: it.subUnit || '',
                pcsPerUnit: Number(it.pcsPerUnit) || 1,
                pcsPerSub: Number(it.pcsPerSub) || 0,
                subQty: Number(it.subQty) || 0,
                productId: it.productId,
                productName: it.productName,
                unit: it.unit,
                unitQty: Number(it.unitQty) || 0,
                pcsQty: Number(it.pcsQty) || 0,
                buyPrice: 0,
                sellPrice: Number(it.sellPricePcs) || 0,
                grossAmount: 0,
                itemDiscount: 0,
                netCost: 0,
                paidQty: 0,
                freeQty: qty,
                stockQty: qty,
                availableQty: qty,
                costPerPcs: 0,
              };
            });

            const allBatches = [...mainBatches, ...freeBatches];
            if (allBatches.length > 0) {
              await stockPurchaseCollection.insertMany(allBatches);
            }
          }
        }
      }

      // Purchase theke return product thakle purchase-bulk-return e sync hobe
      if (updatedData.receiveStatus === 'Received') {
        const p = await purchaseCollection.findOne(query);
        const retItems = (p?.returnItems || []).filter(
          (it) => toNum(it.totalQty) > 0 || toNum(it.freeQty) > 0
        );
        if (retItems.length > 0) {
          const bulkItems = retItems.map((it) => ({
            productId: it.productId,
            productName: it.productName,
            buyPrice: toNum(it.buyPrice),
            sellPrice: 0,
            unit: it.unit,
            parentMode: it.parentMode === true,
            subUnit: it.subUnit || '',
            pcsPerUnit: toNum(it.pcsPerUnit) || 1,
            pcsPerSub: toNum(it.pcsPerSub),
            unitQty: toNum(it.unitQty),
            subQty: toNum(it.subQty),
            pcsQty: toNum(it.pcsQty),
            totalPcs: toNum(it.totalQty),
            freeUnitQty: toNum(it.freeUnitQty),
            freeSubQty: toNum(it.freeSubQty),
            freePcsQty: toNum(it.freePcsQty),
            freeTotalQty: toNum(it.freeQty),
            itemTotal: toNum(it.itemTotal ?? it.subtotal),
          }));
          const total = Math.round(bulkItems.reduce((s, i) => s + i.itemTotal, 0) * 100) / 100;
          const existingBulk = await purchaseBulkReturnCollection.findOne({ purchaseId: id });
          const bulkPlan = await buildBulkReturnPlan(bulkItems, existingBulk?._id || null);
          await purchaseBulkReturnCollection.updateOne(
            { purchaseId: id },
            {
              $set: {
                fromPurchase: true,
                purchaseId: id,
                invoiceNo: p.invoiceNo,
                company: p.company,
                phone: p.phone,
                address: p.address,
                category: p.category,
                returnDate: p.receiveDate || p.purchaseDate,
                items: bulkItems,
                returnAmount: total,
                note: p.orderNote || '',
                stockAllocations: bulkPlan.ok ? bulkPlan.allocations : [],
                ...(existingBulk && JSON.stringify(existingBulk.items || []) !== JSON.stringify(bulkItems)
                  ? { editedAt: new Date().toISOString() }
                  : {}),
              },
              $setOnInsert: { createdAt: new Date().toISOString() },
            },
            { upsert: true }
          );
        } else {
          await purchaseBulkReturnCollection.deleteOne({ purchaseId: id });
        }
      }

      res.send(result);
    });



    // ===== Sales stock helpers =====
    const toNum = (v) => Number(v) || 0;

    // purchase return বাদ দিয়ে batch এর return qty
    const getBatchReturned = (batch, purchase) => {
      let ret = 0;
      (purchase?.returnHistory || []).forEach((r) => {
        if (batch.isFreeProduct) {
          (r.freeItems || []).forEach((it) => {
            if (it.productId === batch.productId) ret += toNum(it.returnTotalQty);
          });
        } else {
          (r.items || []).forEach((it) => {
            if (it.productId === batch.productId) {
              ret += toNum(it.returnTotalQty) + toNum(it.returnFreeTotalQty ?? it.returnFreeQty);
            }
          });
        }
      });
      return ret;
    };

    // batch er date (receiveDate -> purchaseDate -> createdAt) theke time ber kora
    const batchTime = (b) => {
      const s = String(b.receiveDate || b.purchaseDate || '').split(',')[0].trim();
      let t = NaN;
      if (s.includes('/')) {
        const [d, m, y] = s.split('/').map(Number);
        t = new Date(y, m - 1, d).getTime();
      } else if (s) {
        t = new Date(s).getTime();
      }
      return isNaN(t) ? new Date(b.createdAt).getTime() : t;
    };

    // stock check + FIFO (purane batch age) allocation
    // purchase return (paid / free alada)
    const getBatchReturnedSplit = (batch, purchase) => {
      let paid = 0;
      let free = 0;
      (purchase?.returnHistory || []).forEach((r) => {
        if (batch.isFreeProduct) {
          (r.freeItems || []).forEach((it) => {
            if (it.productId === batch.productId) free += toNum(it.returnTotalQty);
          });
        } else {
          (r.items || []).forEach((it) => {
            if (it.productId === batch.productId) {
              paid += toNum(it.returnTotalQty);
              free += toNum(it.returnFreeTotalQty ?? it.returnFreeQty);
            }
          });
        }
      });
      return { paid, free };
    };

    // Main -> shudhu main(paid) stock theke, Free/Others -> shudhu free stock theke (FIFO)
    const buildStockPlan = async (items = [], freeItems = [], excludeSaleId = null, opts = {}) => {
      const allowBorrow = opts.allowBorrow === true;
      const borrowFeatures = await featureCollection
        .find({ key: { $in: ['mainFromFreeStock', 'freeFromMainStock'] } })
        .toArray();
      const allowMainFromFree = borrowFeatures.some((f) => f.key === 'mainFromFreeStock' && f.enabled === true);
      const allowFreeFromMain = borrowFeatures.some((f) => f.key === 'freeFromMainStock' && f.enabled === true);
      const need = new Map();
      const add = (pid, name, main, free, others) => {
        const total = main + free + others;
        if (!pid || total <= 0) return;
        const key = String(pid);
        if (!need.has(key)) need.set(key, { productName: name, qty: 0, main: 0, free: 0, others: 0 });
        const n = need.get(key);
        n.main += main;
        n.free += free;
        n.others += others;
        n.qty += total;
      };
      items.forEach((it) => add(it.productId, it.productName, toNum(it.totalPcs), toNum(it.freeQty), 0));
      freeItems.forEach((it) => add(it.productId, it.productName, 0, 0, toNum(it.totalQty)));

      if (need.size === 0) return { ok: true, shortages: [], borrows: [], allocations: [] };

      const batches = await stockPurchaseCollection
        .find({
          $or: [
            { productId: { $in: [...need.keys()] } },
            { productName: { $in: [...need.values()].map((n) => n.productName) } },
          ],
        })
        .toArray();

      batches.sort((a, b) => {
        const diff = batchTime(a) - batchTime(b);
        if (diff !== 0) return diff;
        return new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime();
      });

      const purchaseIds = [...new Set(batches.map((b) => b.purchaseId).filter(Boolean))]
        .map((i) => { try { return new ObjectId(i); } catch (e) { return null; } })
        .filter(Boolean);
      const purchases = purchaseIds.length
        ? await purchaseCollection.find({ _id: { $in: purchaseIds } }).toArray()
        : [];
      const pMap = new Map(purchases.map((p) => [String(p._id), p]));

      const poolOf = (a) => a.pool || ((a.kind || 'main') === 'main' ? 'paid' : 'free');

      const usedSales = await salesCollection
        .find({ 'stockAllocations.0': { $exists: true } })
        .toArray();
      const used = new Map();
      usedSales.forEach((s) => {
        if (excludeSaleId && String(s._id) === String(excludeSaleId)) return;
        (s.stockAllocations || []).forEach((a) => {
          const k = String(a.batchId);
          const cur = used.get(k) || { paid: 0, free: 0 };
          cur[poolOf(a)] += Math.max(toNum(a.qty) - toNum(a.returned), 0);
          used.set(k, cur);
        });
      });

      const usedBulkRets = await purchaseBulkReturnCollection
        .find({ 'stockAllocations.0': { $exists: true } })
        .toArray();
      usedBulkRets.forEach((r) => {
        (r.stockAllocations || []).forEach((a) => {
          const k = String(a.batchId);
          const cur = used.get(k) || { paid: 0, free: 0 };
          cur[a.pool === 'paid' ? 'paid' : 'free'] += toNum(a.qty);
          used.set(k, cur);
        });
      });
      await applySalesBulkReturnsToUsed(used);
      await applyDamageToUsed(used);
      await applyAdjustmentsToUsed(used);

      const pools = batches.map((b) => {
        const ret = getBatchReturnedSplit(b, pMap.get(String(b.purchaseId)));
        const u = used.get(String(b._id)) || { paid: 0, free: 0 };
        if (b.isFreeProduct) {
          return { b, paid: 0, free: Math.max(toNum(b.freeQty) - ret.free - (u.paid + u.free), 0) };
        }
        return {
          b,
          paid: Math.max(toNum(b.paidQty) - ret.paid - u.paid, 0),
          free: Math.max(toNum(b.freeQty) - ret.free - u.free, 0),
        };
      });

      const shortages = [];
      const borrows = [];
      const allocations = [];

      const takeFrom = (list, poolKey, kind, pid, want) => {
        let remaining = want;
        for (const x of list) {
          if (remaining <= 0) break;
          const t = Math.min(x[poolKey], remaining);
          if (t <= 0) continue;
          x[poolKey] -= t;
          allocations.push({
            batchId: String(x.b._id),
            batchNo: x.b.batchNo,
            productId: pid,
            kind,
            pool: poolKey,
            qty: t,
            returned: 0,
          });
          remaining -= t;
        }
        return remaining;
      };

      for (const [pid, n] of need) {
        const list = pools.filter(
          (x) => String(x.b.productId) === pid || x.b.productName === n.productName
        );
        const totalPaid = list.reduce((s, x) => s + x.paid, 0);
        const totalFree = list.reduce((s, x) => s + x.free, 0);

        const needMain = n.main;
        const needFree = n.free + n.others;
        const mainShort = Math.max(needMain - totalPaid, 0);
        const freeShort = Math.max(needFree - totalFree, 0);
        const surplusPaid = Math.max(totalPaid - needMain, 0);
        const surplusFree = Math.max(totalFree - needFree, 0);

        let mainFromFree = 0;
        let freeFromMain = 0;
        let hardShort = false;

        if (mainShort > 0) {
          if (allowMainFromFree && surplusFree >= mainShort) mainFromFree = mainShort;
          else {
            shortages.push({ productName: `${n.productName} (Main)`, need: needMain, available: totalPaid });
            hardShort = true;
          }
        }
        if (freeShort > 0) {
          if (allowFreeFromMain && surplusPaid >= freeShort) freeFromMain = freeShort;
          else {
            shortages.push({ productName: `${n.productName} (Free)`, need: needFree, available: totalFree });
            hardShort = true;
          }
        }
        if (hardShort) continue;

        if ((mainFromFree > 0 || freeFromMain > 0) && !allowBorrow) {
          borrows.push(
            mainFromFree > 0
              ? { productName: n.productName, direction: 'free_to_main', need: needMain, have: totalPaid, borrowQty: mainFromFree, otherAvailable: totalFree, otherNeed: needFree }
              : { productName: n.productName, direction: 'main_to_free', need: needFree, have: totalFree, borrowQty: freeFromMain, otherAvailable: totalPaid, otherNeed: needMain }
          );
          continue;
        }

        takeFrom(list, 'paid', 'main', pid, needMain - mainFromFree);
        const ownFreeTotal = needFree - freeFromMain;
        const ownFree = Math.min(n.free, ownFreeTotal);
        const ownOthers = ownFreeTotal - ownFree;
        takeFrom(list, 'free', 'free', pid, ownFree);
        takeFrom(list, 'free', 'others', pid, ownOthers);

        if (mainFromFree > 0) takeFrom(list, 'free', 'main', pid, mainFromFree);
        if (freeFromMain > 0) {
          takeFrom(list, 'paid', 'free', pid, n.free - ownFree);
          takeFrom(list, 'paid', 'others', pid, n.others - ownOthers);
        }
      }

      return { ok: shortages.length === 0 && borrows.length === 0, shortages, borrows, allocations };
    };

    // (purano buildStockPlan, ar use hocche na)
    const buildStockPlanUnused = async (items = [], freeItems = [], excludeSaleId = null) => {
      const need = new Map();
      const add = (pid, name, main, free, others) => {
        const total = main + free + others;
        if (!pid || total <= 0) return;
        const key = String(pid);
        if (!need.has(key)) need.set(key, { productName: name, qty: 0, main: 0, free: 0, others: 0 });
        const n = need.get(key);
        n.main += main;
        n.free += free;
        n.others += others;
        n.qty += total;
      };
      items.forEach((it) => add(it.productId, it.productName, toNum(it.totalPcs), toNum(it.freeQty), 0));
      freeItems.forEach((it) => add(it.productId, it.productName, 0, 0, toNum(it.totalQty)));

      if (need.size === 0) return { ok: true, shortages: [], allocations: [] };

      const batches = await stockPurchaseCollection
        .find({
          $or: [
            { productId: { $in: [...need.keys()] } },
            { productName: { $in: [...need.values()].map((n) => n.productName) } },
          ],
        })
        .toArray();

      batches.sort((a, b) => {
        const diff = batchTime(a) - batchTime(b);
        if (diff !== 0) return diff;
        return new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime();
      });

      const purchaseIds = [...new Set(batches.map((b) => b.purchaseId).filter(Boolean))]
        .map((i) => { try { return new ObjectId(i); } catch (e) { return null; } })
        .filter(Boolean);
      const purchases = purchaseIds.length
        ? await purchaseCollection.find({ _id: { $in: purchaseIds } }).toArray()
        : [];
      const pMap = new Map(purchases.map((p) => [String(p._id), p]));

      // ager sales theke batch wise main/free/others koto gese
      const usedSales = await salesCollection
        .find({ 'stockAllocations.0': { $exists: true } })
        .toArray();
      const used = new Map();
      usedSales.forEach((s) => {
        if (excludeSaleId && String(s._id) === String(excludeSaleId)) return;
        (s.stockAllocations || []).forEach((a) => {
          const k = String(a.batchId);
          const cur = used.get(k) || { main: 0, free: 0, others: 0 };
          const kind = a.kind || 'main';
          cur[kind] = (cur[kind] || 0) + Math.max(toNum(a.qty) - toNum(a.returned), 0);
          used.set(k, cur);
        });
      });

      // protita batch er alada paid pool & free pool
      const pools = batches.map((b) => {
        const ret = getBatchReturnedSplit(b, pMap.get(String(b.purchaseId)));
        const u = used.get(String(b._id)) || { main: 0, free: 0, others: 0 };
        if (b.isFreeProduct) {
          return {
            b,
            paid: 0,
            free: Math.max(toNum(b.freeQty) - ret.free - (u.main + u.free + u.others), 0),
          };
        }
        return {
          b,
          paid: Math.max(toNum(b.paidQty) - ret.paid - u.main, 0),
          free: Math.max(toNum(b.freeQty) - ret.free - u.free - u.others, 0),
        };
      });

      const shortages = [];
      const allocations = [];

      for (const [pid, n] of need) {
        const list = pools.filter(
          (x) => String(x.b.productId) === pid || x.b.productName === n.productName
        );
        const totalPaid = list.reduce((s, x) => s + x.paid, 0);
        const totalFree = list.reduce((s, x) => s + x.free, 0);

        let short = false;
        if (totalPaid < n.main) {
          shortages.push({ productName: `${n.productName} (Main)`, need: n.main, available: totalPaid });
          short = true;
        }
        if (totalFree < n.free + n.others) {
          shortages.push({ productName: `${n.productName} (Free)`, need: n.free + n.others, available: totalFree });
          short = true;
        }
        if (short) continue;

        for (const [kind, want] of [['main', n.main], ['free', n.free], ['others', n.others]]) {
          let remaining = want;
          const poolKey = kind === 'main' ? 'paid' : 'free';
          for (const x of list) {
            if (remaining <= 0) break;
            const take = Math.min(x[poolKey], remaining);
            if (take <= 0) continue;
            x[poolKey] -= take;
            allocations.push({ batchId: String(x.b._id), batchNo: x.b.batchNo, productId: pid, kind, qty: take, returned: 0 });
            remaining -= take;
          }
        }
      }

      return { ok: shortages.length === 0, shortages, allocations };
    };

    // (purano version, ar use hocche na)
    const buildStockPlanOld = async (items = [], freeItems = []) => {
      const need = new Map();
      const add = (pid, name, main, free, others) => {
        const total = main + free + others;
        if (!pid || total <= 0) return;
        const key = String(pid);
        if (!need.has(key)) need.set(key, { productName: name, qty: 0, main: 0, free: 0, others: 0 });
        const n = need.get(key);
        n.main += main;
        n.free += free;
        n.others += others;
        n.qty += total;
      };
      items.forEach((it) => add(it.productId, it.productName, toNum(it.totalPcs), toNum(it.freeQty), 0));
      freeItems.forEach((it) => add(it.productId, it.productName, 0, 0, toNum(it.totalQty)));

      if (need.size === 0) return { ok: true, shortages: [], allocations: [] };

      const batches = await stockPurchaseCollection
        .find({
          $or: [
            { productId: { $in: [...need.keys()] } },
            { productName: { $in: [...need.values()].map((n) => n.productName) } },
          ],
        })
        .toArray();

      // FIFO: age je purchase/receive hoyeche sheta age use hobe
      batches.sort((a, b) => {
        const diff = batchTime(a) - batchTime(b);
        if (diff !== 0) return diff;
        return new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime();
      });

      const purchaseIds = [...new Set(batches.map((b) => b.purchaseId).filter(Boolean))]
        .map((i) => { try { return new ObjectId(i); } catch (e) { return null; } })
        .filter(Boolean);
      const purchases = purchaseIds.length
        ? await purchaseCollection.find({ _id: { $in: purchaseIds } }).toArray()
        : [];
      const pMap = new Map(purchases.map((p) => [String(p._id), p]));

      const shortages = [];
      const allocations = [];

      for (const [pid, n] of need) {
        const list = batches
          .filter((b) => String(b.productId) === pid || b.productName === n.productName)
          .map((b) => ({
            b,
            avail: Math.max(toNum(b.availableQty) - getBatchReturned(b, pMap.get(String(b.purchaseId))), 0),
          }));
        const totalAvail = list.reduce((s, x) => s + x.avail, 0);

        if (totalAvail < n.qty) {
          shortages.push({ productName: n.productName, need: n.qty, available: totalAvail });
          continue;
        }

        for (const [kind, want] of [['main', n.main], ['free', n.free], ['others', n.others]]) {
          let remaining = want;
          for (const x of list) {
            if (remaining <= 0) break;
            const take = Math.min(x.avail, remaining);
            if (take <= 0) continue;
            x.avail -= take;
            allocations.push({ batchId: String(x.b._id), batchNo: x.b.batchNo, productId: pid, kind, qty: take, returned: 0 });
            remaining -= take;
          }
        }
      }

      return { ok: shortages.length === 0, shortages, allocations };
    };

    const applyAllocations = async (allocations = []) => {
      for (const a of allocations) {
        await stockPurchaseCollection.updateOne(
          { _id: new ObjectId(a.batchId) },
          { $inc: { availableQty: -toNum(a.qty) } }
        );
      }
    };

    // sales return history theke product wise total return qty
    const sumReturns = (history = []) => {
      const map = new Map();
      const add = (pid, kind, qty) => {
        const k = `${pid}|${kind}`;
        map.set(k, (map.get(k) || 0) + qty);
      };
      (history || []).forEach((r) => {
        (r.items || []).forEach((it) => {
          add(it.productId, 'main', toNum(it.returnTotalQty));
          add(it.productId, 'free', toNum(it.returnFreeTotalQty ?? it.returnFreeQty));
        });
        (r.freeItems || []).forEach((it) => add(it.productId, 'others', toNum(it.returnTotalQty)));
      });
      return map;
    };

    // customer return korle stock e ferot, return edit/delete korle abar kome
    const adjustReturnStock = async (existing, newHistory) => {
      const allocs = (existing.stockAllocations || []).map((a) => ({ ...a, returned: toNum(a.returned) }));
      const oldMap = sumReturns(existing.returnHistory);
      const newMap = sumReturns(newHistory);
      const pids = new Set([...oldMap.keys(), ...newMap.keys()]);

      for (const key of pids) {
        const sep = key.lastIndexOf('|');
        const pid = key.slice(0, sep);
        const kind = key.slice(sep + 1);
        let delta = (newMap.get(key) || 0) - (oldMap.get(key) || 0);
        const list = allocs
          .filter((a) => String(a.productId) === pid && (a.kind || 'main') === kind)
          .reverse();

        if (delta > 0) {
          for (const a of list) {
            if (delta <= 0) break;
            const take = Math.min(toNum(a.qty) - a.returned, delta);
            if (take <= 0) continue;
            a.returned += take;
            delta -= take;
            await stockPurchaseCollection.updateOne({ _id: new ObjectId(a.batchId) }, { $inc: { availableQty: take } });
          }
        } else if (delta < 0) {
          delta = -delta;
          for (const a of list) {
            if (delta <= 0) break;
            const take = Math.min(a.returned, delta);
            if (take <= 0) continue;
            a.returned -= take;
            delta -= take;
            await stockPurchaseCollection.updateOne({ _id: new ObjectId(a.batchId) }, { $inc: { availableQty: -take } });
          }
        }
      }
      return allocs;
    };

    const stockErrorBody = (shortages) => ({
      message: 'স্টকে পণ্য নেই!',
      shortages,
    });

    const sendPlanError = (res, plan) => {
      if (plan.shortages.length > 0) return res.status(400).send(stockErrorBody(plan.shortages));
      return res.status(409).send({
        needsConfirm: true,
        message: 'স্টক সমন্বয় করতে নিশ্চিত করুন',
        borrows: plan.borrows,
      });
    };

    // OrderAdd er bulk return (returnItems) ke sales-bulk-return e sync kora
    const syncSalesBulkFromOrder = async (id) => {
      const s = await salesCollection.findOne({ _id: new ObjectId(id) });
      if (!s || s.status !== 'Delivered') return;
      const retItems = (s.returnItems || []).filter(
        (it) => toNum(it.totalQty) > 0 || toNum(it.freeQty) > 0
      );
      if (retItems.length === 0) {
        await salesBulkReturnCollection.deleteOne({ saleId: id });
        return;
      }
      const total = Math.round(retItems.reduce((a, i) => a + toNum(i.itemTotal ?? i.subtotal), 0) * 100) / 100;
      const existingBulk = await salesBulkReturnCollection.findOne({ saleId: id });
      const bulkPlan = await buildSalesBulkReturnPlan(retItems, existingBulk?._id || null);
      await salesBulkReturnCollection.updateOne(
        { saleId: id },
        {
          $set: {
            fromSales: true,
            saleId: id,
            invoiceNo: s.invoiceNo || s.orderNo,
            customerId: s.customerId,
            customer: s.customer,
            phone: s.phone,
            address: s.address,
            returnDate: s.deliveryDate || s.orderDate,
            items: retItems,
            returnAmount: total,
            note: s.orderNote || '',
            ...(existingBulk && JSON.stringify(existingBulk.items || []) !== JSON.stringify(retItems)
              ? { editedAt: new Date().toISOString() }
              : {}),
            stockAllocations: bulkPlan.allocations,
          },
          $setOnInsert: { createdAt: new Date().toISOString() },
        },
        { upsert: true }
      );
    };

    // sales related api

    app.get('/sales', async (req, res) => {
      const result = await salesCollection.find().toArray();
      res.send(result);
    });

    app.get('/sales/:id', async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await salesCollection.findOne(query);
      res.send(result);
    });

    app.post('/sales', async (req, res) => {
      const { stockBorrowConfirmed, stockAllocations: _ignoreAlloc, _id: _ignoreId, ...item } = req.body;
      if (item.orderNo) {
        const key = `s:${tenantStore.getStore()?.dbName}:${item.orderNo}`;
        if (recentKeys.has(key)) return res.send({ acknowledged: true, duplicate: true });
        recentKeys.add(key);
        setTimeout(() => recentKeys.delete(key), 10000);
        res.on('finish', () => { if (res.statusCode >= 400) recentKeys.delete(key); });
      }
      item.createdAt = new Date().toISOString();
      if (item.status === 'Delivered') item.deliveredAt = item.createdAt;
      if ((item.damageItems || []).length > 0) item.damageAt = item.createdAt;
      let allocations = [];
      if (item.status === 'Delivered') {
        const plan = await buildStockPlan(item.items || [], item.freeItems || [], null, {
          allowBorrow: stockBorrowConfirmed === true,
        });
        if (!plan.ok) return sendPlanError(res, plan);
        allocations = plan.allocations;
        item.stockAllocations = allocations;
      }
      const result = await salesCollection.insertOne(item);
      if (allocations.length > 0) await applyAllocations(allocations);
      if (result.insertedId) await syncSalesBulkFromOrder(String(result.insertedId));
      res.send(result);
    });

    app.delete('/sales/:id', async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const existingSale = await salesCollection.findOne(query);
      const result = await salesCollection.deleteOne(query);
      await salesBulkReturnCollection.deleteMany({ saleId: id });

      // delivered order delete hole stock ferot jabe
      for (const a of existingSale?.stockAllocations || []) {
        const back = toNum(a.qty) - toNum(a.returned);
        if (back > 0) {
          await stockPurchaseCollection.updateOne(
            { _id: new ObjectId(a.batchId) },
            { $inc: { availableQty: back } }
          );
        }
      }
      res.send(result);
    });

    app.put('/sales/:id', async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const { unsetFields: unsetFieldsRaw, stockBorrowConfirmed, stockAllocations: _ignoreAlloc, _id: _ignoreId, createdAt: _ignoreCreated, ...updatedData } = req.body;
      const unsetFields = cleanUnset(unsetFieldsRaw);
      const allowBorrow = stockBorrowConfirmed === true;

      const updateDoc = {
        $set: updatedData,
      };

      if (Array.isArray(unsetFields) && unsetFields.length > 0) {
        updateDoc.$unset = {};
        unsetFields.forEach((field) => {
          updateDoc.$unset[field] = "";
        });
      }

      const existingSale = await salesCollection.findOne(query);
      let allocationsToApply = null;

      // damageItems notun add/change hole time track kora (Sales Return Report er jonno)
      if (existingSale && Array.isArray(updatedData.damageItems) && updatedData.damageItems.length > 0) {
        const dSig = (list) =>
          JSON.stringify(
            (list || []).map((i) => [String(i.productId), toNum(i.totalQty), toNum(i.freeQty), toNum(i.sellPricePcs)])
          );
        if (!existingSale.damageAt || (existingSale.damageItems || []).length === 0) {
          updatedData.damageAt = new Date().toISOString();
        } else if (dSig(existingSale.damageItems) !== dSig(updatedData.damageItems)) {
          updatedData.damageEditedAt = new Date().toISOString();
        }
      }

      if (existingSale && updatedData.status === 'Delivered' && existingSale.status !== 'Delivered') {
        updatedData.deliveredAt = new Date().toISOString();
        // Prothom bar delivery hole original ORDER data orderSnapshot e save thakbe
        if (!existingSale.orderSnapshot) {
          updatedData.orderSnapshot = {
            items: existingSale.items || [],
            freeItems: existingSale.freeItems || [],
            damageItems: existingSale.damageItems || [],
            returnItems: existingSale.returnItems || [],
            subTotal: existingSale.subTotal ?? existingSale.grandTotal,
            productWiseDiscount: existingSale.productWiseDiscount,
            productWiseDiscountPercent: existingSale.productWiseDiscountPercent,
            overallDiscount: existingSale.overallDiscount,
            overallDiscountType: existingSale.overallDiscountType,
            overallDiscountValue: existingSale.overallDiscountValue,
            adjustment: existingSale.adjustment,
            damageAdjustmentAmount: existingSale.damageAdjustmentAmount,
            returnAdjustmentAmount: existingSale.returnAdjustmentAmount,
            payableAmount: existingSale.payableAmount,
          };
        }
      }
      if (existingSale && Array.isArray(updatedData.returnHistory)) {
        updatedData.returnHistory = stampReturns(updatedData.returnHistory, existingSale.returnHistory);
      }

      if (existingSale && updatedData.status === 'Delivered' && existingSale.status !== 'Delivered') {
        // Delivery: age stock check
        const plan = await buildStockPlan(
          updatedData.items ?? existingSale.items ?? [],
          updatedData.freeItems ?? existingSale.freeItems ?? [],
          id,
          { allowBorrow }
        );
        if (!plan.ok) return sendPlanError(res, plan);
        allocationsToApply = plan.allocations;
        updatedData.stockAllocations = plan.allocations;
      } else if (
        existingSale &&
        Array.isArray(updatedData.returnHistory) &&
        (existingSale.stockAllocations || []).length > 0
      ) {
        // Sales return: stock adjust
        updatedData.stockAllocations = await adjustReturnStock(existingSale, updatedData.returnHistory);
      } else if (
        existingSale &&
        existingSale.status === 'Delivered' &&
        Array.isArray(updatedData.items) &&
        !Array.isArray(updatedData.returnHistory) &&
        (existingSale.returnHistory || []).length === 0
      ) {
        // Delivered order edit: purano stock ferot diye notun kore allocate
        const restoreOld = async (sign) => {
          for (const a of existingSale.stockAllocations || []) {
            const back = toNum(a.qty) - toNum(a.returned);
            if (back > 0) {
              await stockPurchaseCollection.updateOne(
                { _id: new ObjectId(a.batchId) },
                { $inc: { availableQty: sign * back } }
              );
            }
          }
        };
        await restoreOld(1);
        const plan = await buildStockPlan(
          updatedData.items,
          updatedData.freeItems ?? existingSale.freeItems ?? [],
          id,
          { allowBorrow }
        );
        if (!plan.ok) {
          await restoreOld(-1);
          return sendPlanError(res, plan);
        }
        allocationsToApply = plan.allocations;
        updatedData.stockAllocations = plan.allocations;
      }

      const result = await salesCollection.updateOne(query, updateDoc);
      if (allocationsToApply) await applyAllocations(allocationsToApply);
      await syncSalesBulkFromOrder(id);
      res.send(result);
    });



    // কোনো route এ error হলে সুন্দর response (request ঝুলে থাকবে না)
    app.use((err, req, res, next) => {
      console.error('Route error:', req.method, req.path, err?.message);
      if (res.headersSent) return next(err);
      const msg = String(err?.message || '');
      if (msg === 'TENANT_NOT_SET') return res.status(401).send({ message: 'unauthorized access' });
      if (/^BSON/.test(String(err?.name)) || /ObjectId|24 character hex/i.test(msg)) {
        return res.status(400).send({ message: 'Invalid ID' });
      }
      if (err?.type === 'entity.parse.failed') return res.status(400).send({ message: 'Invalid JSON' });
      if (err?.type === 'entity.too.large') return res.status(413).send({ message: 'Data too large' });
      res.status(500).send({ message: 'Server error' });
    });

    await client.db("admin").command({ ping: 1 });
    console.log("Pinged your deployment. You successfully connected to MongoDB!");
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);


app.get('/', (req, res) => {
  res.send('Squirrel Peace is running')
})

// keep-alive route
app.get('/ping', (req, res) => {
  res.send('pong');
});


app.listen(port, () => {
  console.log(`Bashay Bazar is sitting on port ${port}`);
})