const dns = require('dns');
dns.setServers(['8.8.8.8', '8.8.4.4']);
const express = require('express');
const app = express();
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { SitemapStream } = require("sitemap");
const { createGzip } = require("zlib");
const slugify = require('slugify');
const { MongoClient, ServerApiVersion, ObjectId, } = require('mongodb');
require('dotenv').config();
const port = process.env.PORT || 5000;

// middleware
app.use(cors());
app.use(express.json());

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.3wtib.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

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

    const usersCollection = client.db("squirrelDb").collection("users");
    const contactCollection = client.db("squirrelDb").collection("contact");
    const productsCollection = client.db("squirrelDb").collection("products");
    const productCollection = client.db("squirrelDb").collection("product");
    const unitCollection = client.db("squirrelDb").collection("unit");
    const categoryCollection = client.db("squirrelDb").collection("category");
    const itemCollection = client.db("squirrelDb").collection("item");
    const trashCollection = client.db("squirrelDb").collection("trash");
    const shopCollection = client.db("squirrelDb").collection("shop");
    const companyCollection = client.db("squirrelDb").collection("company");
    const customerCollection = client.db("squirrelDb").collection("customer");
    const routeCollection = client.db("squirrelDb").collection("route");
    const clientCollection = client.db("squirrelDb").collection("client");
    const userCollection = client.db("squirrelDb").collection("user");
    const userRoleCollection = client.db("squirrelDb").collection("userRole");
    const investmentCollection = client.db("squirrelDb").collection("investment");
    const adjustmentCollection = client.db("squirrelDb").collection("adjustment");
    const headsCollection = client.db("squirrelDb").collection("heads");
    const incomeCollection = client.db("squirrelDb").collection("income");
    const expenseCollection = client.db("squirrelDb").collection("expense");
    const routeExpenseCollection = client.db("squirrelDb").collection("routeExpense");
    const transferCollection = client.db("squirrelDb").collection("transfer");
    const purchaseCollection = client.db("squirrelDb").collection("purchase");
    const stockPurchaseCollection = client.db("squirrelDb").collection("stock-purchase");
    const salesCollection = client.db("squirrelDb").collection("sales");
    const featureCollection = client.db("squirrelDb").collection("feature");


    // jwt related api

    app.post('/jwt', async (req, res) => {
      const user = req.body;
      const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '1h' });
      res.send({ token });
    })

    // middlewares 
    const verifyToken = (req, res, next) => {
      // console.log('inside verify token', req.headers.authorization);
      if (!req.headers.authorization) {
        return res.status(401).send({ message: 'unauthorized access' });
      }
      const token = req.headers.authorization.split(' ')[1];
      jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
        if (err) {
          return res.status(401).send({ message: 'unauthorized access' })
        }
        req.decoded = decoded;
        next();
      })
    }

    // use verify admin after verifyToken
    const verifyAdmin = async (req, res, next) => {
      const email = req.decoded.email;
      const query = { email: email };
      const user = await usersCollection.findOne(query);
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

    app.get('/users', async (req, res) => {
      const result = await usersCollection.find().toArray();
      res.send(result);
    });

    app.get('/users/admin/:email', verifyToken, async (req, res) => {
      const email = req.params.email;

      if (email !== req.decoded.email) {
        return res.status(403).send({ message: 'forbidden access' })
      }

      const query = { email: email };
      const user = await usersCollection.findOne(query);
      let admin = false;
      if (user) {
        admin = user?.role === 'admin';
      }
      res.send({ admin });
    })

    app.post('/users', async (req, res) => {
      const user = req.body;
      // checking user already created or not
      const query = { email: user.email }
      const existingUser = await usersCollection.findOne(query);
      if (existingUser) {
        return res.send({ message: 'user already exists', insertedId: null })
      }
      const result = await usersCollection.insertOne(user);
      res.send(result);
    });

    app.delete('/users/:id', async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await usersCollection.deleteOne(query);
      res.send(result);
    });

    app.patch('/users/admin/:id', async (req, res) => {
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

    app.patch('/users/remove-admin/:id', async (req, res) => {
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

    app.get('/client', async (req, res) => {
      const clients = await clientCollection.find().toArray();
      // পুরনো ডাটাগুলোতে login ফিল্ড না থাকলে ডিফল্টভাবে 'no' সেট করে পাঠানো
      const result = clients.map(client => ({
        ...client,
        login: client.login || 'no'
      }));
      res.send(result);
    });

    // নতুন ক্লায়েন্ট যোগ করার রাউট
    app.post('/client', async (req, res) => {
      const newClient = {
        ...req.body,
        login: req.body.login || 'no'
      };

      // ফোন অথবা ইমেইল অলরেডি আছে কিনা চেক করা
      const existingClient = await clientCollection.findOne({
        $or: [{ phone: newClient.phone }, { email: newClient.email }]
      });

      if (existingClient) {
        let field = existingClient.phone === newClient.phone ? 'phone' : 'email';
        return res.status(400).json({
          error: true,
          field: field,
          message: `This ${field} is already registered!`
        });
      }

      const result = await clientCollection.insertOne(newClient);
      res.send(result);
    });

    // ক্লায়েন্ট আপডেট করার রাউট
    app.put('/client/:id', async (req, res) => {
      const id = req.params.id;
      const updatedClient = req.body;

      // অন্য কোনো ইউজারের সাথে ফোন বা ইমেইল মিলে যায় কি না চেক করা
      const existingClient = await clientCollection.findOne({
        _id: { $ne: new ObjectId(id) },
        $or: [{ phone: updatedClient.phone }, { email: updatedClient.email }]
      });

      if (existingClient) {
        let field = existingClient.phone === updatedClient.phone ? 'phone' : 'email';
        return res.status(400).json({
          error: true,
          field: field,
          message: `This ${field} is already used by another client!`
        });
      }

      const filter = { _id: new ObjectId(id) };
      const updateDoc = {
        $set: {
          name: updatedClient.name,
          phone: updatedClient.phone,
          email: updatedClient.email,
          password: updatedClient.password,
          address: updatedClient.address,
          isActive: updatedClient.isActive,
          login: updatedClient.login || 'no'
        }
      };
      const result = await clientCollection.updateOne(filter, updateDoc);
      res.send(result);
    });

    // ৪. ক্লায়েন্ট ডিলিট করার জন্য
    app.delete('/client/:id', async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await clientCollection.deleteOne(query);
      res.send(result);
    });

    // ক্লায়েন্টের লগইন স্ট্যাটাস আপডেট বা ফোর্সড লগআউট করার জন্য PATCH রুট
    app.patch('/client/login-status/:id', async (req, res) => {
      try {
        const { id } = req.params;
        const { login } = req.body; // 'yes' বা 'no'

        const result = await clientCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { login: login } }
        );

        res.send(result);
      } catch (error) {
        res.status(500).send({ message: "Failed to update login status" });
      }
    });

    // ==========================================
    // নতুন যোগ করা: ক্লায়েন্ট লগইন এপিআই
    // ==========================================
    app.post('/client/login', async (req, res) => {
      try {
        const { email, password } = req.body;

        // ১. ইমেইল দিয়ে ক্লায়েন্ট খোঁজা
        const client = await clientCollection.findOne({ email });
        if (!client) {
          return res.status(400).json({ message: 'Email not found!' });
        }

        // ২. অ্যাকাউন্ট একটিভ আছে কিনা চেক করা
        if (client.isActive === false || client.isActive === 'false') {
          return res.status(400).json({ message: 'Your account is inactive!' });
        }

        // ৩. পাসওয়ার্ড মিলছে কিনা চেক করা
        if (client.password !== password) {
          return res.status(400).json({ message: 'Wrong password!' });
        }

        // ৪. JWT টোকেন তৈরি করা
        const tokenPayload = { clientId: client._id, email: client.email };
        const token = jwt.sign(
          tokenPayload,
          process.env.CLIENT_ACCESS_TOKEN_SECRET || 'client_secret_key_here',
          { expiresIn: '7d' }
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



    // contact related api


    app.get('/contact', async (req, res) => {
      const result = await contactCollection.find().toArray();
      res.send(result);
    });

    app.post('/contact', async (req, res) => {
      const item = req.body;
      const result = await contactCollection.insertOne(item);
      res.send(result);
    });

    app.delete('/contact/:id', async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await contactCollection.deleteOne(query);
      res.send(result);
    });







    // purchase related api

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

    app.post('/purchase', async (req, res) => {
      const item = req.body;
      const result = await purchaseCollection.insertOne(item);
      res.send(result);
    });

    app.delete('/purchase/:id', async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await purchaseCollection.deleteOne(query);

      // purchase delete hole tar stock-purchase batch gulo o delete hobe
      await stockPurchaseCollection.deleteMany({ purchaseId: id });
      res.send(result);
    });

    app.put('/purchase/:id', async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const { unsetFields, stockCreated: _ignoreStockCreated, _id: _ignoreId, ...updatedData } = req.body;

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
      const wasReceived = oldPurchase?.receiveStatus === 'Received' || oldPurchase?.receiveStatus === 'Yes';
      if (wasReceived && updatedData.receiveStatus === 'Received' && !Array.isArray(updatedData.returnHistory)) {
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
            const itemsSubtotalSum = items.reduce((s, it) => s + (Number(it.subtotal) || 0), 0);
            const payable = Number(purchase.payableAmount) || 0;

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
              const itemSubtotal = Number(it.subtotal) || 0;
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
    const buildStockPlan = async (items = [], freeItems = [], excludeSaleId = null) => {
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
      message: 'Stock a product nai!',
      shortages,
    });

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
      const item = req.body;
      let allocations = [];
      if (item.status === 'Delivered') {
        const plan = await buildStockPlan(item.items || [], item.freeItems || []);
        if (!plan.ok) return res.status(400).send(stockErrorBody(plan.shortages));
        allocations = plan.allocations;
        item.stockAllocations = allocations;
      }
      const result = await salesCollection.insertOne(item);
      if (allocations.length > 0) await applyAllocations(allocations);
      res.send(result);
    });

    app.delete('/sales/:id', async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const existingSale = await salesCollection.findOne(query);
      const result = await salesCollection.deleteOne(query);

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
      const { unsetFields, ...updatedData } = req.body;

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

      if (existingSale && updatedData.status === 'Delivered' && existingSale.status !== 'Delivered') {
        // Delivery: age stock check
        const plan = await buildStockPlan(
          updatedData.items ?? existingSale.items ?? [],
          updatedData.freeItems ?? existingSale.freeItems ?? [],
          id
        );
        if (!plan.ok) return res.status(400).send(stockErrorBody(plan.shortages));
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
          id
        );
        if (!plan.ok) {
          await restoreOld(-1);
          return res.status(400).send(stockErrorBody(plan.shortages));
        }
        allocationsToApply = plan.allocations;
        updatedData.stockAllocations = plan.allocations;
      }

      const result = await salesCollection.updateOne(query, updateDoc);
      if (allocationsToApply) await applyAllocations(allocationsToApply);
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
      const id = req.params.id;
      const updatedItem = req.body;
      const filter = { _id: new ObjectId(id) };
      const updateDoc = {
        $set: {
          transferFrom: updatedItem.transferFrom,
          transferTo: updatedItem.transferTo,
          date: updatedItem.date,
          fromAccount: updatedItem.fromAccount,
          toAccount: updatedItem.toAccount,
          amount: updatedItem.amount,
          note: updatedItem.note,
        },
      };
      const result = await transferCollection.updateOne(filter, updateDoc);
      res.send(result);
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




    // account heads related api

    app.get('/account-heads', async (req, res) => {
      const result = await headsCollection.find().sort({ _id: -1 }).toArray();
      res.send(result);
    });

    app.post('/account-heads', async (req, res) => {
      const item = req.body;
      const result = await headsCollection.insertOne(item);
      res.send(result);
    });

    app.put('/account-heads/:id', async (req, res) => {
      const id = req.params.id;
      const updatedData = req.body;
      const query = { _id: new ObjectId(id) };
      const updateDoc = {
        $set: {
          category: updatedData.category,
          name: updatedData.name,
          isActive: updatedData.isActive,
        },
      };
      const result = await headsCollection.updateOne(query, updateDoc);
      res.send(result);
    });

    app.delete('/account-heads/:id', async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await headsCollection.deleteOne(query);
      res.send(result);
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
        const id = req.params.id;
        const updatedData = req.body;
        const filter = { _id: new ObjectId(id) };
        const updateDoc = {
          $set: {
            date: updatedData.date,
            accountType: updatedData.accountType,
            bankName: updatedData.bankName || '',
            accountNumber: updatedData.accountNumber || '',
            accountBranch: updatedData.accountBranch || '',
            accountName: updatedData.accountName || '',
            amount: Number(updatedData.amount),
            note: updatedData.note || ''
          }
        };
        const result = await investmentCollection.updateOne(filter, updateDoc);
        res.send(result);
      } catch (error) {
        res.status(500).send({ error: 'Failed to update investment' });
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
          .find({ investmentId: investmentId })
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
        const id = req.params.id;
        const updatedData = req.body;
        const filter = { _id: new ObjectId(id) };
        const updateDoc = {
          $set: {
            date: updatedData.date,
            mode: updatedData.mode,
            amount: Number(updatedData.amount),
            note: updatedData.note || ''
          }
        };
        const result = await adjustmentCollection.updateOne(filter, updateDoc);
        res.send(result);
      } catch (error) {
        res.status(500).send({ error: 'Failed to update adjustment' });
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




    // --- User Routes (Node.js & Express) ---

    // Get all users
    app.get('/user', async (req, res) => {
      try {
        const result = await userCollection.find().toArray();
        res.send(result);
      } catch (error) {
        res.status(500).send({ error: 'Failed to fetch users' });
      }
    });

    // Add new user (POST)
    app.post('/user', async (req, res) => {
      try {
        const user = req.body;
        // আপনি চাইলে এখানে পাসওয়ার্ড হাশ করে নিতে পারেন
        const result = await userCollection.insertOne(user);
        res.send(result);
      } catch (error) {
        res.status(500).send({ error: 'Failed to create user' });
      }
    });

    // Update user (PUT) - Handles empty password gracefully
    app.put('/user/:id', async (req, res) => {
      try {
        const id = req.params.id;
        const updatedData = req.body;

        // যদি পাসওয়ার্ড ফিল্ড ফাঁকা থাকে, তবে ডাটাবেজে থাকা পুরোনো পাসওয়ার্ডটিই রেখে দেবো
        if (!updatedData.password || updatedData.password.trim() === '') {
          const existingUser = await userCollection.findOne({ _id: new ObjectId(id) });
          if (existingUser) {
            updatedData.password = existingUser.password;
          }
        }

        const filter = { _id: new ObjectId(id) };
        const updateDoc = {
          $set: {
            name: updatedData.name,
            email: updatedData.email,
            phone: updatedData.phone,
            role: updatedData.role,
            address: updatedData.address,
            isActive: updatedData.isActive,
            password: updatedData.password // আগের অথবা নতুন পাসওয়ার্ড
          }
        };

        const result = await userCollection.updateOne(filter, updateDoc);
        res.send(result);
      } catch (error) {
        res.status(500).send({ error: 'Failed to update user' });
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
      const result = await userRoleCollection.insertOne(item);
      res.send(result);
    });

    // ৩. ইউজার রোল আপডেট করা (PUT) - এডিট ফিচারের জন্য এটি লাগবে
    app.put('/userRole/:id', async (req, res) => {
      const id = req.params.id;
      const updatedItem = req.body;
      const filter = { _id: new ObjectId(id) };
      const updateDoc = {
        $set: {
          role: updatedItem.role,
        },
      };
      const result = await userRoleCollection.updateOne(filter, updateDoc);
      res.send(result);
    });

    // ৪. ইউজার রোল ডিলিট করা (DELETE)
    app.delete('/userRole/:id', async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
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
      const id = req.params.id;
      const updatedItem = req.body;
      const filter = { _id: new ObjectId(id) };
      const updateDoc = {
        $set: {
          businessName: updatedItem.businessName,
          contactNumber: updatedItem.contactNumber,
          email: updatedItem.email,
          contactName: updatedItem.contactName,
          businessNumber: updatedItem.businessNumber,
          openingBalance: updatedItem.openingBalance,
          address: updatedItem.address,
          note: updatedItem.note
        },
      };
      const result = await companyCollection.updateOne(filter, updateDoc);
      res.send(result);
    });

    // Delete a company
    app.delete('/company/:id', async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await companyCollection.deleteOne(query);
      res.send(result);
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
      const id = req.params.id;
      const updatedItem = req.body;
      const filter = { _id: new ObjectId(id) };
      const updateDoc = {
        $set: {
          customerType: updatedItem.customerType,
          businessName: updatedItem.businessName,
          contactNumber: updatedItem.contactNumber,
          email: updatedItem.email,
          contactName: updatedItem.contactName,
          businessNumber: updatedItem.businessNumber,
          openingBalance: updatedItem.openingBalance,
          creditLimit: updatedItem.creditLimit,
          address: updatedItem.address,
          route: updatedItem.customerType === 'Wholesale Customer' ? updatedItem.route : '',
          note: updatedItem.note
        },
      };
      const result = await customerCollection.updateOne(filter, updateDoc);
      res.send(result);
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
        const id = req.params.id;
        const { name, isActive } = req.body;
        const query = { _id: new ObjectId(id) };

        const updateDoc = {
          $set: {
            name: name,
            isActive: isActive
          }
        };

        const result = await unitCollection.updateOne(query, updateDoc);
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: "Error updating unit", error });
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

    // ২. নতুন রাউট যোগ করার সময় (কোড সহ)
    app.post('/route', async (req, res) => {
      try {
        const item = req.body;

        // সবচেয়ে বড় order ভ্যালু বের করে তার সাথে ১ যোগ করা
        const lastroute = await routeCollection.findOne({}, { sort: { order: -1 } });
        const nextOrder = lastroute ? (lastroute.order + 1) : 1;

        const newroute = {
          name: item.name,
          code: item.code || "", // নতুন code ফিল্ড যুক্ত হলো
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

    // ৩. নির্দিষ্ট রাউট আপডেট করার জন্য (কোড সহ)
    app.put('/route/:id', async (req, res) => {
      try {
        const id = req.params.id;
        const { name, code, isActive } = req.body; // code রিসিভ করা হলো
        const query = { _id: new ObjectId(id) };

        const updateDoc = {
          $set: {
            name: name,
            code: code, // code আপডেট করা হলো
            isActive: isActive
          }
        };

        const result = await routeCollection.updateOne(query, updateDoc);
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: "Error updating route", error });
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
        const id = req.params.id;
        const { name, isActive } = req.body;
        const query = { _id: new ObjectId(id) };

        const updateDoc = {
          $set: {
            name: name,
            isActive: isActive
          }
        };

        const result = await categoryCollection.updateOne(query, updateDoc);
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: "Error updating category", error });
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









    // shop related api


    app.get('/shop', async (req, res) => {
      const result = await shopCollection.find().sort({ order: 1 }).toArray(); // Order অনুযায়ী সর্ট হবে
      res.send(result);
    });

    app.post('/shop', async (req, res) => {
      const item = req.body;
      // নতুন আইটেমকে শেষে রাখার জন্য কাউন্ট চেক করা যেতে পারে
      const count = await shopCollection.countDocuments();
      item.order = count;
      const result = await shopCollection.insertOne(item);
      res.send(result);
    });

    app.delete('/shop/:id', async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await shopCollection.deleteOne(query);
      res.send(result);
    });

    // ড্র্যাগ অ্যান্ড ড্রপ পজিশন সেভ করার জন্য রুট
    app.put('/shop/reorder', async (req, res) => {
      const updatedList = req.body; // ফ্রন্টএন্ড থেকে আসা নতুন সাজানো লিস্ট
      try {
        const operations = updatedList.map((item, index) => ({
          updateOne: {
            filter: { _id: new ObjectId(item._id) },
            update: { $set: { order: index } },
          }
        }));
        await shopCollection.bulkWrite(operations);
        res.send({ success: true, message: "পজিশন আপডেট হয়েছে" });
      } catch (error) {
        res.status(500).send({ message: "Reorder failed", error });
      }
    });



    // PRODUCT RELATED API 


    // ১. সব প্রোডাক্ট পাওয়া (সর্টেড বাই অর্ডার)
    app.get('/products', async (req, res) => {
      try {
        const data = await productsCollection.find().sort({ order: 1 }).toArray();
        res.send(data);
      } catch (err) {
        console.error(err);
        res.status(500).send({ message: "Error fetching products", error: err.message });
      }
    });

    // ২. ড্র্যাগ অ্যান্ড ড্রপ র‍্যাঙ্কিং সেভ করা (Bulk Update)
    // আইডি রাউটের উপরে রাখা হয়েছে যাতে 'reorder' শব্দটিকে সার্ভার আইডি মনে না করে
    app.put('/products/reorder', async (req, res) => {
      try {
        const items = req.body;
        const operations = items.map((item, index) => ({
          updateOne: {
            filter: { _id: new ObjectId(item._id) },
            update: { $set: { order: index } },
          }
        }));

        const result = await productsCollection.bulkWrite(operations);
        res.send({ success: true, message: "Order Updated Successfully", result });
      } catch (err) {
        res.status(500).send({ message: "Reorder failed", error: err.message });
      }
    });

    // ৩. নতুন প্রোডাক্ট যোগ করা (৫টি ফিল্ড: shop, name, costPrice, sellingPrice, unit)
    app.post('/products', async (req, res) => {
      try {
        const { name, costPrice, sellingPrice, unit, shop } = req.body;
        const count = await productsCollection.countDocuments();

        const newProduct = {
          name,
          costPrice: parseFloat(costPrice) || 0,
          sellingPrice: parseFloat(sellingPrice) || 0,
          unit,
          shop,
          order: count
        };

        const result = await productsCollection.insertOne(newProduct);
        res.status(201).send(result);
      } catch (err) {
        res.status(400).send({ message: "Failed to add product", error: err.message });
      }
    });

    // ৪. প্রোডাক্ট আপডেট করা
    app.put('/product/:id', async (req, res) => {
      try {
        const id = req.params.id;
        const data = { ...req.body };
        delete data._id;

        const parentFields = ['parentUnit', 'parentQty', 'subUnit', 'subUnitQty', 'freeProductParentUnitQty', 'freeProductSubQty'];
        const normalFields = ['unit', 'freeProductUnitQty'];

        const unsetDoc = {};
        if (data.parentUnitUse === true) {
          normalFields.forEach(f => { unsetDoc[f] = ""; });
        } else {
          parentFields.forEach(f => { unsetDoc[f] = ""; });
        }

        const result = await productCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: data, $unset: unsetDoc }
        );
        res.send(result);
      } catch (err) {
        res.status(400).send({ message: "Update failed", error: err.message });
      }
    });

    // ৫. প্রোডাক্ট ডিলিট করা
    app.delete('/products/:id', async (req, res) => {
      try {
        const id = req.params.id;
        const query = { _id: new ObjectId(id) };
        const result = await productsCollection.deleteOne(query);
        res.send(result);
      } catch (err) {
        res.status(500).send({ message: "Delete failed", error: err.message });
      }
    });




    //  ITEM RELATED API 

    // ১. সকল আইটেম বা ইনভয়েস পাওয়ার জন্য

    app.get('/item', async (req, res) => {
      try {
        const result = await itemCollection.find().sort({ _id: -1 }).toArray(); // নতুন ইনভয়েস আগে দেখাবে
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: "Error fetching items" });
      }
    });

    // ২. নির্দিষ্ট একটি আইডি দিয়ে ডাটা খুঁজে বের করার জন্য (এডিট করার সময় এটি লাগবে)
    app.get('/item/:id', async (req, res) => {
      try {
        const id = req.params.id;
        const query = { _id: new ObjectId(id) };
        const result = await itemCollection.findOne(query);
        if (!result) {
          return res.status(404).send({ message: "Item not found" });
        }
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: "Error fetching specific item" });
      }
    });

    // ৩. নতুন ইনভয়েস সেভ করার জন্য
    app.post('/item', async (req, res) => {
      try {
        const invoiceData = req.body;
        if (invoiceData._id) delete invoiceData._id; // আইডি থাকলে ডিলিট করে নতুন আইডি তৈরি হতে দেবে

        const result = await itemCollection.insertOne(invoiceData);
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: "Error saving item" });
      }
    });

    // ৪. ইনভয়েস ডিলিট করার জন্য (Trash-এ সেভ হয়ে তারপর ডিলিট হবে)
    app.delete('/item/:id', async (req, res) => {
      try {
        const id = req.params.id;
        const query = { _id: new ObjectId(id) };

        // ডিলিট করার আগে ডাটা খুঁজে বের করা
        const itemToDelete = await itemCollection.findOne(query);

        if (itemToDelete) {
          // Trash কালেকশনে ডাটা সেভ করা
          await trashCollection.insertOne(itemToDelete);
        }

        // মূল কালেকশন থেকে ডিলিট করা
        const result = await itemCollection.deleteOne(query);
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: "Error deleting item" });
      }
    });

    // ৫. ডাটা আপডেট করার জন্য (Edit Option নিখুঁতভাবে কাজ করার জন্য)
    app.put('/item/:id', async (req, res) => {
      try {
        const id = req.params.id;
        const updatedData = req.body;
        const filter = { _id: new ObjectId(id) };

        // বডি থেকে _id সরিয়ে নেওয়া হচ্ছে যেন মঙ্গোডিবি আপডেট করতে সমস্যা না করে
        const { _id, ...dataWithoutId } = updatedData;

        const updateDoc = {
          $set: dataWithoutId // এটি items অ্যারের ভেতরের showQty সহ সব ডাটা আপডেট করে দেবে
        };

        const result = await itemCollection.updateOne(filter, updateDoc, { upsert: true });
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: "Error updating data" });
      }
    });

    // ৬. একাধিক ইনভয়েস/আইটেম একসাথে ডিলিট করার জন্য (Trash-এ সেভ হয়ে তারপর ডিলিট হবে)
    app.delete('/items/delete-multiple', async (req, res) => {
      try {
        const { ids } = req.body;

        if (!ids || !Array.isArray(ids) || ids.length === 0) {
          return res.status(400).send({ message: "No IDs provided for deletion" });
        }

        const objectIds = ids.map(id => new ObjectId(id));
        const query = { _id: { $in: objectIds } };

        // ডিলিট হতে যাওয়া সব ডাটা আগে বের করা
        const itemsToDelete = await itemCollection.find(query).toArray();

        if (itemsToDelete.length > 0) {
          // Trash কালেকশনে সব ডাটা সেভ করা
          await trashCollection.insertMany(itemsToDelete);
        }

        // মূল কালেকশন থেকে ডিলিট করা
        const result = await itemCollection.deleteMany(query);

        res.send(result);
      } catch (error) {
        res.status(500).send({ message: "Error deleting multiple items" });
      }
    });

    // ৭. ট্র্যাশ থেকে সকল ডিলিট হওয়া ডাটা পাওয়ার জন্য
    app.get('/trash', async (req, res) => {
      try {
        const result = await trashCollection.find().sort({ _id: -1 }).toArray();
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: "Error fetching trash items" });
      }
    });

    // ৮. ট্র্যাশ থেকে একটি আইটেম রিকভার (পুনরুদ্ধার) করার জন্য
    app.post('/trash/restore/:id', async (req, res) => {
      try {
        const id = req.params.id;
        const query = { _id: new ObjectId(id) };
        const itemToRestore = await trashCollection.findOne(query);

        if (!itemToRestore) {
          return res.status(404).send({ message: "Item not found in trash" });
        }

        await itemCollection.insertOne(itemToRestore);
        const result = await trashCollection.deleteOne(query);
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: "Error restoring item" });
      }
    });

    // ৯. ট্র্যাশ থেকে একাধিক আইটেম একসাথে রিকভার করার জন্য
    app.post('/trash/restore-multiple', async (req, res) => {
      try {
        const { ids } = req.body;
        if (!ids || !Array.isArray(ids) || ids.length === 0) {
          return res.status(400).send({ message: "No IDs provided" });
        }

        const objectIds = ids.map(id => new ObjectId(id));
        const query = { _id: { $in: objectIds } };
        const itemsToRestore = await trashCollection.find(query).toArray();

        if (itemsToRestore.length > 0) {
          await itemCollection.insertMany(itemsToRestore);
          const result = await trashCollection.deleteMany(query);
          res.send(result);
        } else {
          res.status(404).send({ message: "No items found to restore" });
        }
      } catch (error) {
        res.status(500).send({ message: "Error restoring multiple items" });
      }
    });

    // ১১. ট্র্যাশ থেকে একাধিক আইটেম একসাথে পার্মানেন্টলি ডিলিট (ডায়নামিক রুটের উপরে রাখতে হবে)
    app.delete('/trash/delete-multiple', async (req, res) => {
      try {
        const { ids } = req.body;
        if (!ids || !Array.isArray(ids) || ids.length === 0) {
          return res.status(400).send({ message: "No IDs provided" });
        }

        const objectIds = ids.map(id => new ObjectId(id));
        const query = { _id: { $in: objectIds } };
        const result = await trashCollection.deleteMany(query);
        res.send(result);
      } catch (error) {
        console.error("Bulk delete error:", error);
        res.status(500).send({ message: "Error deleting multiple items" });
      }
    });

    // ১০. ট্র্যাশ থেকে একটি আইটেম পার্মানেন্টলি ডিলিট করার জন্য
    app.delete('/trash/:id', async (req, res) => {
      try {
        const id = req.params.id;
        const query = { _id: new ObjectId(id) };
        const result = await trashCollection.deleteOne(query);
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: "Error permanently deleting item" });
      }
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

// ✅ SEO-optimized Sitemap route (Only Blogs + Static Pages)
app.get("/sitemap.xml", async (req, res) => {
  try {
    res.header("Content-Type", "application/xml");
    res.header("Content-Encoding", "gzip");

    const smStream = new SitemapStream({ hostname: "https://bashaybazar.com" });
    const pipeline = smStream.pipe(createGzip());

    // 👉 Static pages
    smStream.write({ url: "/", changefreq: "daily", priority: 1.0, lastmod: new Date() });
    smStream.write({ url: "/about", changefreq: "weekly", priority: 0.8, lastmod: new Date() });
    smStream.write({ url: "/contact", changefreq: "weekly", priority: 0.8, lastmod: new Date() });

    // 👉 Dynamic Blogs (✅ Only Blogs)
    const blogs = await client.db("squirrelDb").collection("blog").find().toArray();
    blogs.forEach((blog) => {
      if (blog.blogSlug) {
        smStream.write({
          url: `/blog/${blog.blogSlug}`,
          changefreq: "weekly",
          priority: 0.7,
          lastmod: blog.updatedAt || blog.createdAt || new Date()
        });
      }
    });

    smStream.end();

    // ✅ Directly pipe to response (gzip handled correctly)
    pipeline.pipe(res).on("error", (e) => { throw e });

  } catch (e) {
    console.error("Sitemap generation error:", e);
    res.status(500).end();
  }
});


app.listen(port, () => {
  console.log(`Bashay Bazar is sitting on port ${port}`);
})