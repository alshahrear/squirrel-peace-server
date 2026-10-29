const dns = require('dns');
dns.setServers(['8.8.8.8', '8.8.4.4']);
const express = require('express');
const app = express();
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { MongoClient, ServerApiVersion, ObjectId, } = require('mongodb');
require('dotenv').config();
const port = process.env.PORT || 5000;

// middleware
app.use(cors());
app.use(express.json());

// data change track (sob device er jonno)
const versionCol = () => client.db("squirrelDb").collection("meta");
app.use((req, res, next) => {
  if (req.method === 'GET') res.set('Cache-Control', 'no-store');
  if (req.method !== 'GET' && req.method !== 'OPTIONS' && req.path !== '/jwt' && req.path !== '/client/login') {
    res.on('finish', () => {
      if (res.statusCode < 400) {
        versionCol()
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
    const doc = await versionCol().findOne({ _id: 'dataVersion' });
    res.send({ version: doc?.version || 0 });
  } catch (e) {
    res.status(500).send({ error: 'version failed' });
  }
});


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
    const productCollection = client.db("squirrelDb").collection("product");
    const unitCollection = client.db("squirrelDb").collection("unit");
    const categoryCollection = client.db("squirrelDb").collection("category");
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
    const stockAdjustmentCollection = client.db("squirrelDb").collection("stockAdjustment");
    const salesCollection = client.db("squirrelDb").collection("sales");
    const featureCollection = client.db("squirrelDb").collection("feature");
    const purchaseBulkReturnCollection = client.db("squirrelDb").collection("purchaseBulkReturn");
    const salesBulkReturnCollection = client.db("squirrelDb").collection("salesBulkReturn");
    const salesDamageCollection = client.db("squirrelDb").collection('salesDamage');
    const damageReturnCollection = client.db("squirrelDb").collection('damageReturn');
    const PurchaseDuePaymentCollection = client.db("squirrelDb").collection('purchaseDuePayment');


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
          openingBalanceType: updatedItem.openingBalanceType,
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
          openingBalanceType: updatedItem.openingBalanceType,
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
        const id = req.params.id;
        const { name, isActive } = req.body;

        const duplicate = await routeCollection.findOne(
          { name: String(name || '').trim(), _id: { $ne: new ObjectId(id) } },
          { collation: { locale: 'en', strength: 2 } }
        );
        if (duplicate) {
          return res.status(400).send({ message: 'This route name already exists!' });
        }
        const query = { _id: new ObjectId(id) };

        const updateDoc = {
          $set: {
            name: name,
            isActive: isActive
          },
          $unset: { code: "" }
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
      item.status = 'Pending';
      const result = await damageReturnCollection.insertOne(item);
      res.send(result);
    });

    app.put('/damage-return/:id', async (req, res) => {
      const { _id: _ignoreId, ...updatedData } = req.body;
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
      const plan = await buildBulkReturnPlan(updatedData.items || [], id);
      if (!plan.ok) return res.status(400).send({ message: 'স্টকে পণ্য নেই!', shortages: plan.shortages });
      updatedData.stockAllocations = plan.allocations;
      const result = await purchaseBulkReturnCollection.updateOne(query, { $set: updatedData });
      res.send(result);
    });

    app.delete('/purchase-bulk-return/:id', async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await purchaseBulkReturnCollection.deleteOne(query);
      res.send(result);
    });

    // purchase related api

    // return entry te exact time (createdAt) boshiye dey, age thakle sheta e rakhe
    const stampReturns = (newList = [], oldList = []) => {
      const oldMap = new Map((oldList || []).map((r) => [String(r.returnId), r]));
      const sig = (r) =>
        JSON.stringify([r.items, r.freeItems, r.totalReturnPcs, r.totalReturnFreeQty, r.totalReturnFreeItemsQty, r.totalReturnAmount]);
      const now = new Date().toISOString();
      return (newList || []).map((r) => {
        const old = oldMap.get(String(r.returnId));
        const out = { ...r, createdAt: r.createdAt || old?.createdAt || now };
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
      if (item.invoiceNo) {
        const key = `p:${item.invoiceNo}`;
        if (recentKeys.has(key)) return res.send({ acknowledged: true, duplicate: true });
        recentKeys.add(key);
        setTimeout(() => recentKeys.delete(key), 15000);
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
      const { unsetFields, returnOnly, stockCreated: _ignoreStockCreated, _id: _ignoreId, ...updatedData } = req.body;

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
        updatedData.returnHistory = stampReturns(updatedData.returnHistory, oldPurchase?.returnHistory);
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
      if (hasNewPaid && returnOnly !== true) {
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
      const { stockBorrowConfirmed, ...item } = req.body;
      if (item.orderNo) {
        const key = `s:${item.orderNo}`;
        if (recentKeys.has(key)) return res.send({ acknowledged: true, duplicate: true });
        recentKeys.add(key);
        setTimeout(() => recentKeys.delete(key), 10000);
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
      const { unsetFields, stockBorrowConfirmed, ...updatedData } = req.body;
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