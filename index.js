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

      const filter = { _id: new ObjectId(id) };
      const updateDoc = {
        $set: {
          productName: updatedProduct.productName,
          company: updatedProduct.company,
          sku: updatedProduct.sku,
          category: updatedProduct.category,
          alertQuantity: updatedProduct.alertQuantity,
          purchasePrice: updatedProduct.purchasePrice,
          sellingPrice: updatedProduct.sellingPrice,
          mrp: updatedProduct.mrp,
          unit: updatedProduct.unit,
          pcsOfUnit: updatedProduct.pcsOfUnit,
          freeProductQty: updatedProduct.freeProductQty,
          freeProductName: updatedProduct.freeProductName,
          openingStockQty: updatedProduct.openingStockQty,
          note: updatedProduct.note,
          isActive: updatedProduct.isActive
        },
      };

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
    app.put('/products/:id', async (req, res) => {
      try {
        const id = req.params.id;
        const { name, costPrice, sellingPrice, unit, shop } = req.body;
        const filter = { _id: new ObjectId(id) };

        const updatedDoc = {
          $set: {
            name,
            costPrice: parseFloat(costPrice) || 0,
            sellingPrice: parseFloat(sellingPrice) || 0,
            unit,
            shop
          }
        };

        const result = await productsCollection.updateOne(filter, updatedDoc);
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