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
    const unitCollection = client.db("squirrelDb").collection("unit");
    const itemCollection = client.db("squirrelDb").collection("item");


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

    // users related api

    app.get('/users', verifyToken, async (req, res) => {
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




    // contact related api

    // Only admin can get all contacts
    app.get('/contact', async (req, res) => {
      const result = await contactCollection.find().toArray();
      res.send(result);
    });

    // Only admin can post a new contact
    app.post('/contact', async (req, res) => {
      const item = req.body;
      const result = await contactCollection.insertOne(item);
      res.send(result);
    });

    // Only admin can delete a contact
    app.delete('/contact/:id', async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await contactCollection.deleteOne(query);
      res.send(result);
    });



    // Unit related API

    app.get('/unit', async (req, res) => {
      const result = await unitCollection.find().sort({ order: 1 }).toArray(); // Order অনুযায়ী সর্ট হবে
      res.send(result);
    });

    app.post('/unit', async (req, res) => {
      const item = req.body;
      // নতুন আইটেমকে শেষে রাখার জন্য কাউন্ট চেক করা যেতে পারে
      const count = await unitCollection.countDocuments();
      item.order = count;
      const result = await unitCollection.insertOne(item);
      res.send(result);
    });

    app.delete('/unit/:id', async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await unitCollection.deleteOne(query);
      res.send(result);
    });

    // ড্র্যাগ অ্যান্ড ড্রপ পজিশন সেভ করার জন্য রুট
    app.put('/unit/reorder', async (req, res) => {
      const updatedList = req.body; // ফ্রন্টএন্ড থেকে আসা নতুন সাজানো লিস্ট
      try {
        const operations = updatedList.map((item, index) => ({
          updateOne: {
            filter: { _id: new ObjectId(item._id) },
            update: { $set: { order: index } },
          }
        }));
        await unitCollection.bulkWrite(operations);
        res.send({ success: true, message: "পজিশন আপডেট হয়েছে" });
      } catch (error) {
        res.status(500).send({ message: "Reorder failed", error });
      }
    });



    // --- Product Routes (Fixed for Native MongoDB Driver) ---

    // সব প্রোডাক্ট পাওয়া (সর্টেড বাই অর্ডার)
    app.get('/products', async (req, res) => {
      try {
        const data = await productsCollection.find().sort({ order: 1 }).toArray();
        res.send(data);
      } catch (err) {
        console.error(err);
        res.status(500).send({ message: "Error fetching products", error: err.message });
      }
    });

    // নতুন প্রোডাক্ট যোগ করা
    app.post('/products', async (req, res) => {
      try {
        const { name, price, unit } = req.body;
        const count = await productsCollection.countDocuments();

        const newProduct = {
          name,
          price: parseFloat(price), // নাম্বার হিসেবে সেভ করা ভালো
          unit,
          order: count
        };

        const result = await productsCollection.insertOne(newProduct);
        res.status(201).send(result);
      } catch (err) {
        res.status(400).send({ message: "Failed to add product", error: err.message });
      }
    });

    // প্রোডাক্ট আপডেট করা
    app.put('/products/:id', async (req, res) => {
      try {
        const id = req.params.id;
        const filter = { _id: new ObjectId(id) };
        const updatedDoc = {
          $set: {
            name: req.body.name,
            price: parseFloat(req.body.price),
            unit: req.body.unit
          }
        };
        const result = await productsCollection.updateOne(filter, updatedDoc);
        res.send(result);
      } catch (err) {
        res.status(400).send({ message: "Update failed", error: err.message });
      }
    });

    // প্রোডাক্ট ডিলিট করা
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

    // ড্র্যাগ অ্যান্ড ড্রপ র‍্যাঙ্কিং সেভ করা (Bulk Update)
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













    // ================= ITEM RELATED API =================

    // ১. সকল আইটেম বা ইনভয়েস পাওয়ার জন্য
    app.get('/item', async (req, res) => {
      try {
        const result = await itemCollection.find().toArray();
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: "Error fetching items" });
      }
    });

    // ২. নির্দিষ্ট একটি আইডি দিয়ে ডাটা খুঁজে বের করার জন্য (এডিট করার সময় এটি লাগবে)
    app.get('/item/:id', async (req, res) => {
      try {
        const id = req.params.id;
        const query = { _id: new ObjectId(id) };
        const result = await itemCollection.findOne(query);
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: "Error fetching specific item" });
      }
    });

    // ৩. নতুন ইনভয়েস বা আইটেম সেভ করার জন্য
    app.post('/item', async (req, res) => {
      try {
        const item = req.body;
        const result = await itemCollection.insertOne(item);
        res.send(result); // এখানে insertedId রিটার্ন করবে
      } catch (error) {
        res.status(500).send({ message: "Error saving item" });
      }
    });

    // ৪. ইনভয়েস ডিলিট করার জন্য
    app.delete('/item/:id', async (req, res) => {
      try {
        const id = req.params.id;
        const query = { _id: new ObjectId(id) };
        const result = await itemCollection.deleteOne(query);
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: "Error deleting item" });
      }
    });

    // ৫. ডাটা আপডেট করার জন্য (কাস্টমার এবং আইটেম লিস্ট উভয়ই আপডেট হবে)
    app.put('/item/:id', async (req, res) => {
      try {
        const id = req.params.id;
        const updatedData = req.body;
        const filter = { _id: new ObjectId(id) };

        // এখানে সরাসরি বডি থেকে আসা সব ডাটা আপডেট হবে
        const updateDoc = {
          $set: updatedData
        };

        const result = await itemCollection.updateOne(filter, updateDoc, { upsert: true });
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: "Error updating data" });
      }
    });

    // ================= END OF ITEM API =================











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

    const smStream = new SitemapStream({ hostname: "https://squirrelpeace.com" });
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
  console.log(`Squirrel Peace is sitting on port ${port}`);
})