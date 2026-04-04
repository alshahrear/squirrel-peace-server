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
    const testimonialsCollection = client.db("squirrelDb").collection("reviews");
    const faqsCollection = client.db("squirrelDb").collection("faqs");
    const faqsAddCollection = client.db("squirrelDb").collection("faqsAdd");
    const quizFaqsCollection = client.db("squirrelDb").collection("quizFaqs");
    const quizFaqsAddCollection = client.db("squirrelDb").collection("quizFaqsAdd");
    const quizTermsCollection = client.db("squirrelDb").collection("quizTerms");
    const quizNextCollection = client.db("squirrelDb").collection("quizNext");
    const contactCollection = client.db("squirrelDb").collection("contact");
    const commentCollection = client.db("squirrelDb").collection("comment");
    const blogCollection = client.db("squirrelDb").collection("blog");
    const winnerCollection = client.db("squirrelDb").collection("winner");
    const draftCollection = client.db("squirrelDb").collection("draft");
    const newsletterFaqCollection = client.db("squirrelDb").collection("newsletterFaq");
    const quizToggleCollection = client.db("squirrelDb").collection("quizToggle");
    const quizOtpCollection = client.db("squirrelDb").collection("quizOtp");
    const quizTestCollection = client.db("squirrelDb").collection("quizTest");
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


    // testimonials related api

    app.get('/reviews', async (req, res) => {
      const result = await testimonialsCollection.find().toArray();
      res.send(result);
    });

    app.post('/reviews', async (req, res) => {
      const item = req.body;
      const result = await testimonialsCollection.insertOne(item);
      res.send(result);
    });

    app.delete('/reviews/:id', async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) }
      const result = await testimonialsCollection.deleteOne(query);
      res.send(result);
    })

    app.patch('/reviews/:id', async (req, res) => {
      const id = req.params.id;
      const item = req.body;
      const filter = { _id: new ObjectId(id) };
      const updatedDoc = {
        $set: {
          customerName: item.customerName,
          rating: item.rating,
          review: item.review,
          random: item.random,
          profileLink: item.profileLink
        }
      };
      const result = await testimonialsCollection.updateOne(filter, updatedDoc);
      res.send(result);
    });

    // faq related api

    app.get('/faqs', async (req, res) => {
      const result = await faqsCollection.find().toArray();
      res.send(result);
    });

    app.post('/faqs', async (req, res) => {
      const item = req.body;
      const result = await faqsCollection.insertOne(item);
      res.send(result);
    });

    app.delete('/faqs/:id', async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) }
      const result = await faqsCollection.deleteOne(query);
      res.send(result);
    })

    // ✅ Get current toggle state
    app.get("/quizToggle", async (req, res) => {
      try {
        let toggle = await quizToggleCollection.findOne({});
        if (!toggle) {
          // default state
          toggle = { isQuizEnabled: false };
          await quizToggleCollection.insertOne(toggle);
        }
        res.send(toggle);
      } catch (err) {
        console.error("Error fetching toggle:", err);
        res.status(500).send({ message: "Failed to fetch toggle state" });
      }
    });


    // ✅ Update toggle state 
    app.patch("/quizToggle", verifyToken, verifyAdmin, async (req, res) => {
      try {
        const { isQuizEnabled } = req.body;
        const updateResult = await quizToggleCollection.updateOne(
          {}, // only one document
          { $set: { isQuizEnabled: !!isQuizEnabled } },
          { upsert: true }
        );
        res.send({ message: "Toggle updated", isQuizEnabled });
      } catch (err) {
        console.error("Error updating toggle:", err);
        res.status(500).send({ message: "Failed to update toggle" });
      }
    });


    // Quiz faq related api

    app.get('/quizFaqs', async (req, res) => {
      const result = await quizFaqsCollection.find().toArray();
      res.send(result);
    });

    app.post('/quizFaqs', async (req, res) => {
      const item = req.body;
      const result = await quizFaqsCollection.insertOne(item);
      res.send(result);
    });

    app.delete('/quizFaqs/:id', async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) }
      const result = await quizFaqsCollection.deleteOne(query);
      res.send(result);
    })


    // faq add related api

    app.get('/faqsAdd', async (req, res) => {
      const result = await faqsAddCollection.find().toArray();
      res.send(result);
    });

    app.post('/faqsAdd', async (req, res) => {
      const item = req.body;
      const result = await faqsAddCollection.insertOne(item);
      res.send(result);
    });

    app.delete('/faqsAdd/:id', async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) }
      const result = await faqsAddCollection.deleteOne(query);
      res.send(result);
    })

    app.patch('/faqsAdd/:id', async (req, res) => {
      const id = req.params.id;
      const item = req.body;
      const filter = { _id: new ObjectId(id) };
      const updatedDoc = {
        $set: {
          faqQuestion: item.faqQuestion,
          faqAnswer: item.faqAnswer
        }
      };
      const result = await faqsAddCollection.updateOne(filter, updatedDoc);
      res.send(result);
    });

    // Quiz faq add related api

    app.get('/quizFaqsAdd', async (req, res) => {
      const result = await quizFaqsAddCollection.find().toArray();
      res.send(result);
    });

    app.post('/quizFaqsAdd', async (req, res) => {
      try {
        const item = req.body;
        const result = await quizFaqsAddCollection.insertOne(item);

        res.send({ insertedId: result.insertedId });
      } catch (error) {
        console.error("Insert error:", error);
        res.status(500).send({ error: "Insert failed" });
      }
    });

    app.delete('/quizFaqsAdd/:id', async (req, res) => {
      try {
        const id = req.params.id;
        if (!ObjectId.isValid(id)) {
          return res.status(400).send({ error: "Invalid ID format" });
        }
        const query = { _id: new ObjectId(id) };
        const result = await quizFaqsAddCollection.deleteOne(query);
        res.send(result);
      } catch (error) {
        console.error("Delete error:", error);
        res.status(500).send({ error: "Delete failed" });
      }
    });

    app.patch('/quizFaqsAdd/:id', async (req, res) => {
      try {
        const id = req.params.id;
        if (!ObjectId.isValid(id)) {
          return res.status(400).send({ error: "Invalid ID format" });
        }
        const item = req.body;
        const filter = { _id: new ObjectId(id) };
        const updatedDoc = {
          $set: {
            faqQuestion: item.faqQuestion,
            faqAnswer: item.faqAnswer,
          },
        };
        const result = await quizFaqsAddCollection.updateOne(filter, updatedDoc);
        res.send(result);
      } catch (error) {
        console.error("Update error:", error);
        res.status(500).send({ error: "Update failed" });
      }
    });


    // quiz next collection


    app.get('/quizNext', async (req, res) => {
      const result = await quizNextCollection.find().toArray();
      res.send(result);
    });

    app.post('/quizNext', async (req, res) => {
      const item = req.body;
      // যদি client থেকে না আসে তবে default isSelected false
      if (item.isSelected === undefined) {
        item.isSelected = false;
      }
      const result = await quizNextCollection.insertOne(item);
      res.send(result);
    });

    app.delete('/quizNext/:id', async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await quizNextCollection.deleteOne(query);
      res.send(result);
    });

    app.patch('/quizNext/:id', async (req, res) => {
      const id = req.params.id;
      const item = req.body;
      const filter = { _id: new ObjectId(id) };

      const updatedDoc = {
        $set: {}
      };

      // শুধু quizNext এলে সেট করবে
      if (item.quizNext !== undefined) {
        updatedDoc.$set.quizNext = item.quizNext;
      }

      // শুধু isSelected এলে সেট করবে
      if (item.isSelected !== undefined) {
        updatedDoc.$set.isSelected = item.isSelected;
      }

      const result = await quizNextCollection.updateOne(filter, updatedDoc);
      res.send(result);
    });


    // quiz terms related api

    app.get('/quizTerms', async (req, res) => {
      const result = await quizTermsCollection.find().toArray();
      res.send(result);
    });

    app.post('/quizTerms', async (req, res) => {
      const item = req.body;
      const result = await quizTermsCollection.insertOne(item);
      res.send(result);
    });

    app.delete('/quizTerms/:id', async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) }
      const result = await quizTermsCollection.deleteOne(query);
      res.send(result);
    })

    app.patch('/quizTerms/:id', async (req, res) => {
      const id = req.params.id;
      const item = req.body;
      const filter = { _id: new ObjectId(id) };
      const updatedDoc = {
        $set: {
          quizTerms: item.quizTerms,
        }
      };
      const result = await quizTermsCollection.updateOne(filter, updatedDoc);
      res.send(result);
    });


    // quiz otp related api

    app.get('/quizOtp', async (req, res) => {
      const result = await quizOtpCollection.find().toArray();
      res.send(result);
    });

    app.post('/quizOtp', async (req, res) => {
      const item = req.body;
      // default false if not provided
      if (item.requireImage === undefined) {
        item.requireImage = false;
      }
      const result = await quizOtpCollection.insertOne(item);
      res.send(result);
    });

    app.delete('/quizOtp/:id', async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) }
      const result = await quizOtpCollection.deleteOne(query);
      res.send(result);
    });

    // ✅ Quiz OTP Update API (with optional YouTube video)
    app.patch('/quizOtp/:id', async (req, res) => {
      try {
        const id = req.params.id;
        const item = req.body;
        const filter = { _id: new ObjectId(id) };

        const updatedDoc = {
          $set: {
            quizOtp: item.quizOtp,
            quizQus: item.quizQus,
            requireImage: item.requireImage ?? false, // ✅ toggle save
            quizDateText: item.quizDateText || "",    // ✅ date field
            youtubeUrl: item.youtubeUrl || "",        // ✅ new YouTube field
          },
        };

        const result = await quizOtpCollection.updateOne(filter, updatedDoc);
        res.send(result);
      } catch (err) {
        console.error("❌ quizOtp PATCH error:", err);
        res.status(500).send({ message: "Internal server error" });
      }
    });



    // quiz test related api

    app.get('/quizTest', async (req, res) => {
      const result = await quizTestCollection.find().toArray();
      res.send(result);
    });

    app.post('/quizTest', async (req, res) => {
      const item = req.body;
      const result = await quizTestCollection.insertOne(item);
      res.send(result);
    });

    app.delete('/quizTest/:id', async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await quizTestCollection.deleteOne(query);
      res.send(result);
    });

    // Delete all quiz tests
    app.delete('/quizTest', async (req, res) => {
      try {
        const result = await quizTestCollection.deleteMany({});
        res.send({
          success: true,
          message: `${result.deletedCount} quiz tests deleted successfully`,
        });
      } catch (error) {
        console.error(error);
        res.status(500).send({
          success: false,
          message: 'Failed to delete all quiz tests',
        });
      }
    });


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

    // comment related api

    app.get('/comment', async (req, res) => {
      const result = await commentCollection.find().toArray();
      res.send(result);
    });

    app.post('/comment/blog', async (req, res) => {
      const {
        name,
        email,
        comment,
        blogSlug,
        blogTitle = '',
        blogCategory = '',
        blogImage = ''
      } = req.body;

      const newComment = {
        name,
        email,
        comment,
        blogSlug,
        blogTitle,
        blogCategory,
        blogImage,
        createdAt: new Date()
      };

      const result = await commentCollection.insertOne(newComment);
      res.send(result);
    });

    app.delete('/comment/:id', async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await commentCollection.deleteOne(query);
      res.send(result);
    });


    // blog related api

    // সব blog fetch
    app.get('/blog', async (req, res) => {
      const result = await blogCollection.find().toArray();
      res.send(result);
    });

    // blog id অনুযায়ী fetch
    app.get('/blog/:id', async (req, res) => {
      const id = req.params.id;
      const result = await blogCollection.findOne({ _id: new ObjectId(id) });
      res.send(result);
    });

    // blog slug অনুযায়ী fetch (SEO-friendly)
    app.get('/blog/slug/:slug', async (req, res) => {
      try {
        const slug = req.params.slug;
        if (!slug) {
          return res.status(400).json({ error: "Slug is required" });
        }

        const result = await blogCollection.findOne({ blogSlug: slug });

        if (!result) {
          return res.status(404).json({ error: "blog not found" });
        }

        res.json(result);
      } catch (err) {
        console.error("Error fetching blog by slug:", err);
        res.status(500).json({ error: "Internal server error" });
      }
    });

    // নতুন blog create
    app.post('/blog', async (req, res) => {
      const item = req.body;

      // slug তৈরি করা
      const slug = slugify(item.blogTitle, { lower: true, strict: true });
      item.blogSlug = slug; // MongoDB তে নতুন ফিল্ড

      const result = await blogCollection.insertOne(item);
      res.send(result);
    });

    // blog delete
    app.delete('/blog/:id', async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await blogCollection.deleteOne(query);
      res.send(result);
    });

    // blog update (title, description, category, image)
    app.patch('/blog/:id', async (req, res) => {
      const id = req.params.id;
      const item = req.body;

      const filter = { _id: new ObjectId(id) };

      // slug update করা, যদি title change হয়
      let slug = undefined;
      if (item.blogTitle) {
        slug = slugify(item.blogTitle, { lower: true, strict: true });
      }

      const updatedDoc = {
        $set: {
          blogTitle: item.blogTitle,
          blogShortDescription: item.blogShortDescription,
          blogRandom: item.blogRandom,
          blogCategory: item.blogCategory,
          blogImage: item.blogImage,
          ...(slug && { blogSlug: slug }) // slug only update if title changed
        }
      };
      const result = await blogCollection.updateOne(filter, updatedDoc);
      console.log("👉 Mongo update result:", result);
      res.send(result);
    });

    // blog details update (long description, date, time)
    app.patch('/blogDetails/:id', async (req, res) => {
      const id = req.params.id;
      const item = req.body;
      const filter = { _id: new ObjectId(id) };
      const updateDoc = {
        $set: {
          blogTime: item.blogTime,
          blogDate: item.blogDate,
          blogLongDescription: item.blogLongDescription,
          blogRandom: item.blogRandom,
        }
      };
      const result = await blogCollection.updateOne(filter, updateDoc);
      res.send(result);
    });

    // winner related api

    app.get('/winner', async (req, res) => {
      const result = await winnerCollection.find().toArray();
      res.send(result);
    });

    app.get('/winner/:id', async (req, res) => {
      const id = req.params.id;
      const result = await winnerCollection.findOne({ _id: new ObjectId(id) });
      res.send(result);
    });

    app.post('/winner', async (req, res) => {
      const item = req.body;
      const result = await winnerCollection.insertOne(item);
      res.send(result);
    });

    app.delete('/winner/:id', async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) }
      const result = await winnerCollection.deleteOne(query);
      res.send(result);
    })


    // draft related api

    app.get('/draft', async (req, res) => {
      const result = await draftCollection.find().toArray();
      res.send(result);
    });

    app.get('/draft/:id', async (req, res) => {
      const id = req.params.id;
      const result = await draftCollection.findOne({ _id: new ObjectId(id) });
      res.send(result);
    });

    app.post('/draft', async (req, res) => {
      const item = req.body;
      const result = await draftCollection.insertOne(item);
      res.send(result);
    });

    app.delete('/draft/:id', async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) }
      const result = await draftCollection.deleteOne(query);
      res.send(result);
    });

    app.patch('/draft/:id', async (req, res) => {
      const id = req.params.id;
      const item = req.body;

      const filter = { _id: new ObjectId(id) };
      const updatedDoc = {
        $set: {
          storyTitle: item.storyTitle,
          storyShortDescription: item.storyShortDescription,
          storyRandom: item.storyRandom,
          storyCategory: item.storyCategory,
          storyImage: item.storyImage,
        }
      };
      const result = await draftCollection.updateOne(filter, updatedDoc);
      console.log("👉 Mongo update result:", result);
      res.send(result);
    });

    app.patch('/draftDetails/:id', async (req, res) => {
      const id = req.params.id;
      const item = req.body;
      const filter = { _id: new ObjectId(id) };
      const updateDoc = {
        $set: {
          storyTime: item.storyTime,
          storyDate: item.storyDate,
          storyLongDescription: item.storyLongDescription,
          storyRandom: item.storyRandom,
        }
      };
      const result = await draftCollection.updateOne(filter, updateDoc);
      res.send(result);
    });

    // newsletterFaq related api

    app.get('/newsletterFaq', async (req, res) => {
      const result = await newsletterFaqCollection.find().toArray();
      res.send(result);
    });

    app.post('/newsletterFaq', async (req, res) => {
      const item = req.body;
      const result = await newsletterFaqCollection.insertOne(item);
      res.send(result);
    });

    app.delete('/newsletterFaq/:id', async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) }
      const result = await newsletterFaqCollection.deleteOne(query);
      res.send(result);
    })

    app.patch('/newsletterFaq/:id', async (req, res) => {
      const id = req.params.id;
      const item = req.body;
      const filter = { _id: new ObjectId(id) };
      const updatedDoc = {
        $set: {
          faqQuestion: item.faqQuestion,
          faqAnswer: item.faqAnswer
        }
      };
      const result = await newsletterFaqCollection.updateOne(filter, updatedDoc);
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




    // item related api

    app.get('/item', async (req, res) => {
      const result = await itemCollection.find().toArray();
      res.send(result);
    });

    app.post('/item', async (req, res) => {
      const item = req.body;
      const result = await itemCollection.insertOne(item);
      res.send(result); // এখানে insertedId রিটার্ন করবে
    });

    app.delete('/item/:id', async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) }
      const result = await itemCollection.deleteOne(query);
      res.send(result);
    });

    // কাস্টমার ডাটা আপডেট করার জন্য
    app.put('/item/:id', async (req, res) => {
      const id = req.params.id;
      const customerData = req.body; // সরাসরি বডি থেকে ডাটা নিচ্ছি

      const filter = { _id: new ObjectId(id) };
      const updateDoc = {
        $set: {
          customer: customerData
        }
      };

      const result = await itemCollection.updateOne(filter, updateDoc);
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