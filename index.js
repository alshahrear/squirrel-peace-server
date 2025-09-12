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
    const contactCollection = client.db("squirrelDb").collection("contact");
    const commentCollection = client.db("squirrelDb").collection("comment");
    const blogCollection = client.db("squirrelDb").collection("blog");
    const winnerCollection = client.db("squirrelDb").collection("winner");
    const draftCollection = client.db("squirrelDb").collection("draft");
    const newsletterFaqCollection = client.db("squirrelDb").collection("newsletterFaq");


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
    })

    app.patch('/draft/:id', async (req, res) => {
      const id = req.params.id;
      const item = req.body;

      const filter = { _id: new ObjectId(id) };
      const updatedDoc = {
        $set: {
          blogTitle: item.blogTitle,
          blogShortDescription: item.blogShortDescription,
          blogRandom: item.blogRandom,
          blogCategory: item.blogCategory,
          blogImage: item.blogImage,
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
          blogTime: item.blogTime,
          blogDate: item.blogDate,
          blogLongDescription: item.blogLongDescription,
          blogRandom: item.blogRandom,
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