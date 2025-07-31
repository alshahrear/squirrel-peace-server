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
    const contactCollection = client.db("squirrelDb").collection("contact");
    const commentCollection = client.db("squirrelDb").collection("comment");
    const storyCollection = client.db("squirrelDb").collection("story");
    const draftCollection = client.db("squirrelDb").collection("draft");
    const blogCollection = client.db("squirrelDb").collection("blog");
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
        blogId,
        blogTitle = '',
        blogCategory = '',
        blogImage = ''
      } = req.body;

      const newComment = {
        name,
        email,
        comment,
        blogId,
        blogTitle,
        blogCategory,
        blogImage,
        createdAt: new Date()
      };

      const result = await commentCollection.insertOne(newComment);
      res.send(result);
    });

    app.post('/comment/story', async (req, res) => {
      const {
        name,
        email,
        comment,
        storyId,
        storyTitle = '',
        storyCategory = '',
        storyImage = ''
      } = req.body;

      const newComment = {
        name,
        email,
        comment,
        storyId,
        storyTitle,
        storyCategory,
        storyImage,
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


    // story related api

    app.get('/story', async (req, res) => {
      const result = await storyCollection.find().toArray();
      res.send(result);
    });

    app.get('/story/:id', async (req, res) => {
      const id = req.params.id;
      const result = await storyCollection.findOne({ _id: new ObjectId(id) });
      res.send(result);
    });

    app.get('/storyDetails/:id', async (req, res) => {
      const id = req.params.id;
      const result = await storyCollection.findOne({ _id: new ObjectId(id) });
      res.send(result);
    });

    app.post('/story', async (req, res) => {
      const item = req.body;
      const result = await storyCollection.insertOne(item);
      res.send(result);
    });

    app.delete('/story/:id', async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await storyCollection.deleteOne(query);
      res.send(result);
    });

    app.patch('/story/:id', async (req, res) => {
      const id = req.params.id;
      const item = req.body;

      const filter = { _id: new ObjectId(id) };
      const updatedDoc = {
        $set: {
          storyTitle: item.storyTitle,
          storyShortDescription: item.storyShortDescription,
          storyRandom: item.storyRandom,
          storyCategory: item.storyCategory,
          normalImage: item.normalImage,
        }
      };
      const result = await storyCollection.updateOne(filter, updatedDoc);
      console.log("👉 Mongo update result:", result);
      res.send(result);
    });

    app.patch('/storyDetails/:id', async (req, res) => {
      const id = req.params.id;
      const item = req.body;
      const filter = { _id: new ObjectId(id) };
      const updateDoc = {
        $set: {
          storyTime: item.storyTime,
          storyDate: item.storyDate,
          storyLongDescription: item.storyLongDescription,
          storyRandom: item.storyRandom,
          bannerImage: item.bannerImage
        }
      };
      const result = await storyCollection.updateOne(filter, updateDoc);
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


    // blog related api

    app.get('/blog', async (req, res) => {
      const result = await blogCollection.find().toArray();
      res.send(result);
    });

    app.get('/blog/:id', async (req, res) => {
      const id = req.params.id;
      const result = await blogCollection.findOne({ _id: new ObjectId(id) });
      res.send(result);
    });

    app.post('/blog', async (req, res) => {
      const item = req.body;
      const result = await blogCollection.insertOne(item);
      res.send(result);
    });

    app.delete('/blog/:id', async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) }
      const result = await blogCollection.deleteOne(query);
      res.send(result);
    })

    app.patch('/blog/:id', async (req, res) => {
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
      const result = await blogCollection.updateOne(filter, updatedDoc);
      console.log("👉 Mongo update result:", result);
      res.send(result);
    });

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

app.listen(port, () => {
  console.log(`Squirrel Peace is sitting on port ${port}`);
})