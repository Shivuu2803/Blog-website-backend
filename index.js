require('dotenv').config();

const express = require("express");
const app = express();
const cors = require("cors");
const mongoose = require("mongoose");
const User = require("./models/user");
const Post = require('./models/post');
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const multer = require("multer");
const uploadMiddleware = multer({ dest: 'uploads/' });
const fs = require("fs");

const saltRounds = parseInt(process.env.BCRYPT_SALT_ROUNDS);
const secret = process.env.JWT_SECRET;

app.use(cors({
  origin: ['https://tiny-frangollo-7f6d3d.netlify.app'],
  credentials: true,
}));
app.use(express.json());
app.use(cookieParser());
app.use('/uploads', express.static(__dirname + '/uploads'));

mongoose.connect(process.env.MONGO_URL)
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => console.error("MongoDB connection error:", err));


app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  try {
    const hashedPassword = bcrypt.hashSync(password, saltRounds);
    const userDoc = await User.create({
      username,
      password: hashedPassword,
    });
    res.json(userDoc);
  } catch (err) {
    console.log(err);
    res.status(400).json(err);
  }
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const userDoc = await User.findOne({ username });

  if (!userDoc) {
    return res.status(400).json("User not found");
  }

  const passOK = bcrypt.compareSync(password, userDoc.password);
  if (passOK) {
    jwt.sign({ username, id: userDoc._id }, secret, {}, (err, token) => {
      if (err) throw err;
      res.cookie('token', token, { httpOnly: true }).json({
        id: userDoc._id,
        username,
      });
    });
  } else {
    res.status(400).json("Wrong credentials");
  }
});

app.get('/profile', (req, res) => {
  const { token } = req.cookies;
  if (!token) {
    return res.status(401).json({ error: "Token not provided" });
  }

  jwt.verify(token, secret, {}, (err, info) => {
    if (err) {
      return res.status(403).json({ error: "Invalid token" });
    }
    res.json(info);
  });
});

app.post('/logout', (req, res) => {
  res.cookie('token', '').json('ok');
});

app.post('/post', uploadMiddleware.single('file'), async (req, res) => {
  const { originalname, path } = req.file;
  const parts = originalname.split('.');
  const ext = parts[parts.length - 1];
  const newPath = path + '.' + ext;
  fs.renameSync(path, newPath);

  const { token } = req.cookies;
  if (!token) {
    return res.status(401).json({ error: "Token not provided" });
  }

  jwt.verify(token, secret, {}, async (err, info) => {
    if (err) return res.status(403).json({ error: "Invalid token" });

    const { title, summary, content } = req.body;
    const postDoc = await Post.create({
      title,
      summary,
      content,
      cover: newPath,
      author: info.id,
    });
    res.json(postDoc);
  });
});

app.put('/post', uploadMiddleware.single('file'), async (req, res) => {
  let newPath = null;
  if (req.file) {
    const { originalname, path } = req.file;
    const parts = originalname.split('.');
    const ext = parts[parts.length - 1];
    newPath = path + '.' + ext;
    fs.renameSync(path, newPath);
  }

  const { token } = req.cookies;
  if (!token) {
    return res.status(401).json({ error: "Token not provided" });
  }

  jwt.verify(token, secret, {}, async (err, info) => {
    if (err) return res.status(403).json({ error: "Invalid token" });

    const { id, title, summary, content } = req.body;
    const postDoc = await Post.findById(id);

    const isAuthor = JSON.stringify(postDoc.author) === JSON.stringify(info.id);
    if (!isAuthor) {
      return res.status(400).json('You are not the author');
    }

    await postDoc.updateOne({
      title,
      summary,
      content,
      cover: newPath ? newPath : postDoc.cover,
    });

    res.json(postDoc);
  });
});

app.get('/post', async (req, res) => {
  res.json(
    await Post.find()
      .populate('author', ['username'])
      .sort({ createdAt: -1 })
      .limit(20)
  );
});

app.get('/post/:id', async (req, res) => {
  const { id } = req.params;
  const postDoc = await Post.findById(id).populate('author', ['username']);
  res.json(postDoc);
});

app.listen(4000, () => {
  console.log("Server is running on port 4000");
});
