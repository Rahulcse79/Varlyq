require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const jwt = require('jsonwebtoken');
const redis = require('redis');

const app = express();
const client = redis.createClient();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

const PORT = process.env.PORT || 4500

//mongodb://127.0.0.1:27017/user_api
mongoose.connect(process.env.MONGO_URL, { 
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const User = mongoose.model('User', {
  name: String,
  email: { type: String, unique: true },
  mobile: String,
  password: String,
});

const PostSchema = new mongoose.Schema({
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  createdAt: Date,
  updatedAt: Date,
  message: String,
  comments: [
    {
      sentBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
      sentAt: Date,
      liked: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    }
  ]
});

const Post = mongoose.model('Post', PostSchema);

function verifyToken(req, res, next) {
  const token = req.header('Authorization');
  if (!token) return res.status(403).json({ message: 'Access denied' });

  try {
    const decoded = jwt.verify(token, 'secret_key');
    req.user = decoded;
    next();
  } catch (error) {
    res.status(400).json({ message: 'Invalid token' });
  }
}

function generateAccessToken(user) {
  return jwt.sign(user, 'secret_key', { expiresIn: '15m' });
}

function generateRefreshToken(user) {
  const refreshToken = jwt.sign(user, 'refresh_secret_key', { expiresIn: '7d' });
  client.set(user._id.toString(), refreshToken);
  return refreshToken;
}

async function verifyRefreshToken(userId, refreshToken) {
  return new Promise((resolve, reject) => {
    client.get(userId.toString(), (err, storedRefreshToken) => {
      if (err) reject(err);
      if (storedRefreshToken === refreshToken) {
        resolve(true);
      } else {
        resolve(false);
      }
    });
  });
}

function deleteRefreshToken(userId) {
  client.del(userId.toString());
}

app.get('/api/users', async (req, res) => {
  try {
    const users = await User.find();
    res.json(users);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.post('/api/users', async (req, res) => {
  const user = new User({
    name: req.body.name,
    email: req.body.email,
    mobile: req.body.mobile,
    password: req.body.password,
  });
  try {
    const newUser = await user.save();
    res.status(201).json(newUser);
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

app.put('/api/users/:id', async (req, res) => {
  try {
    const updatedUser = await User.findByIdAndUpdate(
      req.params.id,
      req.body,
      { new: true }
    );
    if (!updatedUser) throw Error('User not found');
    res.json(updatedUser);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.delete('/api/users/:id', async (req, res) => {
  try {
    const deletedUser = await User.findByIdAndDelete(req.params.id);
    if (!deletedUser) throw Error('User not found');
    res.status(200).json({ message: 'User deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.get('/api/posts', verifyToken, async (req, res) => {
  try {
    const posts = await Post.find();
    res.json(posts);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.post('/api/posts', verifyToken, async (req, res) => {
  const post = new Post({
    createdBy: req.user._id,
    createdAt: new Date(),
    updatedAt: new Date(),
    message: req.body.message,
    comments: [],
  });
  try {
    const newPost = await post.save();
    res.status(201).json(newPost);
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

app.delete('/api/posts/:id', verifyToken, async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);
    if (!post) throw Error('Post not found');
    if (post.createdBy.toString() !== req.user._id) {
      return res.status(403).json({ message: 'Unauthorized to delete this post' });
    }
    const deletedPost = await Post.findByIdAndDelete(req.params.id);
    if (!deletedPost) throw Error('Post not found');
    res.status(200).json({ message: 'Post deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.put('/api/posts/:id', verifyToken, async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);
    if (!post) throw Error('Post not found');
    if (post.createdBy.toString() !== req.user._id) {
      return res.status(403).json({ message: 'Unauthorized to update this post' });
    }
    post.message = req.body.message || post.message;
    post.updatedAt = new Date();
    const updatedPost = await post.save();
    res.json(updatedPost);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.post('/api/token', async (req, res) => {
  const userId = req.body.userId;
  const accessToken = generateAccessToken({ _id: userId });
  const refreshToken = generateRefreshToken({ _id: userId });
  res.json({ accessToken, refreshToken });
});

app.post('/api/refresh_token', async (req, res) => {
  const userId = req.body.userId;
  const refreshToken = req.body.refreshToken;
  const isValid = await verifyRefreshToken(userId, refreshToken);

  if (!isValid) {
    return res.status(401).json({ message: 'Invalid refresh token' });
  }

  const accessToken = generateAccessToken({ _id: userId });
  res.json({ accessToken });
});

app.post('/api/logout', async (req, res) => {
  const userId = req.body.userId;
  deleteRefreshToken(userId);
  res.json({ message: 'Logged out successfully' });
});

app.listen(PORT, () => {
  console.log('Server is running on http://localhost:4500');
});
