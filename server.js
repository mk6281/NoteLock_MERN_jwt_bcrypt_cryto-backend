require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { MongoClient, ObjectId } = require("mongodb");
const CryptoJS = require("crypto-js");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

const PORT = process.env.PORT || 8081;

app.use(helmet());

app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
}));

// ================== CONFIG ==================
app.use(express.json());
app.use(cors({
  origin: "*"
}));
const url = process.env.MONGO_URI;
const dbName = "signup";

const SECRET_KEY = process.env.SECRET_KEY;
const JWT_SECRET = process.env.JWT_SECRET;

let db;

// ================== DB CONNECT ==================
MongoClient.connect(url)
  .then(client => {
    console.log("✅ Connected to MongoDB");
    db = client.db(dbName);

    app.listen(PORT, () => {
      console.log("🚀 Server running on port ",PORT);
    });
  })
  .catch(err => console.error("❌ DB Error:", err));


// ================== 🔐 AUTH MIDDLEWARE ==================
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization'];

  if (!token) return res.status(403).json("No token");

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded; // contains email
    next();
  } catch (err) {
    return res.status(401).json("Invalid token");
  }
};


// ================== AUTH ROUTES ==================

// ✅ SIGNUP
app.post('/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    const existingUser = await db.collection("users").findOne({ email });

    if (existingUser) {
      return res.json("User already exists");
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await db.collection("users").insertOne({
      name,
      email,
      password: hashedPassword
    });

    res.json("Success");

  } catch (err) {
    console.error(err);
    res.status(500).json("Error");
  }
});




// ✅ LOGIN
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await db.collection("users").findOne({ email });

    if (!user) return res.json("Failed");

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) return res.json("Failed");

    const token = jwt.sign(
      { email: user.email },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({
      status: "Success",
      token
    });

  } catch (err) {
    console.error(err);
    res.status(500).json("Error");
  }
});


// ================== NOTES ROUTES ==================

// ✅ ADD NOTE
app.post('/addNote', verifyToken, async (req, res) => {
  try {
    const { title, content } = req.body;
    const email = req.user.email; // 🔐 secure

    const encryptedContent = CryptoJS.AES.encrypt(content, SECRET_KEY).toString();

    await db.collection("notes").insertOne({
      email,
      title,
      content: encryptedContent,
      createdAt: new Date()
    });

    res.json("Saved");

  } catch (err) {
    console.error("❌ Add Note error:", err);
    res.status(500).json("Error");
  }
});


// ✅ GET NOTES
app.post('/getNotes', verifyToken, async (req, res) => {
  try {
    const email = req.user.email; // 🔐 secure

    const notes = await db.collection("notes").find({ email }).toArray();

    const decryptedNotes = notes.map(note => {
      const bytes = CryptoJS.AES.decrypt(note.content, SECRET_KEY);
      const decryptedText = bytes.toString(CryptoJS.enc.Utf8);

      return {
        ...note,
        content: decryptedText
      };
    });

    res.json(decryptedNotes);

  } catch (err) {
    console.error("❌ Get Notes error:", err);
    res.status(500).json("Error");
  }
});


// ✅ DELETE NOTE
app.post('/deleteNote', verifyToken, async (req, res) => {
  try {
    const { id } = req.body;

    await db.collection("notes").deleteOne({
      _id: new ObjectId(id),
      email: req.user.email
    });

    res.json("Deleted");

  } catch (err) {
    console.error("❌ Delete error:", err);
    res.status(500).json("Error");
  }
});


// ✅ GET NOTE BY ID
app.post('/getNoteById', verifyToken, async (req, res) => {
  try {
    const { id } = req.body;

    const note = await db.collection("notes").findOne({
      _id: new ObjectId(id),
      email: req.user.email
    });

    if (!note) return res.json(null);

    const bytes = CryptoJS.AES.decrypt(note.content, SECRET_KEY);
    const decryptedText = bytes.toString(CryptoJS.enc.Utf8);

    res.json({
      ...note,
      content: decryptedText
    });

  } catch (err) {
    console.error("❌ getNoteById error:", err);
    res.status(500).json("Error");
  }
});


// ✅ UPDATE NOTE
app.post('/updateNote', verifyToken, async (req, res) => {
  try {
    const { id, title, content } = req.body;

    const encryptedContent = CryptoJS.AES.encrypt(content, SECRET_KEY).toString();

    await db.collection("notes").updateOne(
      {
        _id: new ObjectId(id),
        email: req.user.email
      },
      {
        $set: {
          title,
          content: encryptedContent
        }
      }
    );

    res.json("Updated");

  } catch (err) {
    console.error("❌ Update error:", err);
    res.status(500).json("Error");
  }
});

app.post('/addCredential', verifyToken, async (req, res) => {
  try {
    const { site, username, password } = req.body;
    const email = req.user.email;

    const encryptedPassword = CryptoJS.AES.encrypt(password, SECRET_KEY).toString();

    await db.collection("credentials").insertOne({
      email,
      site,
      username,
      password: encryptedPassword,
      createdAt: new Date()
    });

    res.json("Saved");

  } catch (err) {
    console.error(err);
    res.status(500).json("Error");
  }
});

app.post('/getCredentials', verifyToken, async (req, res) => {
  try {
    const email = req.user.email;

    const creds = await db.collection("credentials").find({ email }).toArray();

    const decrypted = creds.map(c => {
      const bytes = CryptoJS.AES.decrypt(c.password, SECRET_KEY);
      const password = bytes.toString(CryptoJS.enc.Utf8);

      return { ...c, password };
    });

    res.json(decrypted);

  } catch (err) {
    res.status(500).json("Error");
  }
});

app.post('/deleteCredential', verifyToken, async (req, res) => {
  try {
    const { id } = req.body;

    await db.collection("credentials").deleteOne({
      _id: new ObjectId(id),
      email: req.user.email
    });

    res.json("Deleted");

  } catch (err) {
    res.status(500).json("Error");
  }
});

app.post('/updateCredential', verifyToken, async (req, res) => {
  try {
    const { id, site, username, password } = req.body;

    const encryptedPassword = CryptoJS.AES.encrypt(password, SECRET_KEY).toString();

    await db.collection("credentials").updateOne(
      { _id: new ObjectId(id), email: req.user.email },
      {
        $set: { site, username, password: encryptedPassword }
      }
    );

    res.json("Updated");

  } catch (err) {
    res.status(500).json("Error");
  }
});
