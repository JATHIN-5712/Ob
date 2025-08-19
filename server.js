const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const nodemailer = require("nodemailer");
const bcrypt = require("bcrypt");
const sqlite3 = require("sqlite3").verbose();
const jwt = require("jsonwebtoken");

const app = express();
app.use(cors());
app.use(bodyParser.json());

// Database setup (SQLite)
const db = new sqlite3.Database("users.db");
db.run(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    password TEXT,
    name TEXT,
    verified INTEGER DEFAULT 0
  )
`);

// In-memory OTP store
const otpStore = {};

// Mail transporter (Gmail App Password)
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL,       // your Gmail
    pass: process.env.EMAIL_PASS,  // your App Password
  },
});

// Register route
app.post("/register", async (req, res) => {
  const { email, password, name } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  db.run("INSERT INTO users (email, password, name) VALUES (?, ?, ?)",
    [email, hashedPassword, name],
    (err) => {
      if (err) return res.status(400).json({ message: "Email already exists" });

      // Generate OTP
      const otp = Math.floor(100000 + Math.random() * 900000).toString();
      otpStore[email] = otp;

      transporter.sendMail({
        from: `"ORBIT Account" <${process.env.EMAIL}>`,
        to: email,
        subject: "Your ORBIT Account OTP Code",
        text: `Welcome to ORBIT Account!\n\nYour OTP is: ${otp}`,
      });

      res.json({ message: "OTP sent to email. Please verify." });
    });
});

// Verify OTP
app.post("/verify-otp", (req, res) => {
  const { email, otp } = req.body;

  if (otpStore[email] === otp) {
    db.run("UPDATE users SET verified = 1 WHERE email = ?", [email]);
    delete otpStore[email];
    return res.json({ message: "Account verified successfully!" });
  }

  res.status(400).json({ message: "Invalid OTP" });
});

// Login route
app.post("/login", (req, res) => {
  const { email, password } = req.body;

  db.get("SELECT * FROM users WHERE email = ?", [email], async (err, user) => {
    if (!user) return res.status(400).json({ message: "User not found" });
    if (!user.verified) return res.status(400).json({ message: "Account not verified" });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json({ message: "Invalid password" });

    const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: "1h" });
    res.json({ message: "Login successful", token, name: user.name, email: user.email });
  });
});

app.listen(5000, () => console.log("✅ ORBIT Account backend running on port 5000"));
