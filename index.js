import "dotenv/config";
import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import jwt from "jsonwebtoken";
import { nanoid } from "nanoid";
import bcrypt from "bcrypt";
import { z } from "zod";
import User from "./models/User.js";

const app = express();
app.use(express.json());
app.use(cors());

const PORT = 3000;

// MongoDB Connect
mongoose
  .connect(process.env.MONGO_URL, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => console.error("❌ MongoDB error:", err));

// Zod Schema for user input
const authSchema = z.object({
  username: z.string().min(3, "Username must be at least 3 characters"),
  password: z.string().min(6, "Password must be at least 6 characters"),
});

// Routes

// Health Check
app.get("/", (req, res) => {
  res.send("API is running...");
});

// Signup
app.post("/signup", async (req, res) => {
  const parsed = authSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ errors: parsed.error.errors });
  }

  const { username, password } = parsed.data;

  try {
    const existing = await User.findOne({ username });
    if (existing) return res.status(400).send("User already exists");

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      userid: nanoid(),
      username,
      password: hashedPassword,
    });

    await newUser.save();
    res.status(201).send("Signup successful");
  } catch (error) {
    console.error("Signup error:", error);
    res.status(500).send("Internal server error");
  }
});

// Login
app.post("/login", async (req, res) => {
  const parsed = authSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ errors: parsed.error.errors });
  }

  const { username, password } = parsed.data;

  try {
    const user = await User.findOne({ username });
    if (!user) return res.status(401).send("Invalid credentials");

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) return res.status(401).send("Invalid credentials");

    const token = jwt.sign({ userid: user.userid }, process.env.JWT_SECRET);
    res.json({ message: "Login successful", token });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).send("Internal server error");
  }
});

// Protected route
app.get("/protected", authorize, (req, res) => {
  res.send(`Hello user with ID: ${req.userid}`);
});

// Auth middleware
function authorize(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).send("Unauthorized");

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userid = decoded.userid;
    next();
  } catch (err) {
    res.status(400).send("Invalid token");
  }
}

app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
