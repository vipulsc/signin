import "dotenv/config";
import express from "express";
import { nanoid } from "nanoid";
const app = express();
app.use(express.json());
const port = 3000;
import jwt from "jsonwebtoken";
import cors from "cors";

const allowedOrigins = ["http://localhost:5500", "https://yourfrontend.com"];

app.use(cors());

// AUTHENTICATION

app.get("/", (req, res) => {
  res.send("API is running...");
});

app.post("/signup", async (req, res) => {
  try {
    let users = await loadFile("user.json");

    if (!Array.isArray(users)) {
      users = [];
    }

    const { username, password } = req.body;

    // Basic validation
    if (!username || !password) {
      return res.status(400).send("Username and password are required");
    }

    const userExists = users.some((u) => u.username === username);
    if (userExists) {
      return res
        .status(400)
        .send(`User with username ${username} already exists.`);
    }

    users.push({
      userid: nanoid(),
      username: username,
      password: password,
    });

    await editFile("user.json", users);
    return res.status(201).send("SignUP Successfully");
  } catch (error) {
    console.error("Error during signup:", error);
    return res.status(500).send("Internal Server Problem");
  }
});

// LOGIN
app.post("/login", async (req, res) => {
  let users = await loadFile("user.json");
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: "Please enter the required fields" });
  }

  try {
    const currentUser = users.find(
      (index) => index.username === username && index.password === password
    );

    if (currentUser) {
      const JWT_SECRET = process.env.JWT_SECRET;
      if (!JWT_SECRET) {
        return res
          .status(500)
          .json({ error: "JWT Secret is missing in env file" }); // ✅ FIX: Check for missing JWT_SECRET
      }

      const token = jwt.sign({ userid: currentUser.userid }, JWT_SECRET);
      return res.status(200).json({ message: "User found", token: token });
    } else {
      return res.status(401).json({ error: "Invalid username or password" }); // ✅ FIX: Changed from res.json() to proper 401 Unauthorized
    }
  } catch (error) {
    return res.status(500).json({ error: "INTERNAL SERVER ERROR" });
  }
});

// AUTHORIZATION MIDDLEWARE
function authorization(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Unauthorized: No Token" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userid = decoded.userid;
    next();
  } catch (error) {
    return res.status(400).json({ error: "Invalid Token" });
  }
}
