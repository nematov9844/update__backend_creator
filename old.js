const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");

dotenv.config();
const app = express();

// CORS sozlamalarini aniqlash
app.use(cors({
    origin: "*",  // Barcha domenlardan kelgan so'rovlarga ruxsat berish
    methods: ["GET", "POST", "PUT", "DELETE"],  // Ruxsat berilgan metodlar
    allowedHeaders: ["Content-Type", "Authorization"]  // Ruxsat berilgan header'lar
}));

app.use(express.json()); // express.json() body-parser o‘rniga

const PORT = process.env.PORT || 5000;

let users = [];  // Foydalanuvchilarni saqlash uchun massiv
let data = [];   // Itemlar ro'yxati
let currentId = 1;

// JWT tokenni tekshirish middleware'i
const authenticateToken = (req, res, next) => {
  const token = req.headers["authorization"]?.split(" ")[1];  // Bearer tokenni olish
  if (!token) return res.status(401).json({ error: "Token required" });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "Invalid token" });
    req.user = user; // Tokenni to‘g‘ri bo‘lsa, foydalanuvchini qo‘shish
    next();  // So‘rovni davom ettirish
  });
};

// Admin yoki Creator bo'lgan foydalanuvchilarni tekshirish
const checkRole = (roles) => {
  return (req, res, next) => {
    const { role } = req.user; // Userning roli
    if (!roles.includes(role)) {
      return res.status(403).json({ error: "Access denied" });
    }
    next();
  };
};

// Register endpointini o'zgartirish
app.post("/register", (req, res) => {
  const { username, password, role } = req.body;
  if (!username || !password || !role) {
    return res.status(400).json({ error: "Username, password, and role are required" });
  }

  // Foydalanuvchi borligini tekshirish
  const existingUser = users.find((user) => user.username === username);
  if (existingUser) {
    return res.status(400).json({ error: "Username already exists" });
  }

  // Yangi foydalanuvchi qo'shish
  const newUser = { username, password, role };
  users.push(newUser);

  // Token yaratish
  const token = jwt.sign({ username, role }, process.env.JWT_SECRET, {
    expiresIn: "1h",
  });

  return res.json({ status: "success", token, user: newUser });
});

// Login endpointi
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username && u.password === password);
  
  if (user) {
    const token = jwt.sign({ username: user.username, role: user.role }, process.env.JWT_SECRET, { expiresIn: "1h" });
    return res.json({ status: "success", token });
  }
  return res.status(401).json({ error: "Invalid credentials" });
});

// Usersni olish endpointi (Admin uchun)
app.get("/users", authenticateToken, checkRole(["admin"]), (req, res) => {
  res.json(users);
});

// Items yaratish endpointi (Creator va Admin uchun)
app.post("/items", authenticateToken, checkRole(["admin", "creator"]), (req, res) => {
  const { name, description } = req.body;
  const newItem = { id: currentId++, name, description, createdBy: req.user.username };
  data.push(newItem);
  res.status(201).json({ message: "Item created", item: newItem });
});

// Itemsni olish endpointi (Barchaga)
app.get("/items", authenticateToken, (req, res) => {
  res.json(data);
});

// Itemni yangilash endpointi (Admin va Creator uchun)
app.put("/items/:id", authenticateToken, checkRole(["admin", "creator"]), (req, res) => {
  const { id } = req.params;
  const { name, description } = req.body;
  const itemIndex = data.findIndex((item) => item.id == id);

  if (itemIndex === -1) return res.status(404).json({ error: "Item not found" });

  // Faqat admin yoki creator o'zgartirishga ruxsat berilgan
  if (data[itemIndex].createdBy !== req.user.username && req.user.role !== "admin") {
    return res.status(403).json({ error: "You are not allowed to update this item" });
  }

  data[itemIndex] = { id: Number(id), name, description, createdBy: data[itemIndex].createdBy };
  res.json({ message: "Item updated", item: data[itemIndex] });
});

// Itemni o'chirish endpointi (Admin va Creator uchun)
app.delete("/items/:id", authenticateToken, checkRole(["admin", "creator"]), (req, res) => {
  const { id } = req.params;
  const itemIndex = data.findIndex((item) => item.id == id);

  if (itemIndex === -1) return res.status(404).json({ error: "Item not found" });

  // Faqat admin yoki creator o'chirishga ruxsat berilgan
  if (data[itemIndex].createdBy !== req.user.username && req.user.role !== "admin") {
    return res.status(403).json({ error: "You are not allowed to delete this item" });
  }

  data.splice(itemIndex, 1);
  res.json({ message: "Item deleted" });
});

// Serverni ishga tushurish
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
