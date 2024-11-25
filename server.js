const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
const fs = require("fs");

dotenv.config();
const app = express();

// CORS sozlamalarini aniqlash
app.use(cors({
  origin: "http://localhost:5173",  // Barcha domenlardan kelgan so'rovlarga ruxsat berish
  methods: ["GET", "POST", "PUT", "DELETE"],  // Ruxsat berilgan metodlar
  allowedHeaders: ["Content-Type", "Authorization"]  // Ruxsat berilgan header'lar
}));

app.use(express.json()); // express.json() body-parser o‘rniga

const dbPath = './db.json';  // JSON fayl manzili
const PORT = process.env.PORT || 5000;

// DBni o'qish
const getDataFromFile = () => {
  const rawData = fs.readFileSync(dbPath);
  return JSON.parse(rawData);
};

// DBga yozish
const writeDataToFile = (data) => {
  fs.writeFileSync(dbPath, JSON.stringify(data, null, 2));
};

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

  const data = getDataFromFile();
  const existingUser = data.users.find((user) => user.username === username);
  if (existingUser) {
    return res.status(400).json({ error: "Username already exists" });
  }

  const newUser = { id: data.users.length + 1, username, password, role };
  data.users.push(newUser);

  // JSON faylini yangilash
  writeDataToFile(data);

  const token = jwt.sign({ username, role }, process.env.JWT_SECRET, {
    expiresIn: "1h",
  });

  return res.json({ status: "success", token, user: newUser });
});

// Login endpointi
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  const data = getDataFromFile();
  const user = data.users.find(u => u.username === username && u.password === password);

  if (user) {
    const token = jwt.sign({ username: user.username, role: user.role }, process.env.JWT_SECRET, { expiresIn: "1h" });
    return res.json({ status: "success", token });
  }
  return res.status(401).json({ error: "Invalid credentials" });
});

// Usersni olish endpointi (Admin uchun)
app.get("/users", authenticateToken, checkRole(["admin"]), (req, res) => {
  const data = getDataFromFile();
  res.json(data.users);
});

// Items yaratish endpointi (Creator va Admin uchun)
app.post("/items", authenticateToken, checkRole(["admin", "creator"]), (req, res) => {
  const { name, description, price, category, quantity, image } = req.body;
  const data = getDataFromFile();

  const newItem = {
    id: data.items.length + 1,
    name,
    description,
    price,
    category,
    quantity,
    image,
    createdBy: req.user.username
  };

  data.items.push(newItem);

  // JSON faylini yangilash
  writeDataToFile(data);

  res.status(201).json({ message: "Item created", item: newItem });
});

// Itemsni olish endpointi (Barchaga)
app.get("/items", authenticateToken, (req, res) => {
  const data = getDataFromFile();
  res.json(data.items);
});

// Itemni yangilash endpointi (Admin va Creator uchun)
app.put("/items/:id", authenticateToken, checkRole(["admin", "creator"]), (req, res) => {
  const { id } = req.params;
  const { name, description, price, category, quantity, image } = req.body;
  const data = getDataFromFile();
  const itemIndex = data.items.findIndex((item) => item.id == id);

  if (itemIndex === -1) return res.status(404).json({ error: "Item not found" });

  // Faqat admin yoki creator o'zgartirishga ruxsat berilgan
  if (data.items[itemIndex].createdBy !== req.user.username && req.user.role !== "admin") {
    return res.status(403).json({ error: "You are not allowed to update this item" });
  }

  data.items[itemIndex] = { id: Number(id), name, description, price, category, quantity, image, createdBy: data.items[itemIndex].createdBy };

  // JSON faylini yangilash
  writeDataToFile(data);

  res.json({ message: "Item updated", item: data.items[itemIndex] });
});

// Itemni o'chirish endpointi (Admin va Creator uchun)
app.delete("/items/:id", authenticateToken, checkRole(["admin", "creator"]), (req, res) => {
  const { id } = req.params;
  const data = getDataFromFile();
  const itemIndex = data.items.findIndex((item) => item.id == id);

  if (itemIndex === -1) return res.status(404).json({ error: "Item not found" });

  // Faqat admin yoki creator o'chirishga ruxsat berilgan
  if (data.items[itemIndex].createdBy !== req.user.username && req.user.role !== "admin") {
    return res.status(403).json({ error: "You are not allowed to delete this item" });
  }

  data.items.splice(itemIndex, 1);

  // JSON faylini yangilash
  writeDataToFile(data);

  res.json({ message: "Item deleted" });
});

// Serverni ishga tushurish
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
