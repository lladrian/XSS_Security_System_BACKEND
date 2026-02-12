import express from "express";
import mongoose from "mongoose";
import cookieParser from "cookie-parser";
import cors from "cors";
import dotenv from "dotenv";
import authRoutes from "./routes/auth.js";

dotenv.config();
const app = express();

// Middleware
app.use(express.json());
app.use(cookieParser());
// app.use(cors({
//   origin: "http://localhost:3000", // your React frontend
//   credentials: true, // important for cookies
// }));

app.use(cors({
  origin: (origin, callback) => callback(null, true),
  // origin: '*',  // for open access, but can't use credentials:true with '*'
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

// Routes
app.use("/api/auth", authRoutes);

// Connect DB and start server
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB connected"))
  .catch(err => console.log(err));

app.listen(5000, () => console.log("Server running on 5000"));
