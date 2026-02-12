import express from "express";
import User from "./../models/User.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

const router = express.Router();

// -------------------- REGISTER --------------------
router.post("/register", async (req, res) => {
  try {
    const { firstName, lastName, email, password } = req.body;

    if(!firstName || !lastName || !email || !password) {
      return res.status(400).json({ message: "Please provide all fields (firstName, lastName, email, password." });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ message: "Email already in use" });

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create new user
    const newUser = await User.create({
      firstName,
      lastName,
      email,
      password: hashedPassword
    });

    // Generate tokens
    const accessToken = jwt.sign({ userId: newUser._id }, process.env.JWT_SECRET, { expiresIn: "15m" });
    const refreshToken = jwt.sign({ userId: newUser._id }, process.env.JWT_REFRESH_SECRET, { expiresIn: "7d" });

    newUser.refreshToken = refreshToken;
    await newUser.save();

    // // Set HttpOnly cookies
    res.cookie("access_token", accessToken, {
      httpOnly: true,
      // secure: process.env.NODE_ENV === "production",
      // sameSite: "Strict",
      // sameSite: "None",
      sameSite: "Lax",
      secure: true,
      maxAge: 15 * 60 * 1000
    });

    res.cookie("refresh_token", refreshToken, {
      httpOnly: true,
      // secure: process.env.NODE_ENV === "production",
      // sameSite: "Strict",
      // sameSite: "None",
      sameSite: "Lax",
      secure: true,
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    res.status(201).json({ message: "Registered and logged in" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// -------------------- LOGIN --------------------
router.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(401).json({ message: "Invalid credentials" });

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(401).json({ message: "Invalid credentials" });

  const accessToken = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: "15m" });
  const refreshToken = jwt.sign({ userId: user._id }, process.env.JWT_REFRESH_SECRET, { expiresIn: "7d" });

  user.refreshToken = refreshToken;
  await user.save();

  res.cookie("access_token", accessToken, {
    httpOnly: true,
    // secure: process.env.NODE_ENV === "production",
    // sameSite: "Strict",
    // sameSite: "None",
    sameSite: "Lax",
    secure: true,
    maxAge: 15 * 60 * 1000
  });

  res.cookie("refresh_token", refreshToken, {
    httpOnly: true,
    //secure: process.env.NODE_ENV === "production",
    //sameSite: "Strict",
    // sameSite: "None",
    sameSite: "Lax",
    secure: true,
    maxAge: 7 * 24 * 60 * 60 * 1000
  });

  res.json({ message: "Logged in" });
});

// -------------------- AUTH CHECK --------------------
router.get("/me", async (req, res) => {
  const token = req.cookies.access_token;
  if (!token) return res.sendStatus(401);

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId).select("-password -refreshToken");
    if (!user) return res.sendStatus(401);
    res.json(user);
  } catch {
    res.sendStatus(401);
  }
});

// -------------------- REFRESH TOKEN --------------------
router.post("/refresh", async (req, res) => {
  const refreshToken = req.cookies.refresh_token;
  if (!refreshToken) return res.sendStatus(401);

  const user = await User.findOne({ refreshToken });
  if (!user) return res.sendStatus(403);

  try {
    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    const newAccessToken = jwt.sign({ userId: decoded.userId }, process.env.JWT_SECRET, { expiresIn: "15m" });

    res.cookie("access_token", newAccessToken, {
      httpOnly: true,
      // secure: process.env.NODE_ENV === "production",
      // sameSite: "Strict",
      // sameSite: "None",
      sameSite: "Lax",
      secure: true,
      maxAge: 15 * 60 * 1000
    });

    res.json({ message: "Token refreshed" });
  } catch {
    res.sendStatus(403);
  }
});

// -------------------- LOGOUT --------------------
router.post("/logout", async (req, res) => {
  const refreshToken = req.cookies.refresh_token;
  if (refreshToken) {
    await User.updateOne({ refreshToken }, { $unset: { refreshToken: "" } });
  }
  res.clearCookie("access_token");
  res.clearCookie("refresh_token");
  res.json({ message: "Logged out" });
});

export default router;
