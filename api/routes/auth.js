const router = require("express").Router();
const User = require("../models/User");
const CryptoJS = require("crypto-js");
const jwt = require("jsonwebtoken");

// REGISTER
router.post("/register", async (req, res) => {
  const { username, email, password } = req.body;

  // Check if the username or email already exist in the database
  const existingUser = await User.findOne({ $or: [{ username }, { email }] });
  if (existingUser) {
    return res.status(409).json({ message: "Username or email already exists." });
  }

  // Encrypt the password before saving it
  const encryptedPassword = CryptoJS.AES.encrypt(
    password,
    process.env.PASS_SEC
  ).toString();

  const newUser = new User({
    username,
    email,
    password: encryptedPassword,
  });

  try {
    const savedUser = await newUser.save();
    res.status(201).json({ message: "User registered successfully." });
  } catch (err) {
    res.status(500).json({ message: "Failed to register user.", error: err });
  }
});

// LOGIN
router.post("/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    // Find the user in the database
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({ message: "Wrong credentials." });
    }

    // Decrypt the saved password and check if it matches the provided password
    const decryptedPassword = CryptoJS.AES.decrypt(
      user.password,
      process.env.PASS_SEC
    ).toString(CryptoJS.enc.Utf8);

    if (decryptedPassword !== password) {
      return res.status(401).json({ message: "Wrong credentials." });
    }

    // Generate JWT token for authentication
    const accessToken = jwt.sign(
      {
        id: user._id,
        isAdmin: user.isAdmin,
      },
      process.env.JWT_SEC,
      { expiresIn: "3d" }
    );

    const { password: _, ...others } = user._doc;
    res.status(200).json({ ...others, accessToken });
  } catch (err) {
    res.status(500).json({ message: "Failed to log in.", error: err });
  }
});

module.exports = router;
