const express = require("express");
const router = express.Router();
const User = require("../models/User");
const bcrypt = require("bcrypt");

// SIGNUP PAGE
router.get("/signup", (req, res) => {
    res.render("signup");
});

// SIGNUP POST
router.post("/signup", async (req, res) => {
    const { name, email, password } = req.body;

    const hash = await bcrypt.hash(password, 10);

    const user = new User({ name, email, password: hash });
    await user.save();

    res.redirect("/login");
});

// LOGIN PAGE
router.get("/login", (req, res) => {
    res.render("login");
});

// LOGIN POST
router.post("/login", async (req, res) => {
    const { email, password } = req.body;

    const user = await User.findOne({ email });

    if (!user) return res.send("User not found");

    const match = await bcrypt.compare(password, user.password);

    if (!match) return res.send("Wrong password");

    res.redirect("/dashboard");
});

// DASHBOARD
router.get("/dashboard", (req, res) => {
    res.render("dashboard");
});

module.exports = router;
