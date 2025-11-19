const express = require("express");
const app = express();
const mongoose = require("mongoose");
const authRoutes = require("./routes/auth");
const path = require("path");

// MIDDLEWARE
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// STATIC FILES
app.use(express.static("public"));

// VIEW ENGINE
app.set("view engine", "ejs");

// MONGO CONNECT
mongoose
  .connect(process.env.MONGO_URL)
  .then(() => console.log("MongoDB Connected"))
  .catch(err => console.log(err));

// ROUTES
app.use("/", authRoutes);

// HOME PAGE
app.get("/", (req, res) => {
  res.render("index");
});

// SERVER
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log("Server running on port " + PORT));
