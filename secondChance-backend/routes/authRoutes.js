const express = require("express");
const router = express.Router();
const connectToDatabase = require("../models/db");
const logger = require("../logger");
const bcryptjs = require("bcryptjs");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");

dotenv.config();

const JWT_SECRET = process.env.JWT_SECRET;

router.post("/register", async (req, res) => {
  try {
    // Task 1: Connect to `secondChance` in MongoDB through `connectToDatabase` in `db.js`.
    const db = await connectToDatabase();
    // Task 2: Access MongoDB `users` collection
    const collection = db.collection("users");
    // Task 3: Check if user credentials already exists in the database and throw an error if they do
    const existingEmail = await collection.findOne({ email: req.body.email });
    if (existingEmail) {
      logger.error("Email id already exists");
      return res.status(400).json({ error: "Email if alreay exists" });
    }
    // Task 4: Create a hash to encrypt the password so that it is not readable in the database
    const salt = await bcryptjs.genSalt(10);
    const hash = await bcryptjs.hash(req.body.password, salt);
    // Task 5: Insert the user into the database
    const newUser = await collection.insertOne({
      email: req.body.email,
      firstName: req.body.firstName,
      lastName: req.body.lastName,
      password: hash,
      createAt: new Date(),
    });
    // Task 6: Create JWT authentication if passwords match with user._id as payload
    const payload = {
      user: {
        id: newUser.insertedId,
      },
    };
    const authtoken = jwt.sign(payload, JWT_SECRET);
    // Task 7: Log the successful registration using the logger
    logger.info("User registered successfully");
    // Task 8: Return the user email and the token as a JSON
    res.json({ authtoken, email: req.body.email });
  } catch (e) {
    return res.status(500).send("Internal server error");
  }
});

router.post("/login", async (req, res) => {
  try {
    // Task 1: Connect to `secondChance` in MongoDB through `connectToDatabase` in `db.js`.
    const db = await connectToDatabase();
    // Task 2: Access MongoDB `users` collection
    const collection = db.collection("users");
    // Task 3: Check for user credentials in database
    const theUser = await collection.findOne({ email: req.body.email });
    // Task 4: Check if the password matches the encrypted password and send appropriate message on mismatch
    if (theUser) {
      const result = await bcryptjs.compare(
        req.body.password,
        theUser.password
      );
      if (!result) {
        logger.error("Passwords do not match");
        return res.status(404).send({ errpr: "Passwords do not match" });
      }
      const userName = theUser.firstName;
      const userEmail = theUser.email;
      let payload = {
        user: { id: theUser._id.toString() },
      };
      // Task 5: Fetch user details from a database
      // Task 6: Create JWT authentication if passwords match with user._id as payload
      const authtoken = jwt.sign(payload, JWT_SECRET);
      res.json({ authtoken, userName, userEmail });
    } else {
      logger.error("User not found");
      return res.status(404).json({ error: "User not found" });
    }

    // Task 7: Send appropriate message if the user is not found
  } catch (e) {
    logger.error(e);
    return res.status(500).send("Internal server error");
  }
});

/*
curl --location 'http://localhost:3060/api/auth/login' \
--header 'Content-Type: application/json' \
--header 'Cookie: jhub-reverse-tool-proxy=s%3Adf8852e8-fe28-47ac-ab62-cb52fc5bbef5.CxZgc7USbJXpxTv4Vs6BH6esBtnhnYv%2FKQ098HtCm5s' \
--data-raw '{
    "email": "lachie@gmail.com",
    "password": "lac123"
}'
*/

module.exports = router;
