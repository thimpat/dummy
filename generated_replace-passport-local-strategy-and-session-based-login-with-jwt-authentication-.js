/**
 * @module jwtAuth
 * @description JWT authentication middleware for Express.js
 */

const express = require('express');
const jwt = require('jsonwebtoken');
const User = require('./User'); // Import the updated User model
const bcrypt = require('bcryptjs');

/**
 * Login route to generate JWT token and send response
 *
 * @param {Express.Request} req - Request object
 * @param {Express.Response} res - Response object
 */
exports.login = async (req, res) => {
  const email = req.body.email;
  const password = req.body.password;

  const user = await User.findOne({ email }).exec();

  if (!user) return res.status(401).send('Unauthorized');

  const isPasswordValid = await bcrypt.compare(password, user.password);

  if (!isPasswordValid) return res.status(401).send('Unauthorized');

  const token = jwt.sign({ id: user._id }, process.env.SECRET_KEY, { expiresIn: '1h' });
  res.json({ token }); // Change the response format to JSON
};
/**
 * @module mainRouter
 * @description Main router for Express.js
 */

const express = require('express');
const app = express();
const jwtAuth = require('./jwtAuth'); // Import the JWT authentication middleware

app.use(express.json());

// Define protected routes
const protectedRoutes = ['/home', '/api/data'];

// Define login route with Passport Local strategy and JWT middleware
app.post('/login', passport.authenticate('local'), async (req, res) => {
  // ... Your code here to handle JWT token generation and send response
});

// Protect routes with JWT middleware
protectedRoutes.forEach((route) => {
  app.use(`/${route}`, authCheck); // Use the JWT middleware for each protected route
});
/**
 * @module authCheck
 * @description JWT authentication middleware for Express.js
 */

const express = require('express');
const jwt = require('jsonwebtoken');

// Create a new router instance
const authCheck = express.Router();

/**
 * JWT middleware to check for the presence of a valid token in the request headers
 *
 * @param {Express.Request} req - Request object
 * @param {Express.Response} res - Response object
 */
authCheck.use((req, res, next) => {
  const token = req.header('x-auth-token');

  if (!token) return res.status(401).send('Access denied. No token provided.');

  jwt.verify(token, process.env.SECRET_KEY, (err, decoded) => {
    if (err) return res.status(500).send('Invalid token.');

    req.user = decoded;
    next();
  });
});