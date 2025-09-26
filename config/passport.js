const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const User = require('../models/User');
const bcrypt = require('bcrypt');

passport.use(new LocalStrategy(
  async (username, password, done) => {
    const user = await User.findOne({ username });
    if (!user) return done(null, false);
    const isValid = await bcrypt.compare(password, user.password);
    return isValid ? done(null, user) : done(null, false);
  }
));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => User.findById(id).then(user => done(null, user)));

// PATCHED: Update passport.js file to remove session support
// auth.js
/**
 * @fileoverview
 * This file contains functions for handling authentication and generating JWT tokens.
 */

const express = require('express');
const router = express.Router();
const passport = require('passport');
const jwt = require('jsonwebtoken');

const User = require('../models/user'); // Assuming a 'User' model exists

// Step 3: Create a function to generate a JWT for successful login attempts
router.post('/login', passport.authenticate('local', {
    /**
     * @description
     * Success callback after successful authentication.
     *
     * @param {Object} req - The request object.
     * @param {Object} res - The response object.
     */
    successFunction: (req, res) => {
        const user = req.user; // User object returned by Passport Local Strategy
        const payload = { id: user._id };

        /**
         * @description
         * Generate a JSON Web Token (JWT) with the provided secret key and payload.
         *
         * @param {string} payload - The payload to be signed into a JWT.
         * @param {string} secretKey - The secret key used for signing the token.
         * @param {Object} options - Options for generating the JWT, including 'expiresIn'.
         */
        const token = jwt.sign(payload, 'your-secret-key', { expiresIn: '1h' });
        res.json({ token });
    },
    failureRedirect: '/auth/login-failed'
}));

// Step 4: Modify the `/home` route to verify and authenticate the JWT token
router.get('/home', (req, res, next) => {
    const token = req.headers['x-access-token'];
    if (!token) return res.status(401).send('No token provided.');

    /**
     * @description
     * Verify a JSON Web Token (JWT) with the provided secret key.
     *
     * @param {string} token - The JWT to be verified.
     * @param {string} secretKey - The secret key used for verifying the token.
     * @callback {(err: Error, decoded: Object) => void} callback - A callback function called after verification is complete.
     */
    jwt.verify(token, 'your-secret-key', (err, decoded) => {
        if (err) return res.status(500).send({ error: 'Invalid Token.' });

        User.findById(decoded.id, (err, user) => {
            if (err) return next(err);

            /**
             * @description
             * Assign the authenticated user to `req.user`.
             *
             * @param {Object} user - The user object.
             */
            req.user = user; // Assign the authenticated user to `req.user`
            res.send('Welcome!');
        });
    });
});

// Step 5: Update the `passport.js` file to remove session support
/**
 * @fileoverview
 * This file contains Passport.js configuration for authentication.
 */

passport.serializeUser((user, done) => {
    /**
     * @description
     * Serialize the user data by returning only the user's id.
     *
     * @param {Object} user - The user object.
     * @param {(err: Error, id: any) => void} done - A callback function called after serialization is complete.
     */
    done(null, user._id); // Serialize to only the user's id
});

passport.deserializeUser((id, done) => {
    /**
     * @description
     * Deserialize the user data by finding the user with the provided id.
     *
     * @param {any} id - The id of the user to be deserialized.
     * @param {(err: Error, user: Object) => void} done - A callback function called after deserialization is complete.
     */
    User.findById(id).then(user => done(null, user));
});