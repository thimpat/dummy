const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const User = require('../models/User');
const bcrypt = require('bcrypt');

/**
 * Configures the local authentication strategy.
 * @param {function} callback - The callback function.
 */
passport.use(new LocalStrategy(
  async (username, password, done) => {
    const user = await User.findOne({ username });
    if (!user) return done(null, false);
    const isValid = await bcrypt.compare(password, user.password);
    return isValid ? done(null, user) : done(null, false);
  }
));

/**
 * Serializes the user object to store in the session.  Not used with JWT.
 * @param {object} user - The user object.
 * @param {function} done - The callback function.
 */
passport.serializeUser((user, done) => done(null, user.id));

/**
 * Deserializes the user object from the session.  Not used with JWT.
 * @param {string} id - The user ID.
 * @param {function} done - The callback function.
 */
passport.deserializeUser((id, done) => User.findById(id).then(user => done(null, user)));