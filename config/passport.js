const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const jwt = require('jsonwebtoken');
const User = require('../models/User');

// Initialize PassportJS and strategies
passport.use(new LocalStrategy(async (username, password, done) => {
  try {
    const user = await User.findOne({ username });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return done(null, false);
    }

    const token = jwt.sign(
      { userId: user.id },
      'your_secret_key', // Use a secure secret key
      { expiresIn: '2h' }
    );

    return done(null, user, { token });
  } catch (error) {
    return done(null, false, error.message);
  }
}));

// Serializes the JWT payload to be used in the request object
passport.serializeUser((user, done) => {
  done(null, user.id);
});

// Deserializes the JWT token from the request headers
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (error) {
    done(error);
  }
});