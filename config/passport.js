const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const jwt = require('jsonwebtoken');
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

// JWT strategy
passport.use(new jwt.Strategy(
  async (token, done) => {
    try {
      const user = await User.findById(token.userId);
      if (!user) return done(null, false);
      done(null, user);
    } catch (error) {
      done(error, false);
    }
  }
));

module.exports = passport;