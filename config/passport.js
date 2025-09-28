const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const User = require('../models/User');

passport.use(new LocalStrategy(
  async (username, password, done) => {
    const user = await User.findOne({ username });
    if (!user) return done(null, false);
    const isValid = await bcrypt.compare(password, user.password);
    return isValid ? done(null, user) : done(null, false);
  }
));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

// Function to deserialize the JWT and return the user object
const deserializeJWT = async (token, done) => {
  try {
    const decodedToken = jwt.verify(token, process.env.JWT_SECRET || 'secret');
    const user = await User.findById(decodedToken.id);
    if (!user) {
      return res.status(401).send('Unauthorized');
    }
    done(null, user);
  } catch (err) {
    done(err, false);
  }
};

passport.deserializeUser(deserializeJWT);

module.exports = passport;