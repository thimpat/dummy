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

// PATCHED: Configure Passport with new JWT strategy
/**
 * Extracts the JSON Web Token (JWT) from the request cookies.
 *
 * @param {Object} req - The HTTP request object
 * @returns {(string|null)} The extracted JWT token or null if not found
 */
function extractJwt(req) {
  const token = req?.cookies?.token;
  return token ? token : null;
}

/**
 * Passport.js strategy for JSON Web Token (JWT) authentication.
 *
 * @param {Object} options - Options for the strategy
 * @param {(jwt_payload: Object, done: function) => void} verifyCallback - The callback to verify the user
 */
passport.use(new JWTStrategy({
  /**
   * Extracts the JWT token from the request cookies.
   *
   * @param {Object} req - The HTTP request object
   * @returns {(string|null)} The extracted JWT token or null if not found
   */
  jwtFromRequest: extractJwt,
  secretOrKey: 'your_secret'
}, async (jwt_payload, done) => {
  // Your implementation for verifying the user and callback logic
}));

/**
 * Login route to authenticate users and generate JSON Web Token (JWT) tokens.
 *
 * @param {Object} req - The HTTP request object
 * @param {Object} res - The HTTP response object
 */
router.post('/login', async (req, res) => {
  const user = await User.findOne({ username: req.body.username });
  // Your implementation for checking the user's credentials

  if (user) {
    /**
     * Generates a JSON Web Token (JWT) token using the provided secret.
     *
     * @param {string} payload - The payload of the JWT token
     * @param {string} secret - The secret or key to sign the token
     * @param {(expiresIn: string) => void} options - Options for the token expiration
     */
    const token = jsonwebtoken.sign({ id: user._id }, 'your_secret', { expiresIn: '24h' });
    res.cookie('token', token);
    return res.json({ message: 'Logged in successfully!' });
  } else {
    return res.status(401).send('Invalid username or password');
  }
});