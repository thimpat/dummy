const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');

const routesAuth = require('./routes/auth');
const jwt = require('../config/jwt');

const app = express();

app.use(bodyParser.json());
app.use(session({
  secret: process.env.SESSION_SECRET_KEY,
  resave: false,
  saveUninitialized: true
}));

// Passport session setup:
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => User.findById(id, (err, user) => done(err, user)));

app.use(passport.initialize());
app.use(passport.session());

app.use('/auth', routesAuth);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));