const express = require('express');
const session = require('express-session');
const passport = require('passport');
const mongoose = require('mongoose');
const authRoutes = require('./routes/auth');
require('./config/passport');

const app = express();
app.use(express.json());
app.use(session({ secret: 'secret', resave: false, saveUninitialized: false }));
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect('mongodb://localhost:27017/dummy-auth', { useNewUrlParser: true, useUnifiedTopology: true });

app.use('/auth', authRoutes);

app.listen(3000, () => console.log('Server running on port 3000'));