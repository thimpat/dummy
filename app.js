const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');

// Initialize PassportJS
require('./config/passport')(passport);

const app = express();

app.use(bodyParser.json());
app.use('/auth', require('./routes/auth'));

mongoose.connect('mongodb://localhost:27017/mydatabase', { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => {
    console.log('Connected to MongoDB');
  })
  .catch((error) => {
    console.error('Could not connect to MongoDB:', error);
  });

app.listen(3000, () => {
  console.log('Server is running on port 3000');
});