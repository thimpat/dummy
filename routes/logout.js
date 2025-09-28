const express = require('express');
const router = express.Router();

router.post('/', ensureAuthenticated, (req, res) => {
  req.logout(); // Assuming you have a logout function defined in your session or middleware layer

  res.send({ message: 'Logout successful' });
});

module.exports = router;