const jwt = require('jsonwebtoken');

exports.checkAuth = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.toLowerCase().startsWith('bearer ');

  if (!token) return res.status(401).send('Unauthorized');
  
  try {
    const decoded = jwt.verify(token.substring(7), process.env.JWT_SECRET);
    req.authToken = token;
    req.user = decoded.id;
    next();
  } catch (error) {
    res.status(500).send('Server error');
  }
};