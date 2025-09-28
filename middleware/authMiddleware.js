const jwt = require('jsonwebtoken');

exports.jwtCheck = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) return res.status(403).send({ message: 'Access denied. No token provided.' });

  try {
    const decodedToken = jwt.verify(token, process.env.JWT_SECRET);
    const userId = decodedToken.userId;
    
    // Query the database to find a matching user by ID
    User.findById(userId)
      .then(user => {
        if (!user) return res.status(401).send('User not found');
        
        req.user = user;  // Assign the user object to request's user property for further use in routes or controllers.
        next(); // Continue with the route handler
      })
      .catch(error => res.status(500).send(error));
  } catch (error) {
    return res.status(401).send('Token is invalid');
  }
};