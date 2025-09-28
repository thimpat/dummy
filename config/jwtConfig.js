const crypto = require('crypto');

exports.JWT_SECRET = process.env.JWT_SECRET || 'YourSecretKeyHere'; // Replace with your secret key

// Example environment variable names for JWT secrets:
// - JWT_SECRET
// - AUTH_JWT_SECRET (for authentication-specific tokens)