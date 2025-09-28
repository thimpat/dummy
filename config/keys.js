const jwtSecret = process.env.JWT_SECRET || 'your_jwt_secret_here';
const accessTokenSecret = process.env.ACCESS_TOKEN_SECRET || 'access_token_secret';

module.exports = {
  JWT_SECRET: jwtSecret,
  ACCESS_TOKEN_SECRET: accessTokenSecret
};