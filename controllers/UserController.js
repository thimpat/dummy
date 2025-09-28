const User = require('./models/User');

exports.getUserByUsername = async (username) => {
  return await User.findByUsername(username);
};
exports.createUser = async (userObject) => {
  const user = new User(userObject);
  await user.save();
  return user;
};

// Additional methods like find, update, delete can be added here.