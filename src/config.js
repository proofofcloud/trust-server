require('dotenv').config();
const path = require('path');

module.exports = {
  PORT: process.env.PORT || 8080,
  
  PRIVATE_KEY_BASE64: process.env.PRIVATE_KEY_BASE64,

  PATHS: {
    KEYS: path.join(__dirname, "keys.json"),
    WHITELIST: path.join(__dirname, "whitelist.csv")
  }
};
