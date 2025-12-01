require('dotenv').config();
const path = require('path');

module.exports = {
  PORT: process.env.PORT || 8080,
  ATTESTER_IMAGE: "ghcr.io/proofofcloud/attester@sha256:856659bea241a70de6fc1e7524b84c74d58e2b04a8bf815c87055026ccbf4254",
  
  PRIVATE_KEY: process.env.PRIVATE_KEY,

  PATHS: {
    KEYS: path.join(__dirname, "keys.json"),
    WHITELIST: path.join(__dirname, "whitelist.csv")
  }
};
