require("dotenv").config();
const path = require("path");

module.exports = {
  PORT: process.env.PORT || 8080,

  HTTPS_ENABLED: process.env.HTTPS_ENABLED === "true",
  HTTPS_KEY_PATH: process.env.HTTPS_KEY_PATH,
  HTTPS_CERT_PATH: process.env.HTTPS_CERT_PATH,

  PRIVATE_KEY_BASE64: process.env.PRIVATE_KEY_BASE64,
  MULTISIG_MODE: process.env.MULTISIG_MODE === "true",

  SSS_TOOL: "sss-tool",
  ATTESTER_BIN: "attester",
  AMD_VERIFIER: "amd-verifier",

  PATHS: {
    KEYS: path.join(__dirname, "keys.json"),
    WHITELIST: path.join(__dirname, "whitelist.csv"),
  },
};
