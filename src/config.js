require("dotenv").config();
const path = require("path");

module.exports = {
  PORT: process.env.PORT || 8080,

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
