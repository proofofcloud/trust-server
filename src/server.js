const express = require("express");
const fs = require("fs");
const https = require("https");
const http = require("http");
const config = require("./config");
const { loadSecrets, processQuote, checkQuote, verifyToken } = require("./services");

const app = express();
app.use(express.json());

// Handler Wrapper for consistent error handling
const asyncHandler = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

app.post(
  "/get_jwt",
  asyncHandler(async (req, res) => {
    const { quote, timestamp, nonces, partial_sigs } = req.body;
    const result = await processQuote(quote, timestamp, nonces, partial_sigs);
    res.json(result);
  }),
);

app.post(
  "/check_quote",
  asyncHandler(async (req, res) => {
    const { quote } = req.body;
    const result = await checkQuote(quote);
    res.json(result);
  }),
);

app.post(
  "/verify_token",
  asyncHandler(async (req, res) => {
    const { quote, jwt: token } = req.body;
    if (!quote || !token) {
      return res.status(400).json({ error: "Missing quote or jwt" });
    }

    const result = await verifyToken(quote, token);
    res.json(result);
  }),
);

// Global Error Handler
app.use((err, req, res, next) => {
  console.error(`Error processing request: ${err.message}`);
  const isDenial =
    err.message.includes("not whitelisted") ||
    err.message.includes("was revoked on");
  const status = isDenial ? 403 : 500;
  res.status(status).json({ error: err.message });
});

app.get("/", (_, res) => res.send("SGX DCAP Web Service Ready"));

async function startServer() {
  console.log("Initializing Trust Server...");
  await loadSecrets();

  if (config.HTTPS_ENABLED) {
    if (!config.HTTPS_KEY_PATH || !config.HTTPS_CERT_PATH) {
      throw new Error(
        "HTTPS_KEY_PATH and HTTPS_CERT_PATH must be set when HTTPS_ENABLED is true.",
      );
    }

    const options = {
      key: fs.readFileSync(config.HTTPS_KEY_PATH),
      cert: fs.readFileSync(config.HTTPS_CERT_PATH),
    };

    https.createServer(options, app).listen(config.PORT, () => {
      console.log(`Server listening on https://localhost:${config.PORT}`);
    });
  } else {
    http.createServer(app).listen(config.PORT, () => {
      console.log(`Server listening on http://localhost:${config.PORT}`);
    });
  }
}

startServer().catch((err) => {
  console.error("Failed to start server:", err);
  process.exit(1);
});
