const express = require("express");
const config = require("./config");
const { loadSecrets, processQuote, verifyToken } = require("./services");

const app = express();
app.use(express.json());

loadSecrets();

// Handler Wrapper for consistent error handling
const asyncHandler = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

app.post("/get_jwt", asyncHandler(async (req, res) => {
  const { quote, nonces, partial_sigs } = req.body;
  if (!quote) return res.status(400).json({ error: "Missing 'quote'" });

  const result = await processQuote(quote, nonces, partial_sigs);
  res.json(result);
}));

app.post("/verify_token", asyncHandler(async (req, res) => {
  const { quote, jwt: token } = req.body;
  if (!quote || !token) {
    return res.status(400).json({ error: "Missing quote or jwt" });
  }

  const result = await verifyToken(quote, token);
  res.json(result);
}));

// Global Error Handler
app.use((err, req, res, next) => {
  console.error(`Error processing request: ${err.message}`);
  const status = err.message.includes("not whitelisted") ? 403 : 500;
  res.status(status).json({ error: err.message });
});

app.get("/", (_, res) => res.send("SGX DCAP Web Service Ready"));

app.listen(config.PORT, () => {
  console.log(`Listening on http://localhost:${config.PORT}`);
});
