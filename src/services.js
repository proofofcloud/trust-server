const fs = require("fs");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const { spawn } = require("child_process");
const config = require("./config");

const state = {
  privateKey: null,
  publicKey: null,
  keyRegistry: {},
  whitelist: [],
  keyId: null
};

function loadSecrets() {
  try {

  if (fs.existsSync(config.PATHS.WHITELIST)) {
    const whitelistRaw = fs.readFileSync(config.PATHS.WHITELIST, "utf8");
    state.whitelist = whitelistRaw
      .split(/\r?\n/)
      .map(line => line.trim())
      .filter(line => line.length > 0 && !line.startsWith('#'))
      .map(line => {
        const [id, label] = line.split(',');
        return { id: id.trim(), label: label ? label.trim() : 'unlabeled' };
      });
    console.log(`✅ Loaded ${state.whitelist.length} whitelist entries.`);
  } else {
    console.warn("⚠️  No whitelist found. All requests will be rejected.");
  }

    if (config.MULTISIG_MODE)
      loadSecrets_Multisig();
    else
      loadSecrets_SingleSigner();

  } catch (err) {
    console.error(err.message);
    process.exit(1);
  }
}

function loadSecrets_SingleSigner() {

  if (!config.PRIVATE_KEY_BASE64) {
    throw new Error("❌ CRITICAL ERROR: PRIVATE_KEY_BASE64 environment variable is not set.");
  }

  try {
    const buffer = Buffer.from(config.PRIVATE_KEY_BASE64, 'base64');
    state.privateKey = buffer.toString('utf-8');
  } catch (e) {
    throw new Error("❌ Failed to decode Base64 private key string.");
  }

  if (!state.privateKey.includes("BEGIN") || !state.privateKey.includes("PRIVATE KEY")) {
      throw new Error("❌ Decoded private key does not look like a valid PEM file.");
  }

  console.log("✅ Private Key loaded and decoded successfully.");

  const pubKeyObject = crypto.createPublicKey(state.privateKey);
  state.publicKey = pubKeyObject.export({ type: "spki", format: "pem" });

  if (fs.existsSync(config.PATHS.KEYS)) {
    const keysRaw = fs.readFileSync(config.PATHS.KEYS, "utf8");
    state.keyRegistry = JSON.parse(keysRaw);

    for (const [kid, keyString] of Object.entries(state.keyRegistry)) {
      if (keyString.replace(/\\n/g, '\n').trim() === state.publicKey.trim()) {
        state.keyId = kid;
        break;
      }
    }
  }

  if (!state.keyId) {
    console.warn("⚠️  WARNING: Private key does not match any ID in keys.json. 'kid' header will be missing.");
  } else {
    console.log(`✅ Key ID identified: ${state.keyId}`);
  }
}

function loadSecrets_Multisig() {

  config.MULTISIG_NONCE_MAP = {};    // key → value
  config.MULTISIG_NONCE_LIST = [];   // FIFO list of keys

  (async () => {
    try {
      const output = await runSss(["info"]);
      const match_moniker = output.match(/Moniker:\s*(\S+)/i);
      if (!match_moniker)
        throw new Error("Moniker not found in SSS tool output");

      const moniker = match_moniker[1];
      console.log(`Multisig Moniker: ${moniker}`);
      config.MULTISIG_MONIKER = moniker;

      const match_pubkey = output.match(/Shared Pubkey\s*=\s*([0-9a-fA-F]+)/);
      if (!match_pubkey)
        throw new Error("Shared Pubkey not found in SSS tool output");

      const pubkey = match_pubkey[1];      
      console.log(`Multisig Pubkey: ${pubkey}`);
      config.MULTISIG_PUBKEY = pubkey;

    } catch (e) {
      console.error(e);
      process.exit(1);
    }
  })();

}

function runSss(args) {
  return new Promise((resolve, reject) => {
    const child = spawn(config.SSS_TOOL, args);

    let stdout = "";
    let stderr = "";

    child.stdout.on("data", (data) => (stdout += data));
    child.stderr.on("data", (data) => (stderr += data));

    child.on("close", (code) => {
      if (code !== 0) {
        return reject(new Error(`SSS tool failed (code ${code}): ${stderr || stdout}`));
      }
      resolve(stdout);
    });

    child.on("error", (err) => reject(new Error(`Failed to spawn ${config.SSS_TOOL}: ${err.message}`)));
  });
}

function runDcapCheck(hexQuote) {
  return new Promise((resolve, reject) => {
    const args = ["check", hexQuote];
    const child = spawn(config.ATTESTER_BIN, args);

    let stdout = "";
    let stderr = "";

    child.stdout.on("data", (data) => (stdout += data));
    child.stderr.on("data", (data) => (stderr += data));

    child.on("close", (code) => {
      if (code !== 0) {
        return reject(new Error(`DCAP tool failed (code ${code}): ${stderr || stdout}`));
      }
      resolve(stdout);
    });

    child.on("error", (err) => reject(new Error(`Failed to spawn ${config.ATTESTER_BIN}: ${err.message}`)));
  });
}

function runSevSnpCheck(hexQuote) {
  return new Promise((resolve, reject) => {
    const args = ["validate", hexQuote];
    const child = spawn("amd-verifier", args);

    let stdout = "";
    let stderr = "";

    child.stdout.on("data", (data) => (stdout += data));
    child.stderr.on("data", (data) => (stderr += data));

    child.on("close", (code) => {
      try {
        const result = JSON.parse(stdout);

        if (result.result != "success") {
            const errorMsg = result.message || stderr || "Unknown verification error";
            return reject(new Error(`AMD Verifier rejected quote: ${errorMsg}`));
        }

        if (!result.chip_id) {
            return reject(new Error("AMD Verifier success but 'chip_id' missing in response"));
        }

        resolve(result.chip_id);

      } catch (e) {
        if (code !== 0) {
            return reject(new Error(`AMD Verifier failed (code ${code}): ${stderr || stdout}`));
        }
        return reject(new Error(`Invalid JSON output from AMD Verifier: ${e.message}`));
      }
    });

    child.on("error", (err) => reject(new Error(`Failed to spawn ${AMD_VERIFIER_BIN}: ${err.message}`)));
  });
}

function normalizeKvJson(inp) {

  if (typeof inp !== "object" || Array.isArray(inp))
    throw new Error("input malformed");

  const keys = Object.keys(inp).sort();  // for deterministic output

  const out = {};
  for (const k of keys) {
    const val = inp[k];

    if (typeof val !== "string")
      throw new Error(`Nonce for '${k}' must be a string`);

    out[k] = val;
  }

  return out;
}

function base64url(input) {
  return Buffer.from(input)
    .toString("base64")      // normal base64
    .replace(/\+/g, "-")     // convert '+' → '-'
    .replace(/\//g, "_")     // convert '/' → '_'
    .replace(/=+$/g, "");    // remove trailing '='
}

async function processQuote(hexQuote, nonces, partial_sigs) {
  if (!/^[0-9a-fA-F]+$/.test(hexQuote)) {
    throw new Error("Invalid quote format: must be hex string");
  }

  const quoteHash = crypto.createHash("sha256").update(Buffer.from(hexQuote, "hex")).digest("hex");

  let machineIdHex;
  
  // TDX quotes are typically larger (> 4KB), SEV-SNP are smaller (~1KB)
  if (hexQuote.length > 8000) { // Approx 4000 bytes * 2 hex chars
      const output = await runDcapCheck(hexQuote);
      const match = output.match(/PPID:\s*([0-9a-fA-F]+)/i);
      if (!match) throw new Error("PPID not found in attestation output");
      machineIdHex = match[1];
  } else {
      machineIdHex = await runSevSnpCheck(hexQuote);
  }

  const machineId = crypto.createHash("sha256").update(Buffer.from(machineIdHex, "hex")).digest("hex");

  const validNode = state.whitelist.find(entry => machineId.startsWith(entry.id));
   
  if (!validNode) {
    console.warn(`⛔ Access Denied: Machine ID ${machineId} is not in whitelist.`);
    throw new Error("Machine is not whitelisted.");
  }

  const payload = { 
    quote_hash: quoteHash,
    machine_id: machineId,
    label: validNode.label
  };

  jwt_token = null;

  if (config.MULTISIG_MODE)
  {
    if (nonces)
    {
      const safe_nonces = normalizeKvJson(nonces);
      const my_nonce_pub = safe_nonces[config.MULTISIG_MONIKER] || null;
      if (!my_nonce_pub)
        throw new Error("my nonce not included");

      const my_nonce_priv = config.MULTISIG_NONCE_MAP[my_nonce_pub];
      if (!my_nonce_priv)
        throw new Error("my nonce not found");

      delete config.MULTISIG_NONCE_MAP[my_nonce_pub]; // important!

      safe_sigs = {};
      if (partial_sigs)
        safe_sigs = normalizeKvJson(partial_sigs);

      const header = { 
        alg: "EdDSA",
        typ: "JWT",
        kid: config.MULTISIG_PUBKEY
      };
      

      const header_b64  = base64url(Buffer.from(JSON.stringify(header), "utf8"));
      const payload_b64 = base64url(Buffer.from(JSON.stringify(payload), "utf8"));
      const signingInput = `${header_b64}.${payload_b64}`;
      const signingInput_hex = Buffer.from(signingInput, "utf8").toString("hex");

      const args = [
        "sign",
        "--pub-nonces",
        JSON.stringify(safe_nonces),
        "--my-nonce",
        my_nonce_priv,
        "--message",
        signingInput_hex,
        "--partial-sigs",
        JSON.stringify(safe_sigs)
      ];
      const output = await runSss(args);
      //console.log(`sss output: ${output}`);

      const match_full_signature = output.match(/^\s*full_signature\s*:\s*([0-9a-fA-F]+)\s*$/m);
      if (!match_full_signature)
      {
        const match_sigs = output.match(/^\s*sigs\s*=\s*(\{.*\})\s*$/m);
        if (!match_sigs) {
          throw new Error("SSS output missing sigs");
        }

        const sigs_obj = JSON.parse(match_sigs[1]);
        return sigs_obj;
      }

      const full_signature = match_full_signature[1];
      const sig_b64 = base64url(Buffer.from(full_signature, "hex"));

      jwt_token = signingInput + "." + sig_b64;

    }
    else
    {
      const output = await runSss(["get-nonce"]);

      const nonce_priv = output.match(/nonce_priv\s*=\s*([A-Za-z0-9+/=]+)/)?.[1] || null;
      const nonce_pub  = output.match(/nonce_pub\s*=\s*([A-Za-z0-9+/=]+)/)?.[1] || null;

      if (!nonce_priv || !nonce_pub)
        throw new Error("failed to get nonce");

      if (config.MULTISIG_NONCE_LIST.length > 20) {
        const key = config.MULTISIG_NONCE_LIST.shift();  // pop_front
        delete config.MULTISIG_NONCE_MAP[key];           // remove from map
      }

      config.MULTISIG_NONCE_LIST.push(nonce_pub);
      config.MULTISIG_NONCE_MAP[nonce_pub] = nonce_priv;

      return { 
        machineId, 
        moniker: config.MULTISIG_MONIKER, 
        nonce: nonce_pub
      };
    }

  }
  else
  {
    jwt_token = jwt.sign(payload, state.privateKey, {
      algorithm: "RS256",
      header: { kid: state.keyId },
    });
  }

  return { 
    machineId, 
    label: validNode.label, 
    jwt: jwt_token
  };

}

async function verifyToken(hexQuote, token) {
  if (!/^[0-9a-fA-F]+$/.test(hexQuote)) {
    throw new Error("Invalid quote format");
  }

  const decoded = jwt.decode(token, { complete: true });
  if (!decoded) throw new Error("Invalid JWT");

  const { kid } = decoded.header;
  const { quote_hash, label } = decoded.payload;

  if (!state.keyRegistry[kid]) throw new Error(`Unknown key-id: ${kid}`);
  const publicKey = state.keyRegistry[kid].replace(/\\n/g, '\n');

  jwt.verify(token, publicKey, { algorithms: ["RS256"] });

  const expectedHash = crypto.createHash("sha256").update(Buffer.from(hexQuote, "hex")).digest("hex");
  if (expectedHash !== quote_hash) {
    throw new Error("Integrity check failed: Quote does not match Token");
  }

  return { valid: true, keyId: kid, label };
}

module.exports = { loadSecrets, processQuote, verifyToken };
