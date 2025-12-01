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
    if (!fs.existsSync(config.PATHS.PRIVATE_KEY)) {
      throw new Error(`Private key not found at ${config.PATHS.PRIVATE_KEY}. \nHint: Set PRIVATE_KEY_PATH env var or place jwt_key.pem in the src dir.`);
    }
    state.privateKey = fs.readFileSync(config.PATHS.PRIVATE_KEY, "utf8");

    const pubKeyObject = crypto.createPublicKey(state.privateKey);
    state.publicKey = pubKeyObject.export({ type: "spki", format: "pem" });

    if (fs.existsSync(config.PATHS.WHITELIST)) {
      const whitelistRaw = fs.readFileSync(config.PATHS.WHITELIST, "utf8");
      
      state.whitelist = whitelistRaw
        .split(/\r?\n/)
        .map(line => line.trim())
        .filter(line => line.length > 0 && !line.startsWith('#')) // Skip empty lines & comments
        .map(line => {
          const [id, label] = line.split(',');
          return { 
            id: id.trim(), 
            label: label ? label.trim() : 'unlabeled-node' 
          };
        });
        
      console.log(`✅ Loaded ${state.whitelist.length} whitelisted nodes.`);
    } else {
      console.warn("⚠️  No whitelist found. All machine IDs will be rejected.");
      state.whitelist = [];
    }

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
      console.warn("⚠️  WARNING: The loaded private key does not match any public key in keys.json. Tokens will be signed, but 'kid' header will be missing.");
    } else {
      console.log(`✅ Secrets loaded. Using Key ID: ${state.keyId}`);
    }

  } catch (err) {
    console.error("❌ Failed to load configuration:", err.message);
    process.exit(1);
  }
}

function runDcapCheck(hexQuote) {
  return new Promise((resolve, reject) => {
    const args = ["run", "--rm", config.ATTESTER_IMAGE, "check", hexQuote];
    const child = spawn("docker", args);

    let stdout = "";
    let stderr = "";

    child.stdout.on("data", (data) => (stdout += data));
    child.stderr.on("data", (data) => (stderr += data));

    child.on("close", (code) => {
      if (code !== 0) {
        return reject(new Error(`DCAP tool failed (code ${code}): ${stderr}`));
      }
      resolve(stdout);
    });

    child.on("error", (err) => reject(err));
  });
}

async function processQuote(hexQuote) {
  if (!/^[0-9a-fA-F]+$/.test(hexQuote)) {
    throw new Error("Invalid quote format: must be hex string");
  }

  const quoteHash = crypto.createHash("sha256").update(Buffer.from(hexQuote, "hex")).digest("hex");

  const output = await runDcapCheck(hexQuote);

  const match = output.match(/PPID:\s*([0-9a-fA-F]+)/);
  if (!match) throw new Error("PPID not found in attestation output");
  const ppidHex = match[1];

  const machineId = crypto.createHash("sha256").update(Buffer.from(ppidHex, "hex")).digest("hex");

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

  const token = jwt.sign(payload, state.privateKey, {
    algorithm: "RS256",
    header: { kid: state.keyId },
    expiresIn: "1h" // Good practice: Add expiration
  });

  return { 
    machineId, 
    label: validNode.label, 
    jwt: token 
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
