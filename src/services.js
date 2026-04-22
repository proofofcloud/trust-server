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
  keyId: null,
  multisig: {
    moniker: null,
    sharedPublicKey: null,
    nonceMap: {},
    nonceList: [],
  },
};

function execCommand(command, args) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args);
    let stdout = "";
    let stderr = "";

    child.stdout.on("data", (data) => (stdout += data));
    child.stderr.on("data", (data) => (stderr += data));

    child.on("close", (code) => {
      if (code !== 0) {
        const errorDetails = stderr || stdout || "No output";
        return reject(
          new Error(`${command} failed (code ${code}): ${errorDetails}`),
        );
      }
      resolve(stdout);
    });

    child.on("error", (err) => {
      reject(new Error(`Failed to spawn ${command}: ${err.message}`));
    });
  });
}

async function loadSecrets() {
  try {
    if (fs.existsSync(config.PATHS.WHITELIST)) {
      const whitelistRaw = fs.readFileSync(config.PATHS.WHITELIST, "utf8");
      state.whitelist = whitelistRaw
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter((line) => line.length > 0 && !line.startsWith("#"))
        .map((line) => {
          const [id, label] = line.split(",");
          return { id: id.trim(), label: label ? label.trim() : "unlabeled" };
        });
      console.log(`✅ Loaded ${state.whitelist.length} whitelist entries.`);
    } else {
      console.warn("⚠️  No whitelist found. All requests will be rejected.");
    }

    if (config.MULTISIG_MODE) {
      await loadSecrets_Multisig();
    } else {
      loadSecrets_SingleSigner();
    }
  } catch (err) {
    console.error(err.message);
    process.exit(1);
  }
}

function loadSecrets_SingleSigner() {
  if (!config.PRIVATE_KEY_BASE64) {
    throw new Error(
      "❌ CRITICAL ERROR: PRIVATE_KEY_BASE64 environment variable is not set.",
    );
  }

  try {
    const buffer = Buffer.from(config.PRIVATE_KEY_BASE64, "base64");
    state.privateKey = buffer.toString("utf-8");
  } catch (e) {
    throw new Error("Failed to decode Base64 private key string.");
  }

  if (
    !state.privateKey.includes("BEGIN") ||
    !state.privateKey.includes("PRIVATE KEY")
  ) {
    throw new Error(
      "❌ Decoded private key does not look like a valid PEM file.",
    );
  }

  console.log("✅ Private Key loaded and decoded successfully.");

  const pubKeyObject = crypto.createPublicKey(state.privateKey);
  state.publicKey = pubKeyObject.export({ type: "spki", format: "pem" });

  if (fs.existsSync(config.PATHS.KEYS)) {
    const keysRaw = fs.readFileSync(config.PATHS.KEYS, "utf8");
    state.keyRegistry = JSON.parse(keysRaw);

    for (const [kid, keyString] of Object.entries(state.keyRegistry)) {
      if (keyString.replace(/\\n/g, "\n").trim() === state.publicKey.trim()) {
        state.keyId = kid;
        break;
      }
    }
  }

  if (!state.keyId) {
    console.warn(
      "⚠️  WARNING: Private key does not match any ID in keys.json. 'kid' header will be missing.",
    );
  } else {
    console.log(`✅ Key ID identified: ${state.keyId}`);
  }
}

async function loadSecrets_Multisig() {
  state.multisig.nonceMap = {}; // key → value
  state.multisig.nonceList = []; // FIFO list of keys

  try {
    const output = await runSss(["info"]);

    const match_moniker = output.match(/Moniker:\s*(\S+)/i);
    if (!match_moniker) throw new Error("Moniker not found in SSS tool output");
    state.multisig.moniker = match_moniker[1];
    console.log(`Multisig Moniker: ${state.multisig.moniker}`);

    const match_pubkey = output.match(/Shared Pubkey\s*=\s*([0-9a-fA-F]+)/);
    if (!match_pubkey)
      throw new Error("Shared Pubkey not found in SSS tool output");
    state.multisig.sharedPublicKey = match_pubkey[1];
    console.log(`Multisig Pubkey: ${state.multisig.sharedPublicKey}`);
  } catch (e) {
    throw new Error(`Multisig init failed: ${e.message}`);
  }
}

function runSss(args) {
  return execCommand(config.SSS_TOOL, args);
}

function runDcapCheck(hexQuote) {
  return execCommand(config.ATTESTER_BIN, ["check", hexQuote]);
}

async function runSevSnpCheck(hexQuote) {
  try {
    const stdout = await execCommand(config.AMD_VERIFIER, [
      "validate",
      hexQuote,
    ]);
    const result = JSON.parse(stdout);

    if (result.result !== "success") {
      throw new Error(result.message || "Unknown verification error");
    }

    const requireField = (key) => {
      if (!result[key]) {
        throw new Error(`'${key}' missing in response`);
      }
      return String(result[key]).toLowerCase();
    };

    const chipId = requireField("chip_id");
    const tee = {
      type: "sev-snp",
      measurement: requireField("measurement"),
      host_data: requireField("host_data"),
      report_data: requireField("report_data"),
      policy: requireField("policy"),
      reported_tcb: requireField("reported_tcb"),
      id_key_digest: requireField("id_key_digest"),
    };

    return { chipId, tee };
  } catch (error) {
    throw new Error(`AMD Verifier failed: ${error.message}`);
  }
}

function parseAttesterOutput(stdout) {
  const fields = {};
  let sawTdx = false;
  let sawSgx = false;

  for (const line of stdout.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (trimmed === "TDX report_body") sawTdx = true;
    if (trimmed === "SGX report_body") sawSgx = true;
    const eqIdx = trimmed.indexOf("=");
    if (eqIdx > 0) {
      const key = trimmed.slice(0, eqIdx).trim();
      const value = trimmed.slice(eqIdx + 1).trim();
      fields[key] = value;
    }
  }

  const machineIdMatch = stdout.match(/Machine-ID:\s*([0-9a-fA-F]+)/i);
  if (!machineIdMatch) {
    throw new Error("Machine-ID not found in attestation output");
  }
  const machineId = machineIdMatch[1];

  if (!sawTdx && !sawSgx) {
    throw new Error("Could not determine TEE type from attester output");
  }

  const requireHex = (key) => {
    const v = fields[key];
    if (v === undefined) {
      throw new Error(`Missing expected quote field: ${key}`);
    }
    return v.toLowerCase();
  };

  const requireInt = (key) => {
    const v = fields[key];
    if (v === undefined) {
      throw new Error(`Missing expected quote field: ${key}`);
    }
    const n = parseInt(v, 10);
    if (Number.isNaN(n)) {
      throw new Error(`Invalid ${key}: not a number`);
    }
    return n;
  };

  let tee;
  if (sawTdx) {
    tee = {
      type: "tdx",
      mr_td: requireHex("mr_td"),
      mr_seam: requireHex("mr_seam"),
      mr_signer_seam: requireHex("mr_signer_seam"),
      td_attributes: requireHex("td_attributes"),
      xfam: requireHex("xfam"),
      tcb_svn: requireHex("tcb_svn"),
      rtmr0: requireHex("rtmr0"),
      rtmr1: requireHex("rtmr1"),
      rtmr2: requireHex("rtmr2"),
      rtmr3: requireHex("rtmr3"),
      report_data: requireHex("report_data"),
    };
  } else {
    tee = {
      type: "sgx",
      mr_enclave: requireHex("mr_enclave"),
      mr_signer: requireHex("mr_signer"),
      report_data: requireHex("report_data"),
      attributes: requireHex("attributes"),
      cpu_svn: requireHex("cpu_svn"),
      isv_prod_id: requireInt("isv_prod_id"),
      isv_svn: requireInt("isv_svn"),
      config_svn: requireInt("config_svn"),
    };
  }

  return { machineId, tee };
}

function normalizeKvJson(inp) {
  if (typeof inp !== "object" || Array.isArray(inp))
    throw new Error("input malformed");
  const keys = Object.keys(inp).sort(); // for deterministic output
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
    .toString("base64") // normal base64
    .replace(/\+/g, "-") // convert '+' → '-'
    .replace(/\//g, "_") // convert '/' → '_'
    .replace(/=+$/g, ""); // remove trailing '='
}

async function processQuote(hexQuote, timestamp, nonces, partial_sigs) {

  if (!hexQuote) {
    throw new Error("Missing quote");
  }

  if (!/^[0-9a-fA-F]+$/.test(hexQuote)) {
    throw new Error("Invalid quote format: must be hex string");
  }

  const time_now_s = Math.floor(Date.now() / 1000);

  if (!timestamp) {
    timestamp = time_now_s;
  } else {
    const max_diff_s = 5 * 60; // 5 minutes in seconds
    if (Math.abs(time_now_s - timestamp) > max_diff_s) {
      throw new Error("timestamp too distant");
    }
  }

  const quoteHash = crypto
    .createHash("sha256")
    .update(Buffer.from(hexQuote, "hex"))
    .digest("hex");
  let machineId;
  let tee;

  // TDX quotes are typically larger (> 4KB), SEV-SNP are smaller (~1KB)
  if (hexQuote.length > 8000) {
    // Approx 4000 bytes * 2 hex chars
    const output = await runDcapCheck(hexQuote);
    const parsed = parseAttesterOutput(output);
    machineId = parsed.machineId;
    tee = parsed.tee;
  } else {
    const snp = await runSevSnpCheck(hexQuote);
    machineId = snp.chipId;
    tee = snp.tee;
  }

  machineId = machineId.toLowerCase();

  const validNode = state.whitelist.find((entry) =>
    machineId.startsWith(entry.id),
  );

  if (!validNode) {
    console.warn(
      `⛔ Access Denied: Machine ID ${machineId} is not in whitelist.`,
    );
    throw new Error("Machine is not whitelisted.");
  }

  const payload = {
    quote_hash: quoteHash,
    machine_id: machineId,
    label: validNode.label,
    timestamp: timestamp,
    tee: tee,
  };

  let jwt_token = null;

  if (config.MULTISIG_MODE) {
    if (nonces) {
      const safe_nonces = normalizeKvJson(nonces);
      const my_nonce_pub = safe_nonces[state.multisig.moniker] || null;
      if (!my_nonce_pub) throw new Error("my nonce not included");

      const my_nonce_priv = state.multisig.nonceMap[my_nonce_pub];
      if (!my_nonce_priv) throw new Error("my nonce not found");

      delete state.multisig.nonceMap[my_nonce_pub]; // important!

      let safe_sigs = {};
      if (partial_sigs) safe_sigs = normalizeKvJson(partial_sigs);

      const header = {
        alg: "EdDSA",
        typ: "JWT",
        kid: state.multisig.sharedPublicKey,
      };

      const header_b64 = base64url(Buffer.from(JSON.stringify(header), "utf8"));
      const payload_b64 = base64url(
        Buffer.from(JSON.stringify(payload), "utf8"),
      );
      const signingInput = `${header_b64}.${payload_b64}`;
      const signingInput_hex = Buffer.from(signingInput, "utf8").toString(
        "hex",
      );

      const args = [
        "sign",
        "--pub-nonces",
        JSON.stringify(safe_nonces),
        "--my-nonce",
        my_nonce_priv,
        "--message",
        signingInput_hex,
        "--partial-sigs",
        JSON.stringify(safe_sigs),
      ];
      const output = await runSss(args);

      const match_full_signature = output.match(
        /^\s*full_signature\s*:\s*([0-9a-fA-F]+)\s*$/m,
      );
      if (!match_full_signature) {
        const match_sigs = output.match(/^\s*sigs\s*=\s*(\{.*\})\s*$/m);
        if (!match_sigs) throw new Error("SSS output missing sigs");
        return JSON.parse(match_sigs[1]);
      }

      const full_signature = match_full_signature[1];
      const sig_b64 = base64url(Buffer.from(full_signature, "hex"));
      jwt_token = signingInput + "." + sig_b64;
    } else {
      const output = await runSss(["get-nonce"]);

      const nonce_priv =
        output.match(/nonce_priv\s*=\s*([A-Za-z0-9+/=]+)/)?.[1] || null;
      const nonce_pub =
        output.match(/nonce_pub\s*=\s*([A-Za-z0-9+/=]+)/)?.[1] || null;

      if (!nonce_priv || !nonce_pub) throw new Error("failed to get nonce");

      if (state.multisig.nonceList.length > 20) {
        const key = state.multisig.nonceList.shift(); // pop_front
        delete state.multisig.nonceMap[key]; // remove from map
      }

      state.multisig.nonceList.push(nonce_pub);
      state.multisig.nonceMap[nonce_pub] = nonce_priv;

      return { machineId, moniker: state.multisig.moniker, nonce: nonce_pub };
    }
  } else {
    jwt_token = jwt.sign(payload, state.privateKey, {
      algorithm: "RS256",
      header: { kid: state.keyId },
    });
  }

  return { machineId, label: validNode.label, jwt: jwt_token };
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
  const publicKey = state.keyRegistry[kid].replace(/\\n/g, "\n");

  jwt.verify(token, publicKey, { algorithms: ["RS256"] });

  const expectedHash = crypto
    .createHash("sha256")
    .update(Buffer.from(hexQuote, "hex"))
    .digest("hex");
  if (expectedHash !== quote_hash) {
    throw new Error("Integrity check failed: Quote does not match Token");
  }

  return {
    valid: true,
    keyId: kid,
    label,
    tee: decoded.payload.tee || null,
  };
}

module.exports = { loadSecrets, processQuote, verifyToken };
