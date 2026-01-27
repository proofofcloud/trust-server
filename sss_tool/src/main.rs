extern crate aes_gcm;
extern crate aes_siv;
extern crate base64;
extern crate clap;
extern crate getrandom;
extern crate hex;
extern crate rand;
extern crate sha2;
extern crate x25519_dalek;
extern crate curve25519_dalek;
extern crate ed25519_dalek;
extern crate serde;
extern crate anyhow;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use aes_siv::siv::Aes128Siv;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use clap::{Parser, Subcommand};
use curve25519_dalek::scalar::Scalar;
use rand::RngCore;
use std::convert::TryInto;
use sha2::Digest;
use std::collections::{HashMap, HashSet};
use anyhow::Context;


#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Rand(RandArgs),
    GenerateKey(GenerateKeyArgs),
    Encrypt(EncryptArgs),
    Decrypt(EncryptArgs),
    EncryptDstackEnv(EncryptDstackEnvArgs),
    DecryptDstackEnv(DecryptDstackEnvArgs),
    SssInfo,
    SssInitialize(SssInitializeArgs),
    SssInitialPubData(SssInitialPubDataArgs),
    SssInitCommon(SssInitCommonArgs),
    SssInitMyShare(SssInitMyShareArgs),
    SssGetNonce,
    SssSign(SssSignArgs),
    SssAddNew(SssAddNewArgs),
    SssInitNew(SssInitNewArgs),
}

#[derive(Parser)]
struct RandArgs {
    #[arg(short = 'n', long, default_value_t = 32)]
    bytes: usize,
}

#[derive(Parser)]
struct GenerateKeyArgs {
    #[arg(short = 's', long)]
    seed: String,
}

#[derive(Parser)]
struct EncryptArgs {
    #[arg(short = 's', long)]
    seed: String,
    #[arg(short = 'd', long)]
    data: String,
    #[arg(short = 'p', long)]
    pubkey: String,
}

#[derive(Parser)]
struct EncryptDstackEnvArgs {
    #[arg(short = 'p', long)]
    pubkey: String,
    #[arg(short = 'd', long)]
    data: String,
}

#[derive(Parser)]
struct DecryptDstackEnvArgs {
    #[arg(short = 'k', long)]
    privkey: String,
    #[arg(short = 'd', long)]
    data: String,
}

#[derive(Parser)]
struct SssInitializeArgs {
    #[arg(long)]
    moniker: String,
}

#[derive(Parser)]
struct SssInitialPubDataArgs {
    #[arg(long)]
    m: usize,
}

#[derive(Parser)]
struct SssInitCommonArgs {
    #[arg(long)]
    pub_datas: String,
}

#[derive(Parser)]
struct SssInitMyShareArgs {
    #[arg(long)]
    pub_datas: String,
    #[arg(long)]
    partial_shares: String,
}

#[derive(Parser)]
struct SssSignArgs {
    #[arg(long)]
    message: String,
    #[arg(long)]
    my_nonce: String,
    #[arg(long)]
    pub_nonces: String,
    #[arg(long)]
    partial_sigs: String,
}

#[derive(Parser)]
struct SssAddNewArgs {
    #[arg(long)]
    moniker: String,
    #[arg(long)]
    pubkey: String,
    #[arg(long)]
    quorum: String,
}

#[derive(Parser)]
struct SssInitNewArgs {
    #[arg(long)]
    partial_shares: String,
}

fn generate_sk(seed: &String) -> x25519_dalek::StaticSecret {
    let buf = match hex::decode(seed) {
        Ok(buf) => buf,
        Err(e) => {
            panic!("bad key seed: {}", e);
        }
    };

    let mut sha256 = sha2::Sha256::new();
    sha256.update(buf);

    let buf: [u8; 32] = sha256.finalize().into();
    x25519_dalek::StaticSecret::from(buf)
}

fn sk_to_pk(sk: &x25519_dalek::StaticSecret) -> x25519_dalek::PublicKey {
    x25519_dalek::PublicKey::from(sk)
}

fn read_pk(pubkey: &String) -> x25519_dalek::PublicKey {
    match hex::decode(pubkey) {
        Ok(d) => {
            let arr: [u8; 32] = d.try_into().expect("wrong pubkey size");
            x25519_dalek::PublicKey::from(arr)
        }
        Err(e) => {
            panic!("bad pubkey: {}", e);
        }
    }
}

fn read_blob(data: &String) -> Vec<u8> {
    match hex::decode(data) {
        Ok(d) => d,
        Err(e) => {
            panic!("bad data: {}", e);
        }
    }
}

fn dh_get_key(args: &EncryptArgs) -> Aes128Siv {
    let sk = generate_sk(&args.seed);
    let pk = read_pk(&args.pubkey);

    let shared_secret = sk.diffie_hellman(&pk);
    Aes128Siv::new(shared_secret.to_bytes().into())
}


mod sss {

    use anyhow::Context;
    use rand::rngs::OsRng;
    use rand::RngCore;
    use sha2::Digest;
    use std::collections::HashSet;

    use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
    use curve25519_dalek::edwards::EdwardsPoint;
    use curve25519_dalek::scalar::Scalar;
    use curve25519_dalek::traits::{Identity, IsIdentity};

    use ed25519_dalek::Signer;
    use Aes256Gcm;
    use aes_gcm::KeyInit;
    use aes_gcm::aead::Aead;
    use std::convert::TryInto;
    use std::io::{Write, Read};
    use std::fs::File;
    use HashMap;

    use std::io::ErrorKind;
    use std::io::Error;

    use ed25519_dalek::{PublicKey, Signature};

    use serde::{Deserialize, Serialize};
    use serde::{Deserializer, Serializer};
    use serde::ser::SerializeMap;

    use base64::engine::general_purpose;
    use base64::Engine;

    mod signatures_b64 {
        use super::*;
        use serde::{Deserialize, Deserializer, Serialize, Serializer};

        pub fn serialize<S>(sigs: &Vec<Signature>, s: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            // serialize Vec<Signature> as Vec<String> by reusing signature_b64
            let encoded: Vec<String> = sigs.iter().map(|sig| {
                // use a tiny internal serde roundtrip is overkill; just call the same logic:
                // easiest: call to_bytes + base64 here, but to truly reuse, see Option 2.
                base64::engine::general_purpose::STANDARD.encode(sig.to_bytes())
            }).collect();

            encoded.serialize(s)
        }

        pub fn deserialize<'de, D>(d: D) -> Result<Vec<Signature>, D::Error>
        where
            D: Deserializer<'de>,
        {
            let encoded: Vec<String> = Vec::deserialize(d)?;
            let mut out = Vec::with_capacity(encoded.len());

            for s in encoded {
                // reuse single-item deserialize by deserializing from a string
                // (we can just re-run its logic directly to avoid awkward serde plumbing)
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(&s)
                    .map_err(serde::de::Error::custom)?;

                if bytes.len() != 64 {
                    return Err(serde::de::Error::custom("Signature must be 64 bytes"));
                }

                let mut arr = [0u8; 64];
                arr.copy_from_slice(&bytes);

                let sig = Signature::from_bytes(&arr).map_err(serde::de::Error::custom)?;
                out.push(sig);
            }

            Ok(out)
        }
    }

    mod public_keys_b64 {
        use super::*;
        use base64::engine::general_purpose;
        use serde::{Deserialize, Deserializer, Serialize, Serializer};

        pub fn serialize<S>(v: &Vec<ed25519_dalek::PublicKey>, s: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            // Represent as Vec<String> (base64)
            let b64_vec: Vec<String> = v
                .iter()
                .map(|pk| general_purpose::STANDARD.encode(pk.to_bytes()))
                .collect();
            b64_vec.serialize(s)
        }

        pub fn deserialize<'de, D>(d: D) -> Result<Vec<ed25519_dalek::PublicKey>, D::Error>
        where
            D: Deserializer<'de>,
        {
            let b64_vec: Vec<String> = Vec::deserialize(d)?;
            let mut out = Vec::with_capacity(b64_vec.len());

            for s in b64_vec {
                let bytes = general_purpose::STANDARD
                    .decode(&s)
                    .map_err(serde::de::Error::custom)?;

                if bytes.len() != 32 {
                    return Err(serde::de::Error::custom("PublicKey must be 32 bytes"));
                }

                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);

                let pk = ed25519_dalek::PublicKey::from_bytes(&arr)
                    .map_err(serde::de::Error::custom)?;

                out.push(pk);
            }

            Ok(out)
        }
    }

    fn map_bytes_to_base64<S>(
        map: &HashMap<String, Vec<u8>>,
        serializer: S
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut ser_map = serializer.serialize_map(Some(map.len()))?;

        for (k, v) in map {
            let encoded = general_purpose::STANDARD.encode(v);
            ser_map.serialize_entry(k, &encoded)?;
        }

        ser_map.end()
    }    


    pub fn map_bytes_from_base64<'de, D>(
        deserializer: D,
    ) -> Result<HashMap<String, Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw: HashMap<String, String> = HashMap::deserialize(deserializer)?;
        let mut out = HashMap::with_capacity(raw.len());
        for (k, v_b64) in raw {
            let bytes = general_purpose::STANDARD
                .decode(v_b64.as_bytes())
                .map_err(serde::de::Error::custom)?;
            out.insert(k, bytes);
        }
        Ok(out)
    }

    pub fn map_map_bytes_to_base64<S>(
        map: &HashMap<String, HashMap<String, Vec<u8>>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeMap;

        let mut ser = serializer.serialize_map(Some(map.len()))?;
        for (outer_k, inner) in map {
            // reuse the simple helper by first building HashMap<String, String>
            let inner_b64: HashMap<String, String> = inner
                .iter()
                .map(|(k, v)| (k.clone(), general_purpose::STANDARD.encode(v)))
                .collect();

            ser.serialize_entry(outer_k, &inner_b64)?;
        }
        ser.end()
    }

    pub fn map_map_bytes_from_base64<'de, D>(
        deserializer: D,
    ) -> Result<HashMap<String, HashMap<String, Vec<u8>>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw: HashMap<String, HashMap<String, String>> = HashMap::deserialize(deserializer)?;
        let mut out = HashMap::with_capacity(raw.len());

        for (outer_k, inner_map) in raw {
            let mut inner_out = HashMap::with_capacity(inner_map.len());
            for (k, v_b64) in inner_map {
                let bytes = general_purpose::STANDARD
                    .decode(v_b64.as_bytes())
                    .map_err(serde::de::Error::custom)?;
                inner_out.insert(k, bytes);
            }
            out.insert(outer_k, inner_out);
        }

        Ok(out)
    }

    fn ed25519_challenge_scalar(r_bytes: &[u8; 32], a_bytes: &[u8; 32], msg: &[u8]) -> Scalar {
        let mut h = sha2::Sha512::new();
        h.update(r_bytes);
        h.update(a_bytes);
        h.update(msg);
        let out = h.finalize(); // 64 bytes

        let mut wide = [0u8; 64];
        wide.copy_from_slice(&out);

        Scalar::from_bytes_mod_order_wide(&wide)
    }

    pub fn dh_shared_secret(
        my_scalar: &Scalar,
        peer_pub: &EdwardsPoint,
    ) -> [u8; 32]
    {
        // assuming peer_pub already was validated (valid EC point)
        let shared = my_scalar * peer_pub;
        shared.compress().to_bytes()
    }

    pub fn dh_symmetric_key(
        my_scalar: &Scalar,
        peer_pub: &EdwardsPoint,
    ) -> Aes256Gcm
    {
        // assuming peer_pub already was validated (valid EC point)
        let ikm = dh_shared_secret(my_scalar, peer_pub);

        // TODO: use proper HKDF
        let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&ikm);
        Aes256Gcm::new(key)
    }


    pub fn dh_encrypt(
        my_scalar: &Scalar,
        peer_pub: &EdwardsPoint,
        plaintext: &[u8],
    ) -> anyhow::Result<Vec<u8>> {

        let cipher = dh_symmetric_key(my_scalar, peer_pub);

        let mut iv_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut iv_bytes);
        let nonce = aes_siv::aead::Nonce::from_slice(&iv_bytes);

        let ciphertext = cipher.encrypt(nonce, plaintext)
            .map_err(|_| anyhow::anyhow!("aes_gcm encrypt failed")) // convert to anyhow::Error
            .context("dh_encrypt fail")?;

        let mut final_blob = Vec::new();
        final_blob.extend_from_slice(&iv_bytes);
        final_blob.extend_from_slice(&ciphertext);

        Ok(final_blob)
    }

    pub fn dh_decrypt(
        my_scalar: &Scalar,
        peer_pub: &EdwardsPoint,
        final_blob: &[u8],
    ) -> anyhow::Result<Vec<u8>> {

        let cipher = dh_symmetric_key(my_scalar, peer_pub);
    
        let iv_bytes: [u8; 12] = final_blob.get(0..12).context("dh_decrypt iv missing")?.try_into().unwrap();

        let ciphertext = &final_blob[12..];

        let nonce = aes_siv::aead::Nonce::from_slice(&iv_bytes);
        cipher.decrypt(nonce, ciphertext)
            .map_err(|_| anyhow::anyhow!("aes_gcm decrypt failed")) // convert to anyhow::Error
            .context("dh_decrypt fail")
    }


    pub struct CommonState
    {
        pub_coeffs: Vec<EdwardsPoint>,
    }

    impl CommonState
    {
        fn evaluate_at(&self, x: &Scalar) -> EdwardsPoint {
            
            let mut x_pwr = *x;
            let mut res = self.pub_coeffs[0];
            
            for j in 1..self.pub_coeffs.len() {
                res += self.pub_coeffs[j] * x_pwr;
                x_pwr *= x;
            }

            res
        }

        fn test_quorum_size(&self, actual: usize) -> anyhow::Result<()> {
            let m = self.pub_coeffs.len();
            if m == actual {
                Ok(())
            } else {
                Err(anyhow::anyhow!("incorrect quorum actual={}, expected={}", actual, m))
            }
        }

    }

    #[derive(Serialize, Deserialize)]
    pub struct InitPubData {
        #[serde(with = "public_keys_b64")]
        pub_coeffs: Vec<PublicKey>,
        #[serde(with = "signatures_b64")]
        pops: Vec<Signature>,
    }

    #[derive(Serialize, Deserialize)]
    pub struct PartialShares (
         #[serde(
        serialize_with = "map_map_bytes_to_base64",
        deserialize_with = "map_map_bytes_from_base64"
        )]
        pub HashMap<String, HashMap<String, Vec<u8>>>
    );    

    #[derive(Serialize, Deserialize)]
    pub struct StrVecMap (
         #[serde(
        serialize_with = "map_bytes_to_base64",
        deserialize_with = "map_bytes_from_base64"
        )]
        pub HashMap<String, Vec<u8>>,
    );    

    impl InitPubData
    {
        pub fn test(&self) -> anyhow::Result<()> {

            if self.pub_coeffs.len() != self.pops.len() {
                return Err(anyhow::anyhow!("pub_coeffs and pops len do not match"));
            }

            for i in 0..self.pub_coeffs.len() {
                let pubkey = &self.pub_coeffs[i];
                let pop = &self.pops[i];

                pubkey.verify_strict(&[], &pop).context("PoP mismatch")?;
            }

            Ok(())
        }
    }

    pub struct State
    {
        my_seed: [u8;32],
        pub my_moniker: String,

        shared: Option<CommonState>,

        my_share: Option<Scalar>,
    }

    const SSS_DATA_VER: u32 = 1;
    const FILE_PRIVATE: &str = "private.sss";
    const FILE_SHARED: &str = "shared.sss";

    impl State
    {
        pub fn new(moniker: String) -> State {
            let mut seed = [0u8;32];
            OsRng.fill_bytes(&mut seed);
            
            State {
                my_seed: seed,
                my_moniker: moniker,
                shared: None,
                my_share: None,
            }
            
        }

        pub fn have_my_share(&self) -> bool {
            self.my_share.is_some()
        }

        fn get_common_state(&self) -> anyhow::Result<&CommonState> {
            match self.shared.as_ref() {
                Some(sh) => Ok(sh),
                None => Err(anyhow::anyhow!("no common state"))
            }
        }

        fn get_my_share(&self) -> anyhow::Result<&Scalar> {
            match &self.my_share {
                Some(sk) => Ok(sk),
                None => Err(anyhow::anyhow!("no my share"))
            }
        }

        pub fn get_pub_params(&self) -> anyhow::Result<(usize, [u8; 32])> {
            let sh = self.get_common_state()?;
            Ok((sh.pub_coeffs.len(), sh.pub_coeffs[0].compress().as_bytes().clone()))
        }

        pub fn save_private(&self) -> std::io::Result<()> {

            let mut writer = File::create(FILE_PRIVATE)?;
            writer.write_all(&SSS_DATA_VER.to_le_bytes())?;

            writer.write_all(&self.my_seed)?;

            let moniker_b = self.my_moniker.as_bytes();
            writer.write_all(&moniker_b.len().to_le_bytes())?;
            writer.write_all(&moniker_b)?;


            if let Some(sk) = self.my_share {
                writer.write_all(&[1_u8])?;
                writer.write_all(sk.as_bytes())?;
            } else {
                writer.write_all(&[0_u8])?;
            }

            Ok(())
        }

        pub fn save_shared(&self) -> std::io::Result<()> {

            let mut writer = File::create(FILE_SHARED)?;
            writer.write_all(&SSS_DATA_VER.to_le_bytes())?;

            if let Some(sh) = self.shared.as_ref() {
                writer.write_all(&[1_u8])?;

                let m = sh.pub_coeffs.len();
                writer.write_all(&m.to_le_bytes())?;
                
                for pt in sh.pub_coeffs.iter() {
                    writer.write_all(&pt.compress().to_bytes())?;
                }

            } else {
                writer.write_all(&[0_u8])?;
            }

            Ok(())
        }

        fn read_u32(reader: &mut dyn Read) -> std::io::Result<u32> {
            let mut buf = [0u8; 4];
            reader.read_exact(&mut buf)?;
            Ok(u32::from_le_bytes(buf))
        }

        fn read_usize(reader: &mut dyn Read) -> std::io::Result<usize> {
            let mut buf = [0u8; std::mem::size_of::<usize>()];
            reader.read_exact(&mut buf)?;
            Ok(usize::from_le_bytes(buf))
        }

        fn load_preffix(path: &str) -> std::io::Result<File> {
            let mut reader = File::open(path)?;

            let ver = Self::read_u32(&mut reader)?;
            if SSS_DATA_VER != ver {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "unsupported ver",
                ));
            }

            Ok(reader)
        }


        pub fn load_private_only() -> std::io::Result<State> {
            let mut reader = Self::load_preffix(FILE_PRIVATE)?;

            let mut seed = [0_u8; 32];
            reader.read_exact(&mut seed)?;

            let moniker = {
                let len = Self::read_usize(&mut reader)?;
                let mut buf = vec![0u8; len];
                reader.read_exact(&mut buf)?;
                String::from_utf8(buf).map_err(|e| Error::new(ErrorKind::InvalidData, e))
            }?;

            let mut flag = [0_u8];
            reader.read_exact(&mut flag)?;

            let my_share = if 1 & flag[0] != 0 {
                let mut buf = [0_u8; 32];
                reader.read_exact(&mut buf)?;
                Some(Scalar::from_bytes_mod_order(buf))

            } else {
                None
            };


            Ok(State {
                my_seed: seed,
                my_moniker: moniker,
                shared: None,
                my_share: my_share,
            })
        }

        fn decode_point(buf: &[u8]) -> anyhow::Result<EdwardsPoint> {
            curve25519_dalek::edwards::CompressedEdwardsY::from_slice(&buf).decompress().context("decoding EC point")
        }

        pub fn load_shared(&mut self) -> anyhow::Result<()> {

            let mut reader = Self::load_preffix(FILE_SHARED)?;

            let mut flag = [0_u8];
            reader.read_exact(&mut flag)?;

            if 1 & flag[0] != 0 {
                let mut shared = CommonState {
                    pub_coeffs: Vec::new(),
                };

                let m: usize = Self::read_usize(&mut reader)?;
                let mut buf = [0_u8; 32];

                for _ in 0..m {
                    reader.read_exact(&mut buf)?;

                    let pt = Self::decode_point(&buf)?;
                    shared.pub_coeffs.push(pt);

                }

                self.shared = Some(shared);
            }

            Ok(())
        }

        pub fn load_full() -> anyhow::Result<State> {
            let mut me = Self::load_private_only()?;
            me.load_shared()?;
            Ok(me)
        }

        fn generate_init_key_raw(&self, m: usize, i: usize) -> ed25519_dalek::SecretKey {
            let mut h = sha2::Sha256::new();
            h.update(b"init-key");
            h.update(self.my_seed);
            h.update(&m.to_le_bytes());
            h.update(&i.to_le_bytes());
            let key_material: [u8;32] = h.finalize().into();

            ed25519_dalek::SecretKey::from_bytes(&key_material).unwrap()
        }

        fn secret_key_to_scalar(sk: &ed25519_dalek::SecretKey) -> Scalar {
            // 1. Get the 32-byte seed
            let seed = sk.as_bytes();

            // 2. Hash with SHA-512
            let h = sha2::Sha512::digest(seed);

            // 3. Clamp per Ed25519 rules
            let mut a_bytes = [0u8; 32];
            a_bytes.copy_from_slice(&h[..32]);
            a_bytes[0]  &= 248;
            a_bytes[31] &= 63;
            a_bytes[31] |= 64;

            // 4. Convert to scalar (mod ℓ)
            Scalar::from_bytes_mod_order(a_bytes)
        }

        pub fn generate_keys(&self, m: usize) -> InitPubData
        {
            let mut res = InitPubData {
                pub_coeffs: Vec::new(),
                pops: Vec::new(),
            };

            for i in 0..m {

                let sk = self.generate_init_key_raw(m, i);
                let pk = PublicKey::from(&sk);
                let kp = ed25519_dalek::Keypair {
                    secret: sk,
                    public: pk
                };

                //println!("generated key: {}", hex::encode(kp.public.to_bytes()));

                res.pub_coeffs.push(kp.public);
                res.pops.push(kp.sign(&[]));

            }

            res

        }

        fn get_my_keys(&self, m: usize) -> Vec<Scalar> {
            let mut sks = Vec::new();

            for j in 0..m {
                let sk = self.generate_init_key_raw(m, j);
                let sc = Self::secret_key_to_scalar(&sk);
                sks.push(sc);
            }
            sks
        }

        fn calculate_partial_at(x: &Scalar, sks: &Vec<Scalar>) -> Scalar
        {
            let mut x_pwr = *x;
            let mut res = sks[0];
            
            for j in 1..sks.len() {
                res += sks[j] * x_pwr;
                x_pwr *= *x;
            }
            res
        }

        pub fn get_x_raw(moniker: &str) -> Scalar
        {
            let mut hasher = sha2::Sha256::new();
            hasher.update("actor-");
            hasher.update(moniker);

            let res = hasher.finalize();
            Scalar::from_bytes_mod_order(res.into())
        }

        pub fn get_x(&self) -> Scalar {
            Self::get_x_raw(&self.my_moniker)
        }

        pub fn init_common(&mut self, all_datas: &HashMap<String, InitPubData>) -> anyhow::Result<HashMap<String, Vec<u8>>> {

            if let None = all_datas.get(&self.my_moniker) {
                return Err(anyhow::anyhow!("I'm not in the quorum")); // I'm not a part of the quorum!
            }

            // determine m, ensure consistency
            let mut m: usize = 0;
            for (moniker, data) in all_datas.iter() {

                (|| -> anyhow::Result<_> {
                    if m == 0 {
                        m = data.pub_coeffs.len();
                        if m == 0 {
                            anyhow::bail!("zero coeffs");
                        }
                    } else {
                        if data.pub_coeffs.len() != m {
                            anyhow::bail!("wrong number of coeffs");
                        }
                    }

                    Ok::<(), anyhow::Error>(())
                })().context(format!("from {}", moniker))?;
            }

            let sks = self.get_my_keys(m);

            let mut common = CommonState {
                pub_coeffs: Vec::new(),
            };

            for j in 0..m {
                let pk = sks[j] * &ED25519_BASEPOINT_POINT;
                common.pub_coeffs.push(pk);
            }

            let mut res = HashMap::new();

            for (moniker, data) in all_datas.iter() {

                (|| -> anyhow::Result<_> {
                    
                    data.test()?;

                    if *moniker != self.my_moniker {

                        // add contribution
                        let mut peer_pk = None;

                        for j in 0..m {
                            let pubkey = data.pub_coeffs[j];
                            let pk = Self::decode_point(&pubkey.to_bytes())?;

                            common.pub_coeffs[j] += pk;

                            if j == 0 {
                                peer_pk = Some(pk);
                            }
                        }

                        let encrypted_share = {
                            
                            let x = Self::get_x_raw(moniker);
                            let partial_share = Self::calculate_partial_at(&x, &sks);

                            //println!("{} share for {}: {}", self.my_moniker, moniker, hex::encode(&partial_share.to_bytes()));

                            dh_encrypt(&sks[0], &peer_pk.unwrap(), &partial_share.to_bytes())?
                        };

                        res.insert(moniker.clone(), encrypted_share);
                    }

                    Ok(())

                })().context(format!("from {}", moniker))?;


            }

            for j in 0..m {
                let pk = &common.pub_coeffs[j];
                println!("common coeff {}: {}", j, hex::encode(pk.compress().to_bytes()));
            }

            self.shared = Some(common);



            Ok(res)
        }

        fn import_my_share_raw(&mut self, my_x: &Scalar, my_y: &Scalar) -> anyhow::Result<()> {
            // verify
            let sh = self.get_common_state()?;
            let diff = sh.evaluate_at(&my_x) - my_y * &ED25519_BASEPOINT_POINT;
            if !diff.is_identity() {
                anyhow::bail!("my share verification failed");
            }

            self.my_share = Some(*my_y);
            Ok(())
            
        }

        pub fn import_shares(&mut self, all_datas: &HashMap<String, InitPubData>, all_partial_shares: &HashMap<String, HashMap<String, Vec<u8>>>) -> anyhow::Result<()> {

            let sh = self.get_common_state()?;
            let m = sh.pub_coeffs.len();
            
            let sks = self.get_my_keys(m);
            let my_x = self.get_x();
            let mut my_y = Self::calculate_partial_at(&my_x, &sks);

            for (moniker, data) in all_datas.iter() {
                if *moniker == self.my_moniker {
                    continue;
                }

                let share_for_me = (|| -> anyhow::Result<_> {

                    let partial_shares = match all_partial_shares.get(moniker) {
                        Some(x) => x,
                        None => {
                            anyhow::bail!("no shares");
                        }
                    };

                    let my_share = match partial_shares.get(&self.my_moniker) {
                        Some(x) => x,
                        None => {
                            anyhow::bail!("no share for me");
                        }
                    };

                    let pk = Self::decode_point(&data.pub_coeffs[0].to_bytes())?;
                    let plaintext = dh_decrypt(&sks[0], &pk, my_share)?;

                    let y_bytes: [u8;32] = plaintext.as_slice().try_into()?;

                    Ok::<Scalar, anyhow::Error>(Scalar::from_bytes_mod_order(y_bytes))

                })().context(format!("shares from {}", moniker))?;


                my_y += share_for_me;


            }

            self.import_my_share_raw(&my_x, &my_y)
        }

        fn get_coeff(&self, x: &Scalar, quorum: &HashSet<String>) -> anyhow::Result<Scalar>
        {
            let sh = self.get_common_state()?;
            sh.test_quorum_size(quorum.len())?;

            let mut nom = Scalar::from(1u8);
            let mut denom = nom;

            let x_my: Scalar = self.get_x();
            let mut is_part = false;

            for moniker in quorum.iter() {
                if *moniker == self.my_moniker {
                    is_part = true;
                } else {
                    let x_other: Scalar = Self::get_x_raw(moniker);
                    nom *= *x - x_other;
                    denom *= x_my - x_other;
                }
            }

            if !is_part {
                return Err(anyhow::anyhow!("I'm not a part of the quorum"));
            }

            Ok(nom * denom.invert())
        }


        fn get_partial_sig_ex(&self, x: &Scalar, total_nonce_bytes: &[u8;32], msg: &[u8], quorum: &HashSet<String>) -> anyhow::Result<Scalar>
        {
            let my_sk = self.get_coeff(x, quorum)? * self.get_my_share()?;
            
            let sh = self.get_common_state()?;
            let total_pubkey = sh.evaluate_at(x);

            let e = ed25519_challenge_scalar(
                total_nonce_bytes,
                &total_pubkey.compress().to_bytes(),
                msg);

            Ok(my_sk * e)
        }
    
        pub fn get_partial_sig(&self, total_nonce_bytes: &[u8;32], msg: &[u8], quorum: &HashSet<String>) -> anyhow::Result<Scalar>
        {
            self.get_partial_sig_ex(&Scalar::zero(), total_nonce_bytes, msg, quorum)
        }

        pub fn get_total_nonce_and_quorum(pub_nonces: &HashMap<String, Vec<u8>>) -> anyhow::Result<([u8; 32], HashSet<String>)> {
            let mut total_nonce = EdwardsPoint::identity();
            let mut quorum = HashSet::new();

            for (moniker, nonce_bytes) in pub_nonces {

                let pub_nonce = Self::decode_point(nonce_bytes).context(format!("nonce from {}", moniker))?;

                total_nonce += pub_nonce;

                quorum.insert(moniker.clone());

            }

            let total_nonce_bytes: [u8; 32] = *total_nonce.compress().as_bytes();

            Ok((total_nonce_bytes, quorum))

        }

        fn get_ceremony_unique(sh: &CommonState, quorum_vec: &Vec<&String>) -> sha2::Sha256 {
            let mut h = sha2::Sha256::new();
            let m = sh.pub_coeffs.len();
            h.update(&m.to_le_bytes());

            for pt in sh.pub_coeffs.iter() {
                h.update(pt.compress().as_bytes());
            }

            for moniker in quorum_vec {
                h.update(moniker.as_bytes());
                h.update(&[0_u8]);
            }
            h
        }

        pub fn get_new_actor_partial_share_plain(&self, other_moniker: &str, quorum: &HashSet<String>) -> anyhow::Result<Scalar>
        {
            let sh = self.get_common_state()?;
            let my_share = self.get_my_share()?;
            let mut res = self.get_coeff(&Self::get_x_raw(other_moniker), quorum)? * my_share;

            // Note: HashSet iteration is unordered. Moreover, it's randomized artificially!
            // We can't assume all parties will iterate in the same order (whatever it is). Hence - sort manually
            let mut quorum_vec: Vec<&String> = quorum.iter().collect();
            quorum_vec.sort();

            let ceremony_unique: [u8;32] = {

                let mut h = Self::get_ceremony_unique(sh, &quorum_vec);
                h.update(other_moniker.as_bytes());
                h.finalize().into()
            };

            let mut found_self = false;
            for moniker in quorum_vec {
                if *moniker == self.my_moniker {
                    found_self = true;
                } else {
                    // add pseudo-random component
                    let peer_pubkey = sh.evaluate_at(&Self::get_x_raw(moniker));
                    let shared_secret = dh_shared_secret(my_share, &peer_pubkey);

                    let mut h = sha2::Sha256::new();
                    h.update(b"mask-key");
                    h.update(&ceremony_unique);
                    h.update(shared_secret);
                    let key_material: [u8;32] = h.finalize().into();

                    let mut shared_scalar = Self::secret_key_to_scalar(&ed25519_dalek::SecretKey::from_bytes(&key_material).unwrap());
                    if found_self {
                        shared_scalar = -shared_scalar;
                    }

                    res += shared_scalar;
                }
            }
            
            Ok(res)
        }

        pub fn get_new_actor_partial_share(&self, other_moniker: &str, other_pk: &[u8], quorum: &HashSet<String>) -> anyhow::Result<Vec<u8>>
        {
            let plain = self.get_new_actor_partial_share_plain(other_moniker, quorum)?;
            let pk = Self::decode_point(other_pk).context("other actor key")?;

            dh_encrypt(self.get_my_share()?, &pk, plain.as_bytes())
        }

        pub fn get_new_actor_pk(&self) -> anyhow::Result<PublicKey> {
            let sh = self.get_common_state()?;
            let sk = self.generate_init_key_raw(sh.pub_coeffs.len(), 0);
            Ok(PublicKey::from(&sk))
        }

        pub fn import_new_actor_partial_shares(&mut self, encrypted_shares: &HashMap<String, Vec<u8>>) -> anyhow::Result<()> {

            let sh = self.get_common_state()?;
            sh.test_quorum_size(encrypted_shares.len())?;

            let sk = self.generate_init_key_raw(sh.pub_coeffs.len(), 0);
            let sc = Self::secret_key_to_scalar(&sk);
            
            let mut my_y = Scalar::zero();

            for (moniker, encrypted_share) in encrypted_shares.iter() {

                let decoded_share = (|| -> anyhow::Result<_> {

                    let peer_pubkey = sh.evaluate_at(&Self::get_x_raw(moniker));
                    let plaintext = dh_decrypt(&sc, &peer_pubkey, encrypted_share)?;
                    let y_bytes: [u8;32] = plaintext.as_slice().try_into()?;
                    Ok::<Scalar, anyhow::Error>(Scalar::from_bytes_mod_order(y_bytes))

                })().context(format!("shares from {}", moniker))?;

                my_y += decoded_share;
            }

            self.import_my_share_raw(&Self::get_x_raw(&self.my_moniker), &my_y)

        }

    }

    #[allow(dead_code)]
    pub fn test() {

        {
            let mut rng = OsRng;

            let mut alice = State::new("alice".to_string());
            let mut bob = State::new("bob".to_string());
            let mut charlie = State::new("charlie".to_string());

            let mut all_datas = HashMap::new();
            all_datas.insert(alice.my_moniker.clone(), alice.generate_keys(2));
            all_datas.insert(bob.my_moniker.clone(), bob.generate_keys(2));
            all_datas.insert(charlie.my_moniker.clone(), charlie.generate_keys(2));

            let mut all_partial_shares = HashMap::new();
            all_partial_shares.insert(alice.my_moniker.clone(), alice.init_common(&all_datas).unwrap());

            all_partial_shares.insert(bob.my_moniker.clone(), bob.init_common(&all_datas).unwrap());
            all_partial_shares.insert(charlie.my_moniker.clone(), charlie.init_common(&all_datas).unwrap());

            alice.import_shares(&all_datas, &all_partial_shares).unwrap();
            bob.import_shares(&all_datas, &all_partial_shares).unwrap();
            charlie.import_shares(&all_datas, &all_partial_shares).unwrap();

            let msg = b"hello, world!";

            let shared_pubkey = PublicKey::from_bytes(&alice.shared.as_ref().unwrap().pub_coeffs[0].compress().to_bytes()).unwrap();

            // 1. A+B
            {
                let mut quorum = HashSet::new();
                quorum.insert(alice.my_moniker.clone());
                quorum.insert(bob.my_moniker.clone());

                let n1 = Scalar::random(&mut rng);
                let n2 = Scalar::random(&mut rng);

                let total_nonce =
                    n1 * &ED25519_BASEPOINT_POINT +
                    n2 * &ED25519_BASEPOINT_POINT;

                let nonce_bytes = total_nonce.compress().to_bytes();
                  
                let sig_k =
                    n1 + n2 +
                    alice.get_partial_sig(&nonce_bytes, msg, &quorum).unwrap() +
                    bob.get_partial_sig(&nonce_bytes, msg, &quorum).unwrap();

                let mut sig_bytes = [0u8; 64];
                sig_bytes[..32].copy_from_slice(&nonce_bytes);
                sig_bytes[32..].copy_from_slice(&sig_k.to_bytes());


                // verify signature
                let sig_obj = Signature::from_bytes(&sig_bytes).unwrap();
                println!("A+B verify result: {:?}", shared_pubkey.verify_strict(msg, &sig_obj));

            }


            let mut david = State::new("david".to_string());
            david.shared = alice.shared;
            
            // 2. B+C
            {
                let mut quorum = HashSet::new();
                quorum.insert(bob.my_moniker.clone());
                quorum.insert(charlie.my_moniker.clone());

                let n1 = Scalar::random(&mut rng);
                let n2 = Scalar::random(&mut rng);

                let total_nonce =
                    n1 * &ED25519_BASEPOINT_POINT +
                    n2 * &ED25519_BASEPOINT_POINT;

                let nonce_bytes = total_nonce.compress().to_bytes();
                  
                let sig_k =
                    n1 + n2 + 
                    bob.get_partial_sig(&nonce_bytes, msg, &quorum).unwrap() +
                    charlie.get_partial_sig(&nonce_bytes, msg, &quorum).unwrap();

                let mut sig_bytes = [0u8; 64];
                sig_bytes[..32].copy_from_slice(&nonce_bytes);
                sig_bytes[32..].copy_from_slice(&sig_k.to_bytes());


                // verify signature
                let sig_obj = Signature::from_bytes(&sig_bytes).unwrap();
                println!("B+C verify result: {:?}", shared_pubkey.verify_strict(msg, &sig_obj));

                // add David
                let pk_david = david.get_new_actor_pk().unwrap();
                let pk_david_bytes = pk_david.as_bytes();
                let mut all_shares = HashMap::new();
                all_shares.insert(bob.my_moniker.clone(), bob.get_new_actor_partial_share(&david.my_moniker, pk_david_bytes, &quorum).unwrap());
                all_shares.insert(charlie.my_moniker.clone(), charlie.get_new_actor_partial_share(&david.my_moniker, pk_david_bytes, &quorum).unwrap());

                david.import_new_actor_partial_shares(&all_shares).unwrap();

            }

        }


    }



}


fn main() -> anyhow::Result<()> {

    //sss::test();
    
    let cli = Cli::parse();

    match cli.command {
        Commands::Rand(rand_args) => {
            let mut data = vec![0u8; rand_args.bytes];
            getrandom::getrandom(&mut data)
                .map_err(|_| anyhow::anyhow!("getrandom failed"))?;

            println!("{}", hex::encode(data));
        }
        Commands::GenerateKey(args) => {
            let sk = generate_sk(&args.seed);
            let pk = sk_to_pk(&sk);
            println!("{}", hex::encode(pk.to_bytes()));
        }
        Commands::Encrypt(args) => {
            let mut key = dh_get_key(&args);
            let data = read_blob(&args.data);

            let res = key.encrypt([&[]], &data)
                .map_err(|_| anyhow::anyhow!("aes_encrypt failed"))?;

            println!("{}", hex::encode(res));
        }
        Commands::Decrypt(args) => {
            let mut key = dh_get_key(&args);
            let data = read_blob(&args.data);

            let res = key.decrypt([&[]], &data)
                .map_err(|_| anyhow::anyhow!("aes_decrypt failed"))?;

            println!("{}", hex::encode(res));
        }

        Commands::EncryptDstackEnv(args) => {
            let peer_pk = read_pk(&args.pubkey);

            let mut rng = rand::thread_rng();
            let mut ephemeral_bytes = [0u8; 32];
            rng.fill_bytes(&mut ephemeral_bytes);

            let ephemeral_sk = x25519_dalek::StaticSecret::from(ephemeral_bytes);
            let ephemeral_pk = x25519_dalek::PublicKey::from(&ephemeral_sk);

            let shared_secret = ephemeral_sk.diffie_hellman(&peer_pk);

            let key = aes_gcm::Key::<Aes256Gcm>::from_slice(shared_secret.as_bytes());
            let cipher = Aes256Gcm::new(key);

            let mut iv_bytes = [0u8; 12];
            rng.fill_bytes(&mut iv_bytes);
            let nonce = Nonce::from_slice(&iv_bytes);

            let plaintext = args.data.as_bytes();
            let ciphertext = cipher
                .encrypt(nonce, plaintext)
                .expect("encryption failure");

            let mut final_blob = Vec::new();
            final_blob.extend_from_slice(ephemeral_pk.as_bytes());
            final_blob.extend_from_slice(&iv_bytes);
            final_blob.extend_from_slice(&ciphertext);

            println!("{}", BASE64.encode(final_blob));
        }

        Commands::DecryptDstackEnv(args) => {
            let sk_bytes = hex::decode(&args.privkey).expect("bad private key hex");
            let sk_arr: [u8; 32] = sk_bytes.try_into().expect("private key must be 32 bytes");
            let my_sk = x25519_dalek::StaticSecret::from(sk_arr);

            let blob = BASE64.decode(&args.data).expect("invalid base64 data");

            if blob.len() < 32 + 12 {
                panic!("Encrypted data too short");
            }

            let sender_pk_bytes: [u8; 32] = blob[0..32].try_into()?;
            let iv_bytes: [u8; 12] = blob[32..44].try_into()?;
            let ciphertext = &blob[44..];

            let sender_pk = x25519_dalek::PublicKey::from(sender_pk_bytes);

            let shared_secret = my_sk.diffie_hellman(&sender_pk);

            let key = aes_gcm::Key::<Aes256Gcm>::from_slice(shared_secret.as_bytes());
            let cipher = Aes256Gcm::new(key);
            let nonce = Nonce::from_slice(&iv_bytes);

            let plaintext = cipher
                .decrypt(nonce, ciphertext)
                .expect("decryption failed");

            println!(
                "{}",
                String::from_utf8(plaintext).expect("decrypted data is not valid utf8")
            );
        }

        Commands::SssInfo => {

            match sss::State::load_private_only() {
                Ok(mut state) => {

                    println!("Moniker: {}", state.my_moniker);
                    if state.load_shared().is_ok() {
                        println!("Initialization ceremony complete.");

                        let (m, pk) = state.get_pub_params()?;

                        println!("M = {}", m);
                        println!("Shared Pubkey = {}", hex::encode(pk));

                        if state.have_my_share() {
                            println!("My share initialized");
                        } else {
                            println!("My share NOT initialized");
                            println!("My public key: {}", BASE64.encode(state.get_new_actor_pk()?.as_bytes()));

                        }

                    } else {

                    }


                }
                Err(_) => {
                    println!("Not initialized");
                }
            };

        }

        Commands::SssInitialize(args) => {

            let state = sss::State::new(args.moniker);
            state.save_private()?;

        }

        Commands::SssInitialPubData(args) => {

            let state = sss::State::load_private_only()?;
            let keys = state.generate_keys(args.m);

            let mut map = HashMap::<String, sss::InitPubData>::new();
            map.insert(state.my_moniker.clone(), keys);

            let json = serde_json::to_string(&map)?;
            println!("{json}");
        }

        Commands::SssInitCommon(args) => {

            let mut state = sss::State::load_private_only()?;
            let datas: HashMap<String, sss::InitPubData> = serde_json::from_str(&args.pub_datas).context("pub_data")?;

            let my_res = state.init_common(&datas)?;
            state.save_shared()?;

            let mut map = HashMap::new();
            map.insert(state.my_moniker, my_res);

            let json = serde_json::to_string(&sss::PartialShares(map))?;
            println!("{json}");
        }

        Commands::SssInitMyShare(args) => {

            let mut state = sss::State::load_full()?;
            let datas: HashMap<String, sss::InitPubData> = serde_json::from_str(&args.pub_datas).context("pub_data")?;
            let partial_shares: sss::PartialShares = serde_json::from_str(&args.partial_shares).context("partial_shares")?;

            state.import_shares(&datas, &partial_shares.0)?;
            state.save_private()?;
        }

        Commands::SssGetNonce => {
            let mut rng = rand::rngs::OsRng;
            let sk = curve25519_dalek::scalar::Scalar::random(&mut rng);
            let pk = sk * &curve25519_dalek::constants::ED25519_BASEPOINT_POINT;

            println!("nonce_priv = {}", BASE64.encode(sk.as_bytes()));
            println!("nonce_pub = {}", BASE64.encode(pk.compress().as_bytes()));

        }

        Commands::SssSign(args) => {
            let state = sss::State::load_full()?;

            let msg = hex::decode(args.message)?;
            let pub_nonces_obj: sss::StrVecMap = serde_json::from_str(&args.pub_nonces).context("pub_nonces")?;
            let pub_nonces = pub_nonces_obj.0;
            let mut partial_sigs: sss::StrVecMap = serde_json::from_str(&args.partial_sigs).context("partial_sigs")?;

            let (total_nonce_bytes, quorum) = sss::State::get_total_nonce_and_quorum(&pub_nonces)?;


            if partial_sigs.0.contains_key(&state.my_moniker) {
                println!("already included");
            } else
            {
                let mut res = state.get_partial_sig(&total_nonce_bytes, &msg, &quorum)?;

                let my_nonce: [u8; 32] = BASE64.decode(args.my_nonce)
                    .map_err(|_| anyhow::anyhow!("BASE64 decode failed"))?
                    .as_slice().try_into()?;

                res += Scalar::from_bytes_mod_order(my_nonce);

                partial_sigs.0.insert(state.my_moniker.clone(), res.as_bytes().to_vec());


                let json = serde_json::to_string(&partial_sigs)?;
                println!("sigs = {}", json);
            }

            if partial_sigs.0.len() == pub_nonces.len() {

                // assemble and check the signature
                let mut sig_k = Scalar::zero();

                for (_, sk_vec) in partial_sigs.0.iter() {
                    let sk_bytes: [u8; 32] = sk_vec.as_slice().try_into()?;
                    sig_k += Scalar::from_bytes_mod_order(sk_bytes);
                }
                
                let mut sig_bytes = [0u8; 64];
                sig_bytes[..32].copy_from_slice(&total_nonce_bytes);
                sig_bytes[32..].copy_from_slice(&sig_k.to_bytes());


                // verify signature
                let sig_obj = ed25519_dalek::Signature::from_bytes(sig_bytes.as_slice())?;

                let shared_pubkey = ed25519_dalek::PublicKey::from_bytes(&state.get_pub_params()?.1)?;
                let verify_result = shared_pubkey.verify_strict(&msg, &sig_obj);

                if let Err(e) = verify_result {
                    println!("sig_error: {}", e);
                } else {
                    println!("full_signature: {}", hex::encode(sig_bytes));
                }

            }

        }

        Commands::SssAddNew(args) => {
            let state = sss::State::load_full()?;
            let other_pk= BASE64.decode(args.pubkey)
                .map_err(|_| anyhow::anyhow!("BASE64 decode failed"))
                .context("pubkey")?;

            let quorum: HashSet<String> = serde_json::from_str(&args.quorum).context("quorum")?;

            let encrypted_share = state.get_new_actor_partial_share(&args.moniker, &other_pk, &quorum)?;

            let mut map = HashMap::new();
            map.insert(state.my_moniker, BASE64.encode(encrypted_share));

            let json = serde_json::to_string(&map)?;
            println!("{json}");
        }

        Commands::SssInitNew(args) => {
            let mut state = sss::State::load_full()?;
            if state.have_my_share() {
                anyhow::bail!("Already have my share");
            }

            let partial_shares: sss::StrVecMap = serde_json::from_str(&args.partial_shares).context("partial_shares")?;
            state.import_new_actor_partial_shares(&partial_shares.0)?;

            state.save_private()?;

        }

    }

    Ok(())
}
