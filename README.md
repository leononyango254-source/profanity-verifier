# profanity-verifier

Provable check for **CVE-2022-40769**: does an EOA's private key lie in the key space reachable by the Profanity vanity-address generator? If yes, the key is recoverable and the account (and anything it controls) is drainable by anyone.

No heuristics. The result is a boolean backed by a full search of the exact key space, reproducible by re-running the same shard.

## The bug, from the original source

`Dispatcher.cpp`, `createSeed()`:

```c
std::random_device rd;
std::mt19937_64 eng(rd());                 // seeded with only 32 bits  <- CVE-2022-40769
std::uniform_int_distribution<cl_ulong> distr;
cl_ulong4 r;
r.s[0] = distr(eng); r.s[1] = distr(eng);  // 256-bit seed, used directly
r.s[2] = distr(eng); r.s[3] = distr(eng);  // as the private key
```

The OpenCL kernel then takes `G^k` for that key and walks forward, incrementing the key by one per round until the address matches the requested pattern. So the entire reachable key space is:

```
key(x, i) = mt19937_64(x) as a 256-bit scalar + i
x ∈ [0, 2^32)    the 32-bit seed (four billion possibilities)
i ∈ [0, depth]   rounds the generator ran
```

## What this program does

1. Walks **down** from the candidate's public key: `P_j = P − j·G` for `j ≤ depth`. If Profanity made the key, one of these points is a seed public key.
2. Scans the seeds in its shard; for each `x` it derives `mt19937_64(x)` and its address.
3. A match means `P_j` is the seed public key, so the candidate's private key is `seed(x) + j` — recoverable, therefore drainable.

A match is proof. **No match over the full seed range is proof of the opposite, up to the chosen depth.**

## Verified

- **MT19937-64 matches libstdc++ exactly.** Raw `std::mt19937_64` draws for seeds 0, 1, 12345 and 4294967295 were compared limb for limb against a `g++` program using `std::mt19937_64` + `std::uniform_int_distribution<unsigned long long>`; identical.
- **Two independent curve libraries agree.** The same test vectors were produced with `k256` (pure Rust) and `secp256k1` (libsecp256k1 bindings): seed 0 → `0xfef2583edde5637dad990bc5d05d52c8247019cf`, seed 12345 → `0x7712c45360f5dfa3a622a815b6073f0351050f13`.
- **`--selftest`** asserts derivation, address, chain walk, walk-down recovery, and an end-to-end seed scan that finds a known seed.

Run it yourself:

```
cargo run --release -- --selftest
```

## Usage

```
profanity-verifier --address 0x... [--pubkey 0x...] --shard i/n [--depth 16777216]
```

- `--pubkey` — the candidate's uncompressed public key (64 bytes of x||y, with or without the `0x04` prefix). Recover it from any transaction the address has signed. Without it, only chain position 0 can be tested.
- `--shard i/n` — the slice of the 32-bit seed space to search, so the work parallelises across machines.
- `--depth` — how far along the generator's chain to look. 2^24 covers a six-character vanity with room to spare; deeper costs memory and time.

Output is a single JSON line, e.g.:

```json
{"address":"0x...","shard":"0/64","depth":16777216,"seeds_checked":67108864,"seconds":833.4,"match":true}
```

**The seed and the private key are never printed or stored.** Only the boolean, the address and the shard are emitted, so a result can be published without handing anyone the key.

## Running at scale

`.github/workflows/verify.yml` fans the search out over a matrix of `(candidate, shard)` jobs on public runners.

Measured throughput: **~20,000 seeds/s on 2 cores** (libsecp256k1). The full 2^32 seed space is ~59 core-hours, so 64 shards × 4 cores ≈ **14 minutes wall clock per candidate** — free on a public repository.

Dispatch with the candidate list:

```
gh workflow run profanity-verify -f candidates='[{"address":"0x...","pubkey":"0x..."}]' -f shards=64
```

## Limitations

- Assumes the generator used **libstdc++'s `std::mt19937_64`**, which the limb-for-limb comparison covers. Builds against a different standard library would have a different mapping.
- `depth` bounds the search. A candidate generated after an unusually long search (very long vanity patterns) can sit beyond it.
- Full coverage requires a public key. Without a signature from the address, only chain position 0 is testable.
- A negative result says "not in the Profanity space" — it says nothing about any other weakness.
