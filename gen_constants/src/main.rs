extern crate num;
extern crate num_bigint;
extern crate num_traits;

use tiny_keccak::Keccak;

use num_bigint::{BigInt, Sign};
use num_traits::Zero;

const SEED: &str = "mimc";

pub struct Constants {
    // seed_hash: BigInt,
    // iv: BigInt,
    r: BigInt,
    n_rounds: i64,
    cts: Vec<BigInt>,
}

pub fn modulus(a: &BigInt, m: &BigInt) -> BigInt {
    ((a % m) + m) % m
}

pub fn generate_constants() -> Constants {
    let r: BigInt = BigInt::parse_bytes(
        b"21888242871839275222246405745257275088548364400416034343698204186575808495617",
        10,
    )
    .unwrap();

    let mut keccak = Keccak::new_keccak256();
    let mut h = [0u8; 32];
    keccak.update(SEED.as_bytes());
    keccak.finalize(&mut h);
    let mut keccak = Keccak::new_keccak256();
    let mut h_iv = [0u8; 32];
    let seed_iv = format!("{}{}", SEED, "_iv");
    keccak.update(seed_iv.as_bytes());
    keccak.finalize(&mut h_iv);

    // let seed_hash: BigInt = BigInt::from_bytes_be(Sign::Plus, &h);
    // let c: BigInt = BigInt::from_bytes_be(Sign::Plus, &h_iv);
    // let iv: BigInt = c % &r;
    let n_rounds: i64 = 91;
    let cts = get_constants(&r, SEED, n_rounds);

    Constants {
        // seed_hash: seed_hash,
        // iv: iv,
        r: r,
        n_rounds: n_rounds,
        cts: cts,
    }
}

pub fn get_constants(r: &BigInt, seed: &str, n_rounds: i64) -> Vec<BigInt> {
    let mut cts: Vec<BigInt> = Vec::new();
    cts.push(Zero::zero());

    let mut keccak = Keccak::new_keccak256();
    let mut h = [0u8; 32];
    keccak.update(seed.as_bytes());
    keccak.finalize(&mut h);

    let mut c = BigInt::from_bytes_be(Sign::Plus, &h);
    for _ in 1..n_rounds {
        let (_, c_bytes) = c.to_bytes_be();
        let mut c_bytes32: [u8; 32] = [0; 32];
        let diff = c_bytes32.len() - c_bytes.len();
        c_bytes32[diff..].copy_from_slice(&c_bytes[..]);

        let mut keccak = Keccak::new_keccak256();
        let mut h = [0u8; 32];
        keccak.update(&c_bytes[..]);
        keccak.finalize(&mut h);
        c = BigInt::from_bytes_be(Sign::Plus, &h);

        let n = modulus(&c, &r);
        cts.push(n);
    }
    // let l = cts.len();
    // cts[l-1] = Zero::zero();
    cts
}

fn main() {
    let c = generate_constants();
    println!("let cts_str: Vec<&str> = vec![");
    for i in 0..c.cts.len() {
        println!("  {:?},", c.cts[i].to_string());
    }
    println!("];");
    println!("let r: Fr = Fr::from_str(");
    println!("  {:?},", c.r.to_string());
    println!(").unwrap();");
    println!("let n_rounds: i64 = {:?};", c.n_rounds);
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustc_hex::ToHex;

    #[test]
    fn test_sha3() {
        let mut keccak = Keccak::new_keccak256();
        let mut res = [0u8; 32];
        keccak.update(SEED.as_bytes());
        keccak.finalize(&mut res);
        assert_eq!(
            res.to_hex(),
            "b6e489e6b37224a50bebfddbe7d89fa8fdcaa84304a70bd13f79b5d9f7951e9e"
        );

        let mut keccak = Keccak::new_keccak256();
        let mut res = [0u8; 32];
        keccak.update(SEED.as_bytes());
        keccak.finalize(&mut res);
        let c = BigInt::from_bytes_be(Sign::Plus, &res);
        assert_eq!(
            c.to_string(),
            "82724731331859054037315113496710413141112897654334566532528783843265082629790"
        );
    }
}
