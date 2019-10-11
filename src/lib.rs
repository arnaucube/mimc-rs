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
        let mut c_bytes32: [u8;32] = [0;32];
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

pub fn mimc7_hash_generic(r: &BigInt, x_in: &BigInt, k: &BigInt, n_rounds: i64) -> BigInt {
    let cts = get_constants(r, SEED, n_rounds);
    let mut h: BigInt = Zero::zero();
    for i in 0..n_rounds as usize {
        let mut t: BigInt;
        if i == 0 {
            t = x_in + k;
        } else {
            t = h + k + &cts[i];
        }
        t = modulus(&t, &r);
        let t2 = &t * &t;
        let t4 = &t2 * &t2;
        h = (t4 * t2) * t;
        h = modulus(&h, &r);
    }
    modulus(&(h + k), &r)
}

pub fn hash_generic(iv: BigInt, arr: Vec<BigInt>, r: BigInt, n_rounds: i64) -> BigInt {
    let mut h: BigInt = iv;
    for i in 0..arr.len() {
        h = mimc7_hash_generic(&r, &h, &arr[i], n_rounds);
    }
    h
}

pub fn check_bigint_in_field(a: &BigInt, q: &BigInt) -> bool {
    if a >= q {
        return false;
    }
    true
}

pub fn check_bigint_array_in_field(arr: &Vec<BigInt>, q: &BigInt) -> bool {
    for a in arr {
        if !check_bigint_in_field(a, &q) {
            return false;
        }
    }
    true
}

pub struct Mimc7 {
    constants: Constants,
}

impl Mimc7 {
    pub fn new() -> Mimc7 {
        Mimc7 {
            constants: generate_constants(),
        }
    }

    pub fn hash(&self, arr: Vec<BigInt>) -> Result<BigInt, String> {
        // check if arr elements are inside the Finite Field over R
        if !check_bigint_array_in_field(&arr, &self.constants.r) {
            return Err("elements not inside the finite field over R".to_string());
        }
        let mut h: BigInt = Zero::zero();
        for i in 0..arr.len() {
            h = &h + &arr[i] + self.mimc7_hash(&arr[i], &h);
            h = modulus(&h, &self.constants.r)
        }
        Ok(modulus(&h, &self.constants.r))
    }

    pub fn mimc7_hash(&self, x_in: &BigInt, k: &BigInt) -> BigInt {
        let mut h: BigInt = Zero::zero();
        for i in 0..self.constants.n_rounds as usize {
            let t: BigInt;
            if i == 0 {
                t = x_in + k;
            } else {
                t = h + k + &self.constants.cts[i];
            }
            let t2 = &t * &t;
            let t4 = &t2 * &t2;
            h = (t4 * t2) * t;
            h = modulus(&h, &self.constants.r);
        }
        modulus(&(h + k), &self.constants.r)
    }

    pub fn hash_bytes(&self, b: Vec<u8>) -> Result<BigInt, String> {
        let n = 31;
        let mut ints: Vec<BigInt> = Vec::new();
        for i in 0..b.len() / n {
            let v: BigInt = BigInt::from_bytes_le(Sign::Plus, &b[n * i..n * (i + 1)]);
            ints.push(v);
        }
        if b.len() % n != 0 {
            let v: BigInt = BigInt::from_bytes_le(Sign::Plus, &b[(b.len() / n) * n..]);
            ints.push(v);
        }
        self.hash(ints)
    }
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
    #[test]
    fn test_generate_constants() {
        let constants = generate_constants();
        assert_eq!(
            "20888961410941983456478427210666206549300505294776164667214940546594746570981",
            constants.cts[1].to_string()
        );
    }

    #[test]
    fn test_mimc7_generic() {
        let b1: BigInt = BigInt::parse_bytes(b"1", 10).unwrap();
        let b2: BigInt = BigInt::parse_bytes(b"2", 10).unwrap();
        let constants = generate_constants();
        let h1 = mimc7_hash_generic(&constants.r, &b1, &b2, 91);
        assert_eq!(
            h1.to_string(),
            "10594780656576967754230020536574539122676596303354946869887184401991294982664"
        );
    }

    #[test]
    fn test_check_bigint_in_field() {
        let r_0: BigInt = BigInt::parse_bytes(
            b"21888242871839275222246405745257275088548364400416034343698204186575808495617",
            10,
        )
        .unwrap();

        let mut big_arr0: Vec<BigInt> = Vec::new();
        big_arr0.push(r_0.clone());
        let mimc7 = Mimc7::new();
        let h0 = mimc7.hash(big_arr0);
        assert_eq!(h0.is_err(), true);

        let r_1: BigInt = BigInt::parse_bytes(
            b"21888242871839275222246405745257275088548364400416034343698204186575808495616",
            10,
        )
        .unwrap();

        let mut big_arr1: Vec<BigInt> = Vec::new();
        big_arr1.push(r_1.clone());
        let mimc7 = Mimc7::new();
        let h1 = mimc7.hash(big_arr1);
        assert_eq!(h1.is_err(), false);
        assert_eq!(
            h1.unwrap().to_string(),
            "4664475646327377862961796881776103845487084034023211145221745907673012891406"
        );
    }

    #[test]
    fn test_mimc7() {
        let b12: BigInt = BigInt::parse_bytes(b"12", 10).unwrap();
        let b45: BigInt = BigInt::parse_bytes(b"45", 10).unwrap();
        let b78: BigInt = BigInt::parse_bytes(b"78", 10).unwrap();
        let b41: BigInt = BigInt::parse_bytes(b"41", 10).unwrap();

        let mut big_arr1: Vec<BigInt> = Vec::new();
        big_arr1.push(b12.clone());
        let mimc7 = Mimc7::new();
        let h1 = mimc7.hash(big_arr1).unwrap();
        let (_, h1_bytes) = h1.to_bytes_be();
        assert_eq!(
            h1_bytes.to_hex(),
            "237c92644dbddb86d8a259e0e923aaab65a93f1ec5758b8799988894ac0958fd"
        );

        let mh2 = mimc7.mimc7_hash(&b12, &b45);
        let (_, mh2_bytes) = mh2.to_bytes_be();
        assert_eq!(
            mh2_bytes.to_hex(),
            "2ba7ebad3c6b6f5a20bdecba2333c63173ca1a5f2f49d958081d9fa7179c44e4"
        );

        let mut big_arr2: Vec<BigInt> = Vec::new();
        big_arr2.push(b78.clone());
        big_arr2.push(b41.clone());
        let h2 = mimc7.hash(big_arr2).unwrap();
        let (_, h2_bytes) = h2.to_bytes_be();
        assert_eq!(
            h2_bytes.to_hex(),
            "067f3202335ea256ae6e6aadcd2d5f7f4b06a00b2d1e0de903980d5ab552dc70"
        );

        let mut big_arr2: Vec<BigInt> = Vec::new();
        big_arr2.push(b12.clone());
        big_arr2.push(b45.clone());
        let h1 = mimc7.hash(big_arr2).unwrap();
        let (_, h1_bytes) = h1.to_bytes_be();
        assert_eq!(
            h1_bytes.to_hex(),
            "15ff7fe9793346a17c3150804bcb36d161c8662b110c50f55ccb7113948d8879"
        );

        let mut big_arr1: Vec<BigInt> = Vec::new();
        big_arr1.push(b12.clone());
        big_arr1.push(b45.clone());
        big_arr1.push(b78.clone());
        big_arr1.push(b41.clone());
        let mimc7 = Mimc7::new();
        let h1 = mimc7.hash(big_arr1).unwrap();
        let (_, h1_bytes) = h1.to_bytes_be();
        assert_eq!(
            h1_bytes.to_hex(),
            "284bc1f34f335933a23a433b6ff3ee179d682cd5e5e2fcdd2d964afa85104beb"
        );
    }
    #[test]
    fn test_hash_bytes() {
        let msg = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";
        let mimc7 = Mimc7::new();
        let h = mimc7.hash_bytes(msg.as_bytes().to_vec()).unwrap();
        assert_eq!(
            h.to_string(),
            "16855787120419064316734350414336285711017110414939748784029922801367685456065"
        );
    }
}
