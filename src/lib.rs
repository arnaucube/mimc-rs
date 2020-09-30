extern crate rand;
#[macro_use]
extern crate ff;
use ff::*;

#[derive(PrimeField)]
#[PrimeFieldModulus = "21888242871839275222246405745257275088548364400416034343698204186575808495617"]
#[PrimeFieldGenerator = "7"]
pub struct Fr(FrRepr);

extern crate num;
extern crate num_bigint;
use num_bigint::{BigInt, Sign};
use tiny_keccak::Keccak;

const SEED: &str = "mimc";

pub struct Constants {
    n_rounds: usize,
    cts: Vec<Fr>,
}

pub fn generate_constants(n_rounds: usize) -> Constants {
    let cts = get_constants(SEED, n_rounds);

    Constants {
        n_rounds: n_rounds,
        cts: cts,
    }
}

pub fn get_constants(seed: &str, n_rounds: usize) -> Vec<Fr> {
    let mut cts: Vec<Fr> = Vec::new();
    cts.push(Fr::zero());

    let mut keccak = Keccak::new_keccak256();
    let mut h = [0u8; 32];
    keccak.update(seed.as_bytes());
    keccak.finalize(&mut h);

    let r: BigInt = BigInt::parse_bytes(
        b"21888242871839275222246405745257275088548364400416034343698204186575808495617",
        10,
    )
    .unwrap();

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
        cts.push(Fr::from_str(&n.to_string()).unwrap());
    }
    cts
}

pub fn modulus(a: &BigInt, m: &BigInt) -> BigInt {
    ((a % m) + m) % m
}

pub struct Mimc7 {
    constants: Constants,
}

impl Mimc7 {
    pub fn new(n_rounds: usize) -> Mimc7 {
        Mimc7 {
            constants: generate_constants(n_rounds),
        }
    }

    pub fn hash(&self, x_in: &Fr, k: &Fr) -> Fr {
        let mut h: Fr = Fr::zero();
        for i in 0..self.constants.n_rounds {
            let mut t: Fr;
            if i == 0 {
                t = x_in.clone();
                t.add_assign(k);
            } else {
                t = h.clone();
                t.add_assign(&k);
                t.add_assign(&self.constants.cts[i]);
            }
            let mut t2 = t.clone();
            t2.square();
            let mut t7 = t2.clone();
            t7.square();
            t7.mul_assign(&t2);
            t7.mul_assign(&t);
            h = t7.clone();
        }
        h.add_assign(&k);
        h
    }

    pub fn multi_hash(&self, arr: Vec<Fr>, key: &Fr) -> Fr {
        let mut r = key.clone();
        for i in 0..arr.len() {
            let h = self.hash(&arr[i], &r);
            r.add_assign(&arr[i]);
            r.add_assign(&h);
        }
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_constants() {
        let constants = generate_constants(91);
        assert_eq!(
            "Fr(0x2e2ebbb178296b63d88ec198f0976ad98bc1d4eb0d921ddd2eb86cb7e70a98e5)",
            constants.cts[1].to_string()
        );
    }

    #[test]
    fn test_mimc() {
        let b1: Fr = Fr::from_str("1").unwrap();
        let b2: Fr = Fr::from_str("2").unwrap();
        let mimc7 = Mimc7::new(91);
        let h1 = mimc7.hash(&b1, &b2);
        assert_eq!(
            h1.to_string(),
            "Fr(0x176c6eefc3fdf8d6136002d8e6f7a885bbd1c4e3957b93ddc1ec3ae7859f1a08)"
        );

        let b3: Fr = Fr::from_str("3").unwrap();
        let mut arr: Vec<Fr> = Vec::new();
        arr.push(b1.clone());
        arr.push(b2.clone());
        arr.push(b3.clone());
        let h1 = mimc7.multi_hash(arr, &Fr::zero());
        assert_eq!(
            h1.to_string(),
            "Fr(0x25f5a6429a9764564be3955e6f56b0b9143c571528fd30a80ae6c27dc8b4a40c)"
        );

        let b12: Fr = Fr::from_str("12").unwrap();
        let b45: Fr = Fr::from_str("45").unwrap();
        let b78: Fr = Fr::from_str("78").unwrap();
        let b41: Fr = Fr::from_str("41").unwrap();

        let mut big_arr1: Vec<Fr> = Vec::new();
        big_arr1.push(b12.clone());
        let mimc7 = Mimc7::new(91);
        let h1 = mimc7.multi_hash(big_arr1, &Fr::zero());
        assert_eq!(
            h1.to_string(),
            "Fr(0x237c92644dbddb86d8a259e0e923aaab65a93f1ec5758b8799988894ac0958fd)"
        );

        let mh2 = mimc7.hash(&b12, &b45);
        assert_eq!(
            mh2.to_string(),
            "Fr(0x2ba7ebad3c6b6f5a20bdecba2333c63173ca1a5f2f49d958081d9fa7179c44e4)"
        );

        let mut big_arr1: Vec<Fr> = Vec::new();
        big_arr1.push(b78.clone());
        big_arr1.push(b41.clone());
        let h2 = mimc7.multi_hash(big_arr1, &Fr::zero());
        assert_eq!(
            h2.to_string(),
            "Fr(0x067f3202335ea256ae6e6aadcd2d5f7f4b06a00b2d1e0de903980d5ab552dc70)"
        );

        let mut big_arr1: Vec<Fr> = Vec::new();
        big_arr1.push(b12.clone());
        big_arr1.push(b45.clone());
        let h1 = mimc7.multi_hash(big_arr1, &Fr::zero());
        assert_eq!(
            h1.to_string(),
            "Fr(0x15ff7fe9793346a17c3150804bcb36d161c8662b110c50f55ccb7113948d8879)"
        );

        let mut big_arr1: Vec<Fr> = Vec::new();
        big_arr1.push(b12.clone());
        big_arr1.push(b45.clone());
        big_arr1.push(b78.clone());
        big_arr1.push(b41.clone());
        let mimc7 = Mimc7::new(91);
        let h1 = mimc7.multi_hash(big_arr1, &Fr::zero());
        assert_eq!(
            h1.to_string(),
            "Fr(0x284bc1f34f335933a23a433b6ff3ee179d682cd5e5e2fcdd2d964afa85104beb)"
        );

        let r_1: Fr = Fr::from_str(
            "21888242871839275222246405745257275088548364400416034343698204186575808495616",
        )
        .unwrap();

        let mut big_arr1: Vec<Fr> = Vec::new();
        big_arr1.push(r_1.clone());
        let mimc7 = Mimc7::new(91);
        let h1 = mimc7.multi_hash(big_arr1, &Fr::zero());
        assert_eq!(
            h1.to_string(),
            "Fr(0x0a4fffe99225f9972ec39fd780dd084f349286c723d4dd42ad05e2e7421fef0e)"
        );
    }
}
