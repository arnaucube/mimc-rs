use criterion::{criterion_group, criterion_main, Criterion};

#[macro_use]
extern crate ff;
use ff::*;

use mimc_rs::{Fr, Mimc7};

fn criterion_benchmark(c: &mut Criterion) {
    let b1: Fr = Fr::from_str(
        "12242166908188651009877250812424843524687801523336557272219921456462821518061",
    )
    .unwrap();
    let b2: Fr = Fr::from_str(
        "12242166908188651009877250812424843524687801523336557272219921456462821518061",
    )
    .unwrap();
    let mimc7 = Mimc7::new(91);

    c.bench_function("hash", |b| b.iter(|| mimc7.hash(&b1, &b2)));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
