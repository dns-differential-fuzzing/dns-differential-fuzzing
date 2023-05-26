#![cfg(FALSE)]

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, SamplingMode};
use fuzzer::FuzzingStateBench;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::io::BufWriter;

fn rmp_named_serialize<T: Serialize + DeserializeOwned>((t, path): &(&T, &str)) {
    let _ = black_box(rmp_serde::encode::write_named(
        &mut BufWriter::with_capacity(
            10 * 1024 * 1024,
            misc_utils::fs::WriteBuilder::new(path.into())
                .compression_level(misc_utils::fs::Compression::Fastest)
                .truncate()
                .unwrap(),
        ),
        t,
    ));
}

fn rmp_named_serialize_buffer<T: Serialize + DeserializeOwned>((t, path): &(&T, &str)) {
    let data = rmp_serde::encode::to_vec_named(t).unwrap();
    let _ = black_box(
        misc_utils::fs::WriteBuilder::new(path.into())
            .compression_level(misc_utils::fs::Compression::Fastest)
            .truncate()
            .unwrap()
            .write_all(&data),
    );
}

fn bincode_serialize<T: Serialize + DeserializeOwned>((t, path): &(&T, &str)) {
    let _ = black_box(bincode::serialize_into(
        &mut misc_utils::fs::WriteBuilder::new(path.into())
            .compression_level(misc_utils::fs::Compression::Fastest)
            .truncate()
            .unwrap(),
        t,
    ));
}

fn bincode_serialize_buffer<T: Serialize + DeserializeOwned>((t, path): &(&T, &str)) {
    let data = bincode::serialize(t).unwrap();
    let _ = black_box(
        misc_utils::fs::WriteBuilder::new(path.into())
            .compression_level(misc_utils::fs::Compression::Fastest)
            .truncate()
            .unwrap()
            .write_all(&data),
    );
}

fn fuzz_state_json_serialize(c: &mut Criterion) {
    let data = misc_utils::fs::read("../fuzzing-state.json.gz").unwrap();
    let data: FuzzingStateBench = serde_json::from_slice(&data).unwrap();

    let mut c = c.benchmark_group("JSON Serialize");
    c.sampling_mode(SamplingMode::Flat);
    c.sample_size(10);

    for path in ["/tmp/fuzzing-state.json", "/tmp/fuzzing-state.json.gz"] {
        c.bench_with_input(
            BenchmarkId::new("MessagePack Named Serialize", path),
            &(&data, path),
            |b, data| {
                b.iter(|| rmp_named_serialize(data));
            },
        );
        c.bench_with_input(
            BenchmarkId::new("MessagePack Named Serialize Buffer", path),
            &(&data, path),
            |b, data| {
                b.iter(|| rmp_named_serialize_buffer(data));
            },
        );
        c.bench_with_input(
            BenchmarkId::new("Bincode Serialize", path),
            &(&data, path),
            |b, data| {
                b.iter(|| bincode_serialize(data));
            },
        );
        c.bench_with_input(
            BenchmarkId::new("Bincode Serialize Buffer", path),
            &(&data, path),
            |b, data| {
                b.iter(|| bincode_serialize_buffer(data));
            },
        );
    }
    c.finish();
}

// fn fuzz_state_roundtrip(c: &mut Criterion) {
//     let data = misc_utils::fs::read("../fuzzing-state.json.gz").unwrap();
//     let data: FuzzingStateBench = serde_json::from_slice(&data).unwrap();

//     let mut c = c.benchmark_group("flat-sampling-example");
//     c.sampling_mode(SamplingMode::Flat);
//     c.sample_size(20);

//     c.bench_with_input(
//         BenchmarkId::new("FuzzState Round-Trip", "json"),
//         &data,
//         |b, data| {
//             b.iter(|| json_round_trip(data));
//         },
//     );

//     c.bench_with_input(
//         BenchmarkId::new("FuzzState Round-Trip", "messagepack"),
//         &data,
//         |b, data| {
//             b.iter(|| messagepack_round_trip(data));
//         },
//     );

//     c.bench_with_input(
//         BenchmarkId::new("FuzzState Round-Trip", "bincode"),
//         &data,
//         |b, data| {
//             b.iter(|| bincode_round_trip(data));
//         },
//     );
//     c.finish();
// }

// criterion_group!(benches, fuzz_state_roundtrip);
criterion_group!(benches, fuzz_state_json_serialize);
criterion_main!(benches);
