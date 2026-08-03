use crate::model;
use crate::model::Os;
use crate::model::raw::{BenchmarkType, BinaryType};
use serde_json::json;

#[test]
fn os_maps_to_numeric_code() {
    for (os, wire) in [(Os::Linux, 0), (Os::Windows, 1), (Os::Darwin, 2)] {
        assert_eq!(u8::from(os), wire);
    }
}

#[test]
fn os_detect_matches_the_build_target() {
    let expected = if cfg!(target_os = "linux") {
        0
    } else if cfg!(target_os = "windows") {
        1
    } else {
        2
    };

    assert_eq!(u8::from(Os::detect()), expected);
}

#[test]
fn benchmark_type_round_trips_through_wire() {
    for (bench, wire) in [
        (model::BenchmarkType::Speed, "speed"),
        (model::BenchmarkType::Run, "run"),
    ] {
        assert_eq!(
            serde_json::to_value(BenchmarkType::from(bench)).unwrap(),
            json!(wire)
        );
        let decoded: BenchmarkType = serde_json::from_value(json!(wire)).unwrap();
        assert_eq!(model::BenchmarkType::from(decoded), bench);
    }
}

#[test]
fn binary_type_wire_values() {
    for (binary, wire) in [
        (BinaryType::Extractor, "7zr"),
        (BinaryType::Cracker, "cracker"),
        (BinaryType::Uftpd, "uftpd"),
        (BinaryType::Preprocessor, "preprocessor"),
    ] {
        assert_eq!(serde_json::to_value(binary).unwrap(), json!(wire));
    }
}
