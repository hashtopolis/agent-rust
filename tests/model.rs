use htp_agent::model::{Os, TaskId};
use serde_json::json;

#[test]
fn os_maps_to_and_from_wire_codes() {
    assert_eq!(Os::Linux.code(), 0);
    assert_eq!(Os::Windows.code(), 1);
    assert_eq!(Os::Darwin.code(), 2);

    assert_eq!(serde_json::to_value(Os::Linux).unwrap(), json!(0));
    assert_eq!(serde_json::to_value(Os::Windows).unwrap(), json!(1));
    assert_eq!(serde_json::to_value(Os::Darwin).unwrap(), json!(2));

    assert_eq!(serde_json::from_value::<Os>(json!(2)).unwrap(), Os::Darwin);
    assert!(serde_json::from_value::<Os>(json!(9)).is_err());
}

#[test]
fn os_binary_extension() {
    assert_eq!(Os::Windows.binary_extension(), ".exe");
    assert_eq!(Os::Linux.binary_extension(), "");
    assert_eq!(Os::Darwin.binary_extension(), "");
}

#[test]
fn task_id_classifies_the_overloaded_field() {
    assert_eq!(TaskId::from_raw(None), TaskId::None);
    assert_eq!(TaskId::from_raw(Some(-1)), TaskId::HealthCheck);
    assert_eq!(TaskId::from_raw(Some(0)), TaskId::Id(0));
    assert_eq!(TaskId::from_raw(Some(42)), TaskId::Id(42));
    assert_eq!(TaskId::from_raw(Some(-99)), TaskId::None);
}
