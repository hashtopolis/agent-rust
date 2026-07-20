use htp_agent::model::Os;

#[test]
fn os_binary_extension() {
    assert_eq!(Os::Windows.binary_extension(), ".exe");
    assert_eq!(Os::Linux.binary_extension(), "");
    assert_eq!(Os::Darwin.binary_extension(), "");
}
