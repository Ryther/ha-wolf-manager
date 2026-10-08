use std::io;
use uuid::Uuid;
use wolf_core::*;
use wolf_manager_host::dispatcher::dispatch;
fn request() -> RpcRequest {
    RpcRequest {
        version: 1,
        request_id: Uuid::new_v4(),
        pc_id: PcId::new("office").unwrap(),
        operation: RpcOperation::Stop(EmptyPayload {}),
    }
}
#[test]
fn only_exact_forced_command_reaches_helper_with_validated_json() {
    let request = request();
    let bytes = canonical_json(&request).unwrap();
    let response = RpcResponse {
        version: 1,
        request_id: request.request_id,
        pc_id: request.pc_id.clone(),
        ok: false,
        result: None,
        error: Some(SafeError::new("host_unavailable")),
    };
    let expected = canonical_json(&response).unwrap();
    let actual = dispatch("wolf-manager-rpc-v1", &bytes[..], |input| {
        assert_eq!(input, bytes);
        Ok(expected.clone())
    })
    .unwrap();
    assert_eq!(actual, expected);
}
#[test]
fn invalid_command_payload_or_oversize_never_calls_privileged_helper() {
    let bytes = canonical_json(&request()).unwrap();
    for command in [
        "",
        "id",
        "wolf-manager-rpc-v1; id",
        "wolf-manager-rpc-v1 --unit sshd",
    ] {
        assert!(dispatch(command, &bytes[..], |_| panic!("helper called")).is_err());
    }
    assert!(
        dispatch("wolf-manager-rpc-v1", &b"{}"[..], |_| panic!(
            "helper called"
        ))
        .is_err()
    );
    assert!(
        dispatch("wolf-manager-rpc-v1", &vec![b' '; 65537][..], |_| panic!(
            "helper called"
        ))
        .is_err()
    );
}
#[test]
fn helper_reply_must_match_request_and_output_bound() {
    let bytes = canonical_json(&request()).unwrap();
    assert!(
        dispatch("wolf-manager-rpc-v1", &bytes[..], |_| Ok(vec![
            b' ';
            1024 * 1024
                + 1
        ]))
        .is_err()
    );
    let other = request();
    let mismatched = RpcResponse {
        version: 1,
        request_id: other.request_id,
        pc_id: other.pc_id,
        ok: false,
        result: None,
        error: Some(SafeError::validation()),
    };
    assert!(
        dispatch("wolf-manager-rpc-v1", &bytes[..], |_| Ok(canonical_json(
            &mismatched
        )
        .unwrap()))
        .is_err()
    );
    assert!(
        dispatch("wolf-manager-rpc-v1", &bytes[..], |_| Err(
            io::Error::other("unavailable")
        ))
        .is_err()
    );
}
