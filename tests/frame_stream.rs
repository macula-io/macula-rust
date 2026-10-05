//! Stream frames (D25 item 5): the provider's carry its key on its first frame
//! and not after, the caller's are verified with the key its STREAM_OPEN
//! carried, each side's seq runs from 0 without a gap, and nothing follows a
//! side's STREAM_END.

use macula_rust::cbor::{self, Value};
use macula_rust::frame::{
    open_stream, sign_caller_stream, sign_provider_stream, sign_stream_open, verify_caller_stream,
    verify_provider_stream, verify_request, FrameError, RequestSpec, StreamEncoding, StreamFields,
    StreamMode, StreamRole, StreamState, VerifiedRequest,
};
use macula_rust::node_key::{NodeKey, Purpose};
use macula_rust::profile::Profile;

const P: Profile = Profile::PqPure;

struct Stream {
    caller: NodeKey,
    provider: NodeKey,
    open: VerifiedRequest,
}

fn stream(mode: StreamMode) -> Stream {
    let caller = NodeKey::generate(Purpose::Identity, P).unwrap();
    let provider = NodeKey::generate(Purpose::Identity, P).unwrap();
    let spec = RequestSpec {
        request_id: [4; 16],
        realm: [3; 32],
        procedure: "acme/watch".to_string(),
        target: provider.key_id(),
        deadline: 1_789_000_005_000,
        payload: Value::Null,
        sealed: None,
        mode: Some(mode),
        token: None,
        proofs: Vec::new(),
        source_route: None,
        retry_budget: None,
    };
    let frame = sign_stream_open(&spec, &caller).unwrap();
    let open = verify_request(&arrived(&frame), P).unwrap();
    Stream {
        caller,
        provider,
        open,
    }
}

fn arrived(frame: &Value) -> Value {
    cbor::decode(&cbor::encode(frame).unwrap()).unwrap()
}

fn data(seq: u64, body: &[u8]) -> StreamFields {
    StreamFields::Data {
        seq,
        encoding: StreamEncoding::Raw,
        body: Value::Bytes(body.to_vec()),
    }
}

#[test]
fn a_provider_s_frames_carry_its_key_first_and_run_in_order() {
    let s = stream(StreamMode::ServerStream);
    let mut state = open_stream(&s.open).unwrap();
    let first = arrived(&sign_provider_stream(&data(0, b"one"), &s.open, &s.provider).unwrap());
    assert!(first.get("stream").and_then(|o| o.get("key")).is_some());
    let later = arrived(&sign_provider_stream(&data(1, b"two"), &s.open, &s.provider).unwrap());
    assert!(later.get("stream").and_then(|o| o.get("key")).is_none());
    let end = arrived(
        &sign_provider_stream(
            &StreamFields::End {
                seq: 2,
                role: StreamRole::Both,
            },
            &s.open,
            &s.provider,
        )
        .unwrap(),
    );

    // The later frame before the first: no key held yet.
    assert_eq!(
        verify_provider_stream(&later, &state, P).unwrap_err(),
        FrameError::SeqMismatch
    );
    for (frame, want) in [(&first, data(0, b"one")), (&later, data(1, b"two"))] {
        let (verified, next) = verify_provider_stream(frame, &state, P).unwrap();
        assert_eq!(verified.signer, s.provider.key_id());
        assert_eq!(verified.fields, want);
        state = next;
    }
    // The same frame again: out of order.
    assert_eq!(
        verify_provider_stream(&later, &state, P).unwrap_err(),
        FrameError::SeqMismatch
    );
    let (_, ended) = verify_provider_stream(&end, &state, P).unwrap();
    let after = arrived(&sign_provider_stream(&data(3, b"late"), &s.open, &s.provider).unwrap());
    assert_eq!(
        verify_provider_stream(&after, &ended, P).unwrap_err(),
        FrameError::StreamEnded
    );
}

#[test]
fn a_caller_s_frames_verify_with_the_stream_open_s_key() {
    let s = stream(StreamMode::ClientStream);
    let state = open_stream(&s.open).unwrap();
    let chunk = arrived(&sign_caller_stream(&data(0, b"up"), &s.open, &s.caller).unwrap());
    let (verified, state) = verify_caller_stream(&chunk, &state, P).unwrap();
    assert_eq!(verified.signer, s.caller.key_id());
    let end = arrived(
        &sign_caller_stream(
            &StreamFields::End {
                seq: 1,
                role: StreamRole::Send,
            },
            &s.open,
            &s.caller,
        )
        .unwrap(),
    );
    let (_, state) = verify_caller_stream(&end, &state, P).unwrap();

    // The provider answers a client_stream with a STREAM_REPLY; a caller sends
    // none.
    let reply = StreamFields::Reply {
        seq: 0,
        payload: Value::Int(6),
    };
    let from_provider = arrived(&sign_provider_stream(&reply, &s.open, &s.provider).unwrap());
    let (verified, _) = verify_provider_stream(&from_provider, &state, P).unwrap();
    assert_eq!(verified.fields, reply);
    assert!(matches!(
        sign_caller_stream(&reply, &s.open, &s.caller),
        Err(FrameError::NotAllowed(_))
    ));
}

#[test]
fn a_caller_sends_no_data_in_a_server_stream() {
    let s = stream(StreamMode::ServerStream);
    assert!(matches!(
        sign_caller_stream(&data(0, b"x"), &s.open, &s.caller),
        Err(FrameError::NotAllowed(_))
    ));
    // An end is allowed.
    assert!(sign_caller_stream(
        &StreamFields::End {
            seq: 0,
            role: StreamRole::Both
        },
        &s.open,
        &s.caller
    )
    .is_ok());
}

#[test]
fn a_stream_frame_for_another_stream_or_signer_is_refused() {
    let s = stream(StreamMode::Bidi);
    let other = stream(StreamMode::Bidi);
    let state: StreamState = open_stream(&s.open).unwrap();
    // Signed by the provider of another stream: unsignable here, and refused
    // when it arrives.
    assert_eq!(
        sign_provider_stream(&data(0, b"x"), &s.open, &other.provider).unwrap_err(),
        FrameError::Unsignable
    );
    let foreign =
        arrived(&sign_provider_stream(&data(0, b"x"), &other.open, &other.provider).unwrap());
    assert_eq!(
        verify_provider_stream(&foreign, &state, P).unwrap_err(),
        FrameError::RequestMismatch
    );
    let raw_value = StreamFields::Data {
        seq: 0,
        encoding: StreamEncoding::Raw,
        body: Value::Int(1),
    };
    assert!(matches!(
        sign_provider_stream(&raw_value, &s.open, &s.provider),
        Err(FrameError::OutOfRange(_))
    ));
    let error = StreamFields::Error {
        seq: 0,
        code: "c".repeat(65),
        message: String::new(),
    };
    assert!(matches!(
        sign_provider_stream(&error, &s.open, &s.provider),
        Err(FrameError::TextTooLong(_))
    ));
}

#[test]
fn a_stream_opens_only_on_a_stream_open() {
    let s = stream(StreamMode::Bidi);
    let mut call = s.open.clone();
    call.frame_type = macula_rust::frame::RequestType::Call;
    call.mode = None;
    assert!(matches!(open_stream(&call), Err(FrameError::OutOfRange(_))));
}
