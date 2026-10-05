//! E2E seal scheme 1 against macula's vectors (tests/vectors/seal/
//! e2e_seal_v1.json, macula v13.3.0), as E2E_SEAL_V1.md's "What an SDK must
//! pass" lists it: the key as carried, its hash and id; the recipient's side
//! of the shared secret, exactly; every derived key; every AAD; SEAL and
//! OPEN, and one flipped bit refused; the sender's side by round trip; every
//! refusal refused. The sender's ML-KEM randomness (`encaps_m`) is FIPS 203's
//! seeded interface, which aws-lc-rs does not expose, so the sender's side is
//! checked by round trip, as the spec allows.

use serde_json::Value as Json;

use super::*;

fn vectors() -> Json {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/seal/e2e_seal_v1.json"
    ))
    .unwrap();
    serde_json::from_str(&text).unwrap()
}

fn b(v: &Json) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

fn fixed<const N: usize>(v: &Json) -> [u8; N] {
    b(v).try_into().unwrap()
}

fn profile_of(v: &Json) -> Profile {
    Profile::parse(v.as_str().unwrap()).unwrap()
}

/// A recipient from its vector entry: the expanded decapsulation key, the
/// key as carried, and the P-384 scalar in pq_hybrid.
fn recipient(r: &Json, profile: Profile) -> PrivateKey {
    let scalar = r.get("p384_priv").map(b);
    PrivateKey::from_parts(
        profile,
        &b(&r["mlkem_dk"]),
        &b(&r["key_as_carried"]),
        scalar.as_deref(),
    )
    .unwrap()
}

fn sealed_and_opened(key: &[u8; 32], entry: &Json, what: &str) {
    let nonce: [u8; NONCE_SIZE] = fixed(&entry["nonce"]);
    let (aad, plain, ct) = (b(&entry["aad"]), b(&entry["plain"]), b(&entry["ct"]));
    assert_eq!(seal(key, &nonce, &aad, &plain), ct, "{what}: SEAL");
    assert_eq!(open(key, &nonce, &aad, &ct), Ok(plain), "{what}: OPEN");
    let mut flipped = ct.clone();
    flipped[0] ^= 1;
    assert_eq!(
        open(key, &nonce, &aad, &flipped),
        Err(SealError::Refused),
        "{what}: a flipped bit"
    );
}

#[test]
fn the_recipients_keys_are_carried_hashed_and_named_as_macula_names_them() {
    let v = vectors();
    for (name, r) in v["recipients"].as_object().unwrap() {
        let profile = Profile::parse(name).unwrap();
        let key = recipient(r, profile);
        let carried = key.public_key().carried();
        assert_eq!(carried, b(&r["key_as_carried"]).as_slice(), "{name}");
        assert_eq!(carried.len(), carried_key_size(profile), "{name}");
        assert_eq!(key_hash(carried).to_vec(), b(&r["key_hash"]), "{name}");
        assert_eq!(key_id(carried).to_vec(), b(&r["key_id"]), "{name}");
        assert_eq!(key.mlkem_dk().unwrap(), b(&r["mlkem_dk"]), "{name}");
        assert_eq!(
            parse_public_key(profile, carried).unwrap(),
            *key.public_key(),
            "{name}"
        );
    }
}

#[test]
fn every_call_and_stream_vector_reaches_macula_s_bytes() {
    let v = vectors();
    let calls = v["calls"].as_array().unwrap();
    assert_eq!(calls.len(), 4);
    for c in calls {
        let profile = profile_of(&c["profile"]);
        let frame_type = c["frame_type"].as_str().unwrap();
        let what = format!("{} {frame_type}", profile.name());
        let key = recipient(&v["recipients"][profile.name()], profile);
        assert_eq!(
            key.public_key().key_id().to_vec(),
            b(&c["key_id"]),
            "{what}"
        );

        // The combiner's input, from the vector's own parts.
        let key_hash = key_hash(key.public_key().carried());
        let ikm = match profile {
            Profile::PqPure => pure_ikm(&b(&c["ss_mlkem"]), &b(&c["mlkem_ct"]), &key_hash),
            Profile::PqHybrid => hybrid_ikm(
                &b(&c["ss_mlkem"]),
                &b(&c["ss_ecdh"]),
                &b(&c["mlkem_ct"]),
                &b(&c["eph_pub"]),
                &key_hash,
            ),
        };
        assert_eq!(ikm, b(&c["ikm"]), "{what}: ikm");

        // The recipient's side, exactly.
        let ss = recipient_secret(&key, &b(&c["kem_ct"])).unwrap();
        assert_eq!(ss.to_vec(), b(&c["ss"]), "{what}: ss");
        if let (Some(p384), Some(eph_pub)) = (&key.p384, c.get("eph_pub")) {
            assert_eq!(
                ecdh_secret(p384, &b(eph_pub)).unwrap(),
                b(&c["ss_ecdh"]),
                "{what}: ss_ecdh"
            );
        }

        let parties = Parties {
            request_id: fixed(&c["request_id"]),
            caller: fixed(&c["caller"]),
            target: fixed(&c["target"]),
        };
        let (k_req, k_rep) = call_keys(&ss, frame_type, &parties);
        assert_eq!(k_req.to_vec(), b(&c["k_req"]), "{what}: k_req");
        assert_eq!(k_rep.to_vec(), b(&c["k_rep"]), "{what}: k_rep");

        let request = Request {
            frame_type: frame_type.to_string(),
            realm: fixed(&c["realm"]),
            procedure: c["procedure"].as_str().unwrap().to_string(),
            caller: parties.caller,
            target: parties.target,
            request_id: parties.request_id,
            deadline: c["deadline"].as_u64().unwrap(),
        };
        assert_eq!(
            request_aad(&request),
            b(&c["request"]["aad"]),
            "{what}: request AAD"
        );
        assert_eq!(b(&c["request"]["nonce"]), vec![0; NONCE_SIZE]);
        sealed_and_opened(&k_req, &c["request"], &format!("{what} request"));

        for reply in ["reply", "error_reply"] {
            let Some(r) = c.get(reply) else { continue };
            let aad = reply_aad(
                &request,
                r["frame_type"].as_str().unwrap(),
                &fixed(&r["request_hash"]),
                &fixed(&r["responded_by"]),
            );
            assert_eq!(aad, b(&r["aad"]), "{what}: {reply} AAD");
            sealed_and_opened(&k_rep, r, &format!("{what} {reply}"));
            if reply == "error_reply" {
                let (code, detail) = (r["code"].as_str().unwrap(), r["detail"].as_str().unwrap());
                assert_eq!(
                    error_plain(code, detail),
                    b(&r["plain"]),
                    "{what}: ERROR plain"
                );
                assert_eq!(
                    open_error_plain(&b(&r["plain"])),
                    Ok((
                        code.to_string(),
                        (!detail.is_empty()).then(|| detail.to_string())
                    ))
                );
            }
        }

        let Some(frames) = c.get("frames").and_then(Json::as_array) else {
            assert_eq!(frame_type, FRAME_CALL);
            continue;
        };
        assert_eq!(frame_type, FRAME_STREAM_OPEN);
        let (k_c2p, k_p2c) = stream_keys(&ss, &parties);
        assert_eq!(k_c2p.to_vec(), b(&c["k_c2p"]), "{what}: k_c2p");
        assert_eq!(k_p2c.to_vec(), b(&c["k_p2c"]), "{what}: k_p2c");
        for f in frames {
            let seq = f["seq"].as_u64().unwrap();
            let (direction, key) = match f["direction"].as_u64().unwrap() {
                0 => (Direction::CallerToProvider, &k_c2p),
                _ => (Direction::ProviderToCaller, &k_p2c),
            };
            let aad = stream_aad(
                f["frame_type"].as_str().unwrap(),
                &parties.request_id,
                seq,
                direction,
            );
            assert_eq!(aad, b(&f["aad"]), "{what}: stream frame {seq} AAD");
            if direction == Direction::CallerToProvider {
                assert_eq!(
                    stream_nonce(seq).to_vec(),
                    b(&f["nonce"]),
                    "{what}: seq nonce"
                );
            }
            sealed_and_opened(key, f, &format!("{what} stream frame {seq}"));
        }
    }
}

/// The sender's side by round trip: a fresh key of this SDK's own, sealed
/// to, recovers the same secret, in both profiles.
#[test]
fn a_sender_s_secret_is_the_one_its_recipient_recovers() {
    for profile in [Profile::PqPure, Profile::PqHybrid] {
        let key = PrivateKey::generate(profile).unwrap();
        let (ss, kem_ct) = sender_secret(key.public_key()).unwrap();
        assert_eq!(
            kem_ct.len(),
            match profile {
                Profile::PqPure => MLKEM_CIPHERTEXT_SIZE,
                Profile::PqHybrid => MLKEM_CIPHERTEXT_SIZE + P384_POINT_BYTES,
            }
        );
        assert_eq!(
            recipient_secret(&key, &kem_ct),
            Ok(ss),
            "{}",
            profile.name()
        );
        let other = PrivateKey::generate(profile).unwrap();
        assert_ne!(recipient_secret(&other, &kem_ct), Ok(ss), "another key");
        let mut short = kem_ct.clone();
        short.pop();
        assert_eq!(recipient_secret(&key, &short), Err(SealError::Refused));
    }
}

/// Every refusal is refused: the ephemeral point that makes the recipient's
/// ECDH output 48 zero bytes, which the primitives under every stack return
/// without an error.
#[test]
fn every_refusal_vector_is_refused() {
    let v = vectors();
    let refusals = v["refusals"].as_array().unwrap();
    assert!(!refusals.is_empty());
    for r in refusals {
        assert_eq!(r["expect"], "sealed_refused");
        let key = recipient(r, profile_of(&r["profile"]));
        assert_eq!(
            recipient_secret(&key, &b(&r["kem_ct"])),
            Err(SealError::Refused),
            "{}",
            r["why"]
        );
    }
}

#[test]
fn a_key_that_is_not_one_is_refused() {
    let v = vectors();
    let pure = b(&v["recipients"]["pq_pure"]["key_as_carried"]);
    let hybrid = b(&v["recipients"]["pq_hybrid"]["key_as_carried"]);
    assert!(
        parse_public_key(Profile::PqHybrid, &pure).is_err(),
        "pure as hybrid"
    );
    assert!(
        parse_public_key(Profile::PqPure, &hybrid).is_err(),
        "hybrid as pure"
    );
    let mut compressed = hybrid.clone();
    compressed[MLKEM_EK_BYTES] = 0x02;
    assert!(
        parse_public_key(Profile::PqHybrid, &compressed).is_err(),
        "not uncompressed"
    );
    let mut off_curve = hybrid.clone();
    let last = off_curve.len() - 1;
    off_curve[last] ^= 1;
    assert!(
        parse_public_key(Profile::PqHybrid, &off_curve).is_err(),
        "off the curve"
    );
    assert!(
        open_error_plain(&error_plain(&"c".repeat(MAX_ERROR_CODE_BYTES + 1), "")).is_err(),
        "an ERROR code past its bound"
    );
}
