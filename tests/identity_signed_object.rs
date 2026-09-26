//! Signed objects, as macula_signed_object signs and verifies them: fields
//! gain alg, the signature covers the label, the key's SHA-384 and the tbs as
//! received, and a verifier reads the object in macula's order.

use macula_rust::cbor::Value;
use macula_rust::node_key::{NodeKey, Purpose};
use macula_rust::profile::Profile;
use macula_rust::signed_object::{
    sign_held_object, sign_object, verify_held_object, verify_object, HeldObject, Object,
    ObjectError,
};

fn fields() -> Vec<(Value, Value)> {
    vec![
        (Value::text("procedure"), Value::text("acme/echo")),
        (Value::text("seq"), Value::Int(7)),
    ]
}

#[test]
fn a_signed_object_verifies_under_its_label_and_names_its_algorithm() {
    for profile in [Profile::PqPure, Profile::PqHybrid] {
        let key = NodeKey::generate(Purpose::Identity, profile).unwrap();
        let object = sign_object("MACULA-TEST-V1", &fields(), &key).unwrap();
        assert_eq!(object.key, key.public_key());
        let verified = verify_object("MACULA-TEST-V1", &object.to_value(), profile).unwrap();
        assert_eq!(verified.key, key.public_key());
        assert_eq!(verified.tbs, object.tbs);
        assert_eq!(
            verified.fields.get("alg"),
            Some(&Value::text(profile.sig_alg()))
        );
        assert_eq!(verified.fields.get("seq"), Some(&Value::Int(7)));

        assert_eq!(
            verify_object("MACULA-OTHER-V1", &object.to_value(), profile).unwrap_err(),
            ObjectError::SignatureInvalid
        );
        let mut altered = object.clone();
        altered.tbs[3] ^= 1;
        assert_eq!(
            verify_object("MACULA-TEST-V1", &altered.to_value(), profile).unwrap_err(),
            ObjectError::SignatureInvalid
        );
    }
}

#[test]
fn an_alg_the_signer_supplied_is_replaced_by_its_profile_s() {
    let key = NodeKey::generate(Purpose::Identity, Profile::PqPure).unwrap();
    let mut with_alg = fields();
    with_alg.push((Value::text("alg"), Value::text("RSA")));
    let object = sign_object("MACULA-TEST-V1", &with_alg, &key).unwrap();
    let verified = verify_object("MACULA-TEST-V1", &object.to_value(), Profile::PqPure).unwrap();
    assert_eq!(verified.fields.get("alg"), Some(&Value::text("ML-DSA-87")));
}

#[test]
fn a_held_object_leaves_its_key_out_and_still_signs_its_hash() {
    let key = NodeKey::generate(Purpose::Identity, Profile::PqPure).unwrap();
    let held = sign_held_object("MACULA-TEST-V1", &fields(), &key).unwrap();
    let value = held.to_value();
    assert_eq!(value.get("key"), None);
    verify_held_object("MACULA-TEST-V1", &value, &key.public_key(), Profile::PqPure).unwrap();
    let other = NodeKey::generate(Purpose::Identity, Profile::PqPure).unwrap();
    assert_eq!(
        verify_held_object(
            "MACULA-TEST-V1",
            &value,
            &other.public_key(),
            Profile::PqPure
        )
        .unwrap_err(),
        ObjectError::SignatureInvalid
    );
}

#[test]
fn an_object_of_the_wrong_shape_or_another_profile_is_refused() {
    let key = NodeKey::generate(Purpose::Identity, Profile::PqPure).unwrap();
    let object = sign_object("MACULA-TEST-V1", &fields(), &key).unwrap();
    // The verifier's profile is pq_hybrid: a pq_pure key is not in its
    // carried form.
    assert_eq!(
        verify_object("MACULA-TEST-V1", &object.to_value(), Profile::PqHybrid).unwrap_err(),
        ObjectError::Malformed
    );
    let missing = Value::Map(vec![(Value::text("tbs"), Value::Bytes(object.tbs.clone()))]);
    assert_eq!(
        Object::from_value(&missing).unwrap_err(),
        ObjectError::Malformed
    );
    assert_eq!(
        HeldObject::from_value(&object.to_value()).unwrap_err(),
        ObjectError::Malformed
    );

    let duplicate = vec![
        (Value::text("a"), Value::Int(1)),
        (Value::text("a"), Value::Int(2)),
    ];
    assert!(sign_object("MACULA-TEST-V1", &duplicate, &key).is_err());
    let int_key = vec![(Value::Int(1), Value::Int(1))];
    assert!(sign_object("MACULA-TEST-V1", &int_key, &key).is_err());
}
