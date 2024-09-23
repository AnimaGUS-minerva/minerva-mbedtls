#![no_std]

use mcu_if::alloc::vec;
pub use minerva_mbedtls;
use minerva_mbedtls::{psa_ifce::*, mbedtls_error};

pub fn test_md() -> Result<(), mbedtls_error> {
    // product jada
    let msg: &[u8] = /* `to_verify` */ &[132, 106, 83, 105, 103, 110, 97, 116, 117, 114, 101, 49, 65, 160, 64, 88, 185, 161, 26, 0, 15, 70, 140, 166, 5, 105, 112, 114, 111, 120, 105, 109, 105, 116, 121, 6, 193, 26, 87, 247, 248, 30, 8, 193, 26, 89, 208, 48, 0, 14, 109, 74, 65, 68, 65, 49, 50, 51, 52, 53, 54, 55, 56, 57, 11, 105, 97, 98, 99, 100, 49, 50, 51, 52, 53, 13, 120, 124, 77, 70, 107, 119, 69, 119, 89, 72, 75, 111, 90, 73, 122, 106, 48, 67, 65, 81, 89, 73, 75, 111, 90, 73, 122, 106, 48, 68, 65, 81, 99, 68, 81, 103, 65, 69, 78, 87, 81, 79, 122, 99, 78, 77, 85, 106, 80, 48, 78, 114, 116, 102, 101, 66, 99, 48, 68, 74, 76, 87, 102, 101, 77, 71, 103, 67, 70, 100, 73, 118, 54, 70, 85, 122, 52, 68, 105, 102, 77, 49, 117, 106, 77, 66, 101, 99, 47, 103, 54, 87, 47, 80, 54, 98, 111, 84, 109, 121, 84, 71, 100, 70, 79, 104, 47, 56, 72, 119, 75, 85, 101, 114, 76, 53, 98, 112, 110, 101, 75, 56, 115, 103, 61, 61];

    let info = md_info::from_type(MD_SHA256);
    assert_eq!(info.get_type(), md_info::from_str("SHA256").get_type());

    assert_eq!(
        info.md(msg).as_slice(),
        [45, 106, 33, 97, 249, 125, 54, 185, 225, 237, 251, 191, 101, 21, 189, 9, 181, 239, 153, 225, 101, 54, 111, 15, 208, 136, 97, 182, 140, 57, 230, 157],
    );

    Ok(())
}

pub fn test_pk_context_verify_via_ecp() -> Result<(), mbedtls_error> {
    // product jada
    let hash = &md_info::from_type(MD_SHA256)
        .md(/* `to_verify` */ &[132, 106, 83, 105, 103, 110, 97, 116, 117, 114, 101, 49, 65, 160, 64, 88, 185, 161, 26, 0, 15, 70, 140, 166, 5, 105, 112, 114, 111, 120, 105, 109, 105, 116, 121, 6, 193, 26, 87, 247, 248, 30, 8, 193, 26, 89, 208, 48, 0, 14, 109, 74, 65, 68, 65, 49, 50, 51, 52, 53, 54, 55, 56, 57, 11, 105, 97, 98, 99, 100, 49, 50, 51, 52, 53, 13, 120, 124, 77, 70, 107, 119, 69, 119, 89, 72, 75, 111, 90, 73, 122, 106, 48, 67, 65, 81, 89, 73, 75, 111, 90, 73, 122, 106, 48, 68, 65, 81, 99, 68, 81, 103, 65, 69, 78, 87, 81, 79, 122, 99, 78, 77, 85, 106, 80, 48, 78, 114, 116, 102, 101, 66, 99, 48, 68, 74, 76, 87, 102, 101, 77, 71, 103, 67, 70, 100, 73, 118, 54, 70, 85, 122, 52, 68, 105, 102, 77, 49, 117, 106, 77, 66, 101, 99, 47, 103, 54, 87, 47, 80, 54, 98, 111, 84, 109, 121, 84, 71, 100, 70, 79, 104, 47, 56, 72, 119, 75, 85, 101, 114, 76, 53, 98, 112, 110, 101, 75, 56, 115, 103, 61, 61]);
    let sig = &[234, 232, 104, 236, 193, 118, 136, 55, 102, 197, 220, 91, 165, 184, 220, 162, 93, 171, 60, 46, 86, 165, 81, 206, 87, 5, 183, 147, 145, 67, 72, 225, 145, 46, 83, 95, 231, 182, 170, 68, 123, 26, 104, 156, 7, 204, 120, 204, 21, 231, 109, 98, 125, 108, 112, 63, 147, 120, 2, 102, 156, 19, 172, 227];

    let grp = ecp_group::from_id(ECP_DP_SECP256R1)?;
    let mut pt = ecp_point::new();
    pt.read_binary(grp, /* `signer_cert` */ &[4, 186, 197, 177, 28, 173, 143, 153, 249, 199, 43, 5, 207, 75, 158, 38, 210, 68, 220, 24, 159, 116, 82, 40, 37, 90, 33, 154, 134, 214, 160, 158, 255, 32, 19, 139, 248, 45, 193, 182, 213, 98, 190, 15, 165, 74, 183, 128, 74, 58, 100, 182, 215, 44, 207, 237, 107, 111, 182, 237, 40, 187, 252, 17, 126])?;

    assert!(pk_context::new()
        .setup(PK_ECKEY)?
        .set_grp(ecp_group::from_id(ECP_DP_SECP256R1)?)
        .set_q(pt)
        .verify(MD_SHA256, hash, sig)?);

    Ok(())
}

pub fn test_pk_context_verify_via_x509_crt() -> Result<(), mbedtls_error> {
    // product f2_00_02
    let pem = b"-----BEGIN CERTIFICATE-----
MIIByzCCAVKgAwIBAgIESltVuTAKBggqhkjOPQQDAjBTMRIwEAYKCZImiZPyLGQB
GRYCY2ExGTAXBgoJkiaJk/IsZAEZFglzYW5kZWxtYW4xIjAgBgNVBAMMGWhpZ2h3
YXktdGVzdC5zYW5kZWxtYW4uY2EwHhcNMTgxMTIyMTg1MjAxWhcNMjAxMTIxMTg1
MjAxWjBXMRIwEAYKCZImiZPyLGQBGRYCY2ExGTAXBgoJkiaJk/IsZAEZFglzYW5k
ZWxtYW4xJjAkBgNVBAMMHWhpZ2h3YXktdGVzdC5leGFtcGxlLmNvbSBNQVNBMFkw
EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqgQVo0S54kT4yfkbBxumdHOcHrpsqbOp
MKmiMln3oB1HAW25MJV+gqi4tMFfSJ0iEwt8kszfWXK4rLgJS2mnpaMQMA4wDAYD
VR0TAQH/BAIwADAKBggqhkjOPQQDAgNnADBkAjBkuTwpIGSZTJ3cDNv3RkZ9xR5F
F+msNgl8HH50lTF47uRVn/FrY3S8GS1TjP9RGhoCMC8lEKi0zeSya9yYDdXuxUVy
G5/TRupdVlCjPz1+tm/iA9ykx/sazZsuPgw14YulLw==
-----END CERTIFICATE-----
";
    let hash = &md_info::from_type(MD_SHA256)
        .md(/* `to_verify` */ &[132, 106, 83, 105, 103, 110, 97, 116, 117, 114, 101, 49, 67, 161, 1, 38, 64, 89, 2, 183, 161, 25, 9, 147, 165, 1, 102, 108, 111, 103, 103, 101, 100, 2, 193, 26, 95, 86, 209, 119, 11, 113, 48, 48, 45, 68, 48, 45, 69, 53, 45, 70, 50, 45, 48, 48, 45, 48, 50, 7, 118, 88, 83, 121, 70, 52, 76, 76, 73, 105, 113, 85, 50, 45, 79, 71, 107, 54, 108, 70, 67, 65, 103, 8, 121, 2, 116, 77, 73, 73, 66, 48, 84, 67, 67, 65, 86, 97, 103, 65, 119, 73, 66, 65, 103, 73, 66, 65, 106, 65, 75, 66, 103, 103, 113, 104, 107, 106, 79, 80, 81, 81, 68, 65, 122, 66, 120, 77, 82, 73, 119, 69, 65, 89, 75, 67, 90, 73, 109, 105, 90, 80, 121, 76, 71, 81, 66, 71, 82, 89, 67, 89, 50, 69, 120, 71, 84, 65, 88, 66, 103, 111, 74, 107, 105, 97, 74, 107, 47, 73, 115, 90, 65, 69, 90, 70, 103, 108, 122, 89, 87, 53, 107, 90, 87, 120, 116, 89, 87, 52, 120, 81, 68, 65, 43, 66, 103, 78, 86, 66, 65, 77, 77, 78, 121, 77, 56, 85, 51, 108, 122, 100, 71, 86, 116, 86, 109, 70, 121, 97, 87, 70, 105, 98, 71, 85, 54, 77, 72, 103, 119, 77, 68, 65, 119, 77, 68, 65, 119, 78, 71, 89, 53, 77, 84, 70, 104, 77, 68, 52, 103, 86, 87, 53, 122, 100, 72, 74, 49, 98, 109, 99, 103, 82, 109, 57, 49, 98, 110, 82, 104, 97, 87, 52, 103, 81, 48, 69, 119, 72, 104, 99, 78, 77, 84, 99, 120, 77, 84, 65, 51, 77, 106, 77, 48, 78, 84, 73, 52, 87, 104, 99, 78, 77, 84, 107, 120, 77, 84, 65, 51, 77, 106, 77, 48, 78, 84, 73, 52, 87, 106, 66, 68, 77, 82, 73, 119, 69, 65, 89, 75, 67, 90, 73, 109, 105, 90, 80, 121, 76, 71, 81, 66, 71, 82, 89, 67, 89, 50, 69, 120, 71, 84, 65, 88, 66, 103, 111, 74, 107, 105, 97, 74, 107, 47, 73, 115, 90, 65, 69, 90, 70, 103, 108, 122, 89, 87, 53, 107, 90, 87, 120, 116, 89, 87, 52, 120, 69, 106, 65, 81, 66, 103, 78, 86, 66, 65, 77, 77, 67, 87, 120, 118, 89, 50, 70, 115, 97, 71, 57, 122, 100, 68, 66, 90, 77, 66, 77, 71, 66, 121, 113, 71, 83, 77, 52, 57, 65, 103, 69, 71, 67, 67, 113, 71, 83, 77, 52, 57, 65, 119, 69, 72, 65, 48, 73, 65, 66, 74, 90, 108, 85, 72, 73, 48, 117, 112, 47, 108, 51, 101, 90, 102, 57, 118, 67, 66, 98, 43, 108, 73, 110, 111, 69, 77, 69, 103, 99, 55, 82, 111, 43, 88, 90, 67, 116, 106, 65, 73, 48, 67, 68, 49, 102, 74, 102, 74, 82, 47, 104, 73, 121, 121, 68, 109, 72, 87, 121, 89, 105, 78, 70, 98, 82, 67, 72, 57, 102, 121, 97, 114, 102, 107, 122, 103, 88, 52, 112, 48, 122, 84, 105, 122, 113, 106, 68, 84, 65, 76, 77, 65, 107, 71, 65, 49, 85, 100, 69, 119, 81, 67, 77, 65, 65, 119, 67, 103, 89, 73, 75, 111, 90, 73, 122, 106, 48, 69, 65, 119, 77, 68, 97, 81, 65, 119, 90, 103, 73, 120, 65, 76, 81, 77, 78, 117, 114, 102, 56, 116, 118, 53, 48, 108, 82, 79, 68, 53, 68, 81, 88, 72, 69, 79, 74, 74, 78, 87, 51, 81, 86, 50, 103, 57, 81, 69, 100, 68, 83, 107, 50, 77, 89, 43, 65, 111, 83, 114, 66, 83, 109, 71, 83, 78, 106, 104, 52, 111, 108, 69, 79, 104, 69, 117, 76, 103, 73, 120, 65, 74, 52, 110, 87, 102, 78, 119, 43, 66, 106, 98, 90, 109, 75, 105, 73, 105, 85, 69, 99, 84, 119, 72, 77, 104, 71, 86, 88, 97, 77, 72, 89, 47, 70, 55, 110, 51, 57, 119, 119, 75, 99, 66, 66, 83, 79, 110, 100, 78, 80, 113, 67, 112, 79, 69, 76, 108, 54, 98, 113, 51, 67, 90, 113, 81, 61, 61]);
    assert_eq!(hash, &[54, 231, 97, 210, 190, 7, 213, 205, 54, 208, 99, 79, 66, 160, 246, 154, 204, 198, 56, 162, 103, 201, 116, 248, 63, 96, 116, 7, 135, 89, 115, 215]);
    let sig = &[99, 204, 130, 58, 52, 185, 100, 173, 200, 53, 181, 142, 46, 225, 231, 227, 0, 136, 173, 230, 137, 111, 148, 177, 58, 199, 48, 100, 62, 150, 96, 181, 169, 52, 83, 243, 201, 216, 160, 154, 181, 122, 1, 19, 164, 6, 114, 120, 132, 118, 58, 42, 208, 75, 79, 171, 79, 111, 184, 188, 179, 46, 250, 71];

    assert!(x509_crt::new()
        .parse(pem)? // cf. `x509parse_crt()` of 'mbedtls/tests/suites/test_suite_x509parse.function'
        .info()? // debug
        .pk_ctx()
        .verify(MD_SHA256, hash, sig)?);

    Ok(())
}

pub fn test_pk_context_sign() -> Result<(), mbedtls_error> {
    // product 02_00_2e
    let hash = &[106, 89, 235, 58, 30, 187, 255, 243, 109, 213, 190, 148, 10, 189, 99, 109, 245, 189, 49, 17, 191, 161, 61, 17, 16, 123, 135, 119, 223, 123, 126, 174];
    let pem = b"-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIJZu2S7Bm5PnAIM6RKYsOza3Q+z3UZHUrVr/BMxzk3KZoAoGCCqGSM49
AwEHoUQDQgAEey+I0TtIhm8ivRJY36vF5ZRHs/IwhQWRc2Ql70rN+aYLZPOIXYc6
ZzlO62kDYBo3IPrcjkiPVnhoCosUBpTzbg==
-----END EC PRIVATE KEY-----
";

    let mut pk = pk_context::new();
    let f_rng = Some(pk_context::test_f_rng_ptr());

    pk.parse_key(pem, None, f_rng, core::ptr::null_mut())?;

    let mut sig = vec![];
    pk.sign(MD_SHA256, hash, &mut sig, f_rng, core::ptr::null_mut())?;
    assert_eq!(sig, /* asn1 */ [48, 70, 2, 33, 0, 226, 133, 204, 212, 146, 54, 173, 224, 191, 137, 104, 146, 5, 43, 216, 61, 167, 219, 192, 125, 138, 167, 160, 145, 26, 197, 52, 17, 94, 97, 210, 115, 2, 33, 0, 149, 230, 42, 127, 120, 31, 10, 28, 154, 2, 82, 16, 154, 165, 201, 129, 133, 192, 49, 15, 44, 159, 165, 129, 124, 210, 216, 67, 144, 174, 77, 107]);

    assert!(pk.verify(MD_SHA256, hash, &sig)?);

    Ok(())
}

pub fn test_utils_is_asn1_signature() -> Result<(), mbedtls_error> {
    use minerva_mbedtls::utils::*;

    assert_eq!(is_asn1_signature(&[ // len=64; product=F2_00_02
        99, 204, 130, 58, 52, 185, 100, 173, 200, 53, 181, 142, 46, 225, 231, 227, 0, 136, 173, 230, 137, 111, 148, 177, 58, 199, 48, 100, 62, 150, 96, 181, 169, 52, 83, 243, 201, 216, 160, 154, 181, 122, 1, 19, 164, 6, 114, 120, 132, 118, 58, 42, 208, 75, 79, 171, 79, 111, 184, 188, 179, 46, 250, 71
    ]), false);

    assert_eq!(is_asn1_signature(&[ // len=72; product=02_00_2E; sidhash: Map({Integer(1001154): Map({})})
        48, 70, 2, 33, 0, 207, 108, 40, 154, 180, 93, 219, 99, 88, 85, 28, 106, 253, 2, 206, 174, 5, 173, 169, 237, 87, 55, 52, 221, 140, 157, 195, 235, 48, 33, 104, 200, 2, 33, 0, 222, 162, 96, 5, 154, 133, 186, 60, 156, 254, 101, 61, 63, 157, 87, 33, 113, 38, 236, 114, 99, 79, 149, 7, 131, 88, 193, 26, 27, 124, 54, 230
    ]), true);

    assert_eq!(is_asn1_signature(&[ // len=71; product=02_00_2E; sidhash: Map({Integer(1): Map({})})
        48, 69, 2, 33, 0, 152, 82, 125, 36, 97, 213, 158, 38, 8, 68, 14, 194, 99, 237, 119, 120, 106, 11, 51, 153, 151, 187, 19, 189, 52, 137, 8, 86, 218, 247, 111, 220, 2, 32, 39, 131, 155, 58, 236, 211, 16, 142, 139, 129, 22, 124, 70, 214, 168, 71, 12, 83, 62, 248, 57, 2, 152, 23, 4, 163, 170, 80, 127, 137, 35, 52
    ]), true);

    Ok(())
}

#[cfg(test)]
fn init_psa_crypto() {
    use minerva_mbedtls::psa_crypto;
    psa_crypto::init().unwrap();
    psa_crypto::initialized().unwrap();
}

#[test] fn md(){ test_md().unwrap() }
#[test] fn pk_context_verify_via_ecp() { init_psa_crypto(); test_pk_context_verify_via_ecp().unwrap() }
#[test] fn pk_context_verify_via_x509_crt() { init_psa_crypto(); test_pk_context_verify_via_x509_crt().unwrap() }
#[test] fn pk_context_sign() { init_psa_crypto(); test_pk_context_sign().unwrap() }
#[test] fn utils_is_asn1_signature() { test_utils_is_asn1_signature().unwrap() }
