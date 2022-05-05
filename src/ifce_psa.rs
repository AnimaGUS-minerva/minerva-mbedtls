use super::utils::{asn1_signature_from, is_asn1_signature};
use crate::{println, vec, Vec};

#[cfg(feature = "std")]
pub use std::os::raw::*;
#[cfg(not(feature = "std"))]
pub use mcu_if::c_types::*;

pub type mbedtls_error = c_int;

use psa_crypto::ffi;

//
// md
//

pub use ffi::{md_type_t, MD_SHA256, MD_SHA384, MD_SHA512};
pub struct md_info(*const ffi::md_info_t);

impl md_info {
    pub fn from_type(ty: md_type_t) -> Self {
        Self(unsafe { ffi::md_info_from_type(ty) })
    }

    pub fn from_str(s: &str) -> Self {
        Self(unsafe { ffi::md_info_from_string(crate::cstr_from!(s)) })
    }

    pub fn get_type(&self) -> md_type_t {
        unsafe { ffi::md_get_type(self.0) }
    }

    pub fn md(&self, input: &[u8]) -> Vec<u8> {
        let sz = match self.get_type() {
            MD_SHA256 => 32,
            MD_SHA384 => 48,
            MD_SHA512 => 64,
            _ => unimplemented!("Unsupported `md_type`"),
        };
        let mut digest = vec![0; sz];

        let ret = unsafe {
            ffi::md(self.0, input.as_ptr(), input.len(), digest.as_mut_ptr())
        };
        assert_eq!(ret, 0);

        digest[..sz].to_vec()
    }
}

//
// x509_crt
//

pub struct x509_crt(ffi::x509_crt);

impl Drop for x509_crt {
    fn drop(&mut self) {
        unsafe { ffi::x509_crt_free(&mut self.0) }
    }
}

impl x509_crt {
    pub fn new() -> Self {
        let mut crt = ffi::x509_crt::default();
        unsafe { ffi::x509_crt_init(&mut crt) }

        Self(crt)
    }

    pub fn pk_ctx(&mut self) -> pk_context {
        pk_context::from(&mut self.0.private_pk as *mut ffi::pk_context)
    }

    pub fn parse(&mut self, buf: &[u8]) -> Result<&mut Self, mbedtls_error> {
        let buf = &crate::null_terminate_bytes!(buf);
        let ret = unsafe {
            ffi::x509_crt_parse(&mut self.0, buf.as_ptr(), buf.len())
        };

        if ret == 0 { Ok(self) } else { Err(ret) }
    }

    pub fn info(&mut self) -> Result<&mut Self, mbedtls_error> {
        let mut buf = [0u8; 2000];
        let ret = unsafe {
            ffi::x509_crt_info(
                buf.as_mut_ptr() as *mut i8,
                buf.len(), crate::cstr_from!("@@ "), &self.0)
        };

        if ret < 0 {
            return Err(ret);
        }

        let info = &buf[.. ret as usize];

        #[cfg(feature = "std")]
        {
            let info = std::string::String::from_utf8_lossy(info);
            println!("info:\n{}", info);
        }
        #[cfg(not(feature = "std"))]
        {
            println!("raw info len: {}", info.len());
            //println!("raw info: {:?}", info);
        }

        Ok(self)
    }
}

//
// pk_context
//

pub struct pk_context(*mut ffi::pk_context, /* managed */ bool);

impl Drop for pk_context {
    fn drop(&mut self) {
        if self.1 {
            unsafe { ffi::pk_free(self.0) }
        }
    }
}

impl pk_context {
    pub fn new() -> Self {
        let mut pk = ffi::pk_context::default();
        unsafe { ffi::pk_init(&mut pk) }

        Self(&mut pk as *mut ffi::pk_context, true)
    }

    pub fn from(ptr: *mut ffi::pk_context) -> Self {
        Self(ptr, false)
    }

    pub fn verify(&mut self, ty: md_type_t, hash: &[u8], sig: &[u8]) -> Result<bool, mbedtls_error> {
        let sig = if is_asn1_signature(sig) {
            sig.to_vec()
        } else {
            if let Ok(asn1) = asn1_signature_from(sig) {
                asn1
            } else {
                return Ok(false);
            }
        };

        let ret = unsafe {
            ffi::pk_verify(self.0, ty, hash.as_ptr(), hash.len(), sig.as_ptr(), sig.len())
        };

        if ret == 0 { Ok(true) } else { Err(ret) }
    }
}


#[test]
fn test_ifce_psa() -> Result<(), mbedtls_error> {
    use super::*;

    psa_crypto::init().unwrap();
    psa_crypto::initialized().unwrap();

    { // md
        // jada's `to_verify`
        let msg: &[u8] = &[132, 106, 83, 105, 103, 110, 97, 116, 117, 114, 101, 49, 65, 160, 64, 88, 185, 161, 26, 0, 15, 70, 140, 166, 5, 105, 112, 114, 111, 120, 105, 109, 105, 116, 121, 6, 193, 26, 87, 247, 248, 30, 8, 193, 26, 89, 208, 48, 0, 14, 109, 74, 65, 68, 65, 49, 50, 51, 52, 53, 54, 55, 56, 57, 11, 105, 97, 98, 99, 100, 49, 50, 51, 52, 53, 13, 120, 124, 77, 70, 107, 119, 69, 119, 89, 72, 75, 111, 90, 73, 122, 106, 48, 67, 65, 81, 89, 73, 75, 111, 90, 73, 122, 106, 48, 68, 65, 81, 99, 68, 81, 103, 65, 69, 78, 87, 81, 79, 122, 99, 78, 77, 85, 106, 80, 48, 78, 114, 116, 102, 101, 66, 99, 48, 68, 74, 76, 87, 102, 101, 77, 71, 103, 67, 70, 100, 73, 118, 54, 70, 85, 122, 52, 68, 105, 102, 77, 49, 117, 106, 77, 66, 101, 99, 47, 103, 54, 87, 47, 80, 54, 98, 111, 84, 109, 121, 84, 71, 100, 70, 79, 104, 47, 56, 72, 119, 75, 85, 101, 114, 76, 53, 98, 112, 110, 101, 75, 56, 115, 103, 61, 61];

        let info = md_info::from_type(MD_SHA256);
        assert_eq!(info.get_type(), md_info::from_str("SHA256").get_type());

        assert_eq!(
            info.md(msg).as_slice(),
            [45, 106, 33, 97, 249, 125, 54, 185, 225, 237, 251, 191, 101, 21, 189, 9, 181, 239, 153, 225, 101, 54, 111, 15, 208, 136, 97, 182, 140, 57, 230, 157],
        );
    }

    { // x509_crt
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

        // cf - fn test_pk_verify_f2_00_02() -> Result<(), c_int> {
        let hash = &md_info::from_type(MD_SHA256)
            .md(/* `to_verify` */&[132, 106, 83, 105, 103, 110, 97, 116, 117, 114, 101, 49, 67, 161, 1, 38, 64, 89, 2, 183, 161, 25, 9, 147, 165, 1, 102, 108, 111, 103, 103, 101, 100, 2, 193, 26, 95, 86, 209, 119, 11, 113, 48, 48, 45, 68, 48, 45, 69, 53, 45, 70, 50, 45, 48, 48, 45, 48, 50, 7, 118, 88, 83, 121, 70, 52, 76, 76, 73, 105, 113, 85, 50, 45, 79, 71, 107, 54, 108, 70, 67, 65, 103, 8, 121, 2, 116, 77, 73, 73, 66, 48, 84, 67, 67, 65, 86, 97, 103, 65, 119, 73, 66, 65, 103, 73, 66, 65, 106, 65, 75, 66, 103, 103, 113, 104, 107, 106, 79, 80, 81, 81, 68, 65, 122, 66, 120, 77, 82, 73, 119, 69, 65, 89, 75, 67, 90, 73, 109, 105, 90, 80, 121, 76, 71, 81, 66, 71, 82, 89, 67, 89, 50, 69, 120, 71, 84, 65, 88, 66, 103, 111, 74, 107, 105, 97, 74, 107, 47, 73, 115, 90, 65, 69, 90, 70, 103, 108, 122, 89, 87, 53, 107, 90, 87, 120, 116, 89, 87, 52, 120, 81, 68, 65, 43, 66, 103, 78, 86, 66, 65, 77, 77, 78, 121, 77, 56, 85, 51, 108, 122, 100, 71, 86, 116, 86, 109, 70, 121, 97, 87, 70, 105, 98, 71, 85, 54, 77, 72, 103, 119, 77, 68, 65, 119, 77, 68, 65, 119, 78, 71, 89, 53, 77, 84, 70, 104, 77, 68, 52, 103, 86, 87, 53, 122, 100, 72, 74, 49, 98, 109, 99, 103, 82, 109, 57, 49, 98, 110, 82, 104, 97, 87, 52, 103, 81, 48, 69, 119, 72, 104, 99, 78, 77, 84, 99, 120, 77, 84, 65, 51, 77, 106, 77, 48, 78, 84, 73, 52, 87, 104, 99, 78, 77, 84, 107, 120, 77, 84, 65, 51, 77, 106, 77, 48, 78, 84, 73, 52, 87, 106, 66, 68, 77, 82, 73, 119, 69, 65, 89, 75, 67, 90, 73, 109, 105, 90, 80, 121, 76, 71, 81, 66, 71, 82, 89, 67, 89, 50, 69, 120, 71, 84, 65, 88, 66, 103, 111, 74, 107, 105, 97, 74, 107, 47, 73, 115, 90, 65, 69, 90, 70, 103, 108, 122, 89, 87, 53, 107, 90, 87, 120, 116, 89, 87, 52, 120, 69, 106, 65, 81, 66, 103, 78, 86, 66, 65, 77, 77, 67, 87, 120, 118, 89, 50, 70, 115, 97, 71, 57, 122, 100, 68, 66, 90, 77, 66, 77, 71, 66, 121, 113, 71, 83, 77, 52, 57, 65, 103, 69, 71, 67, 67, 113, 71, 83, 77, 52, 57, 65, 119, 69, 72, 65, 48, 73, 65, 66, 74, 90, 108, 85, 72, 73, 48, 117, 112, 47, 108, 51, 101, 90, 102, 57, 118, 67, 66, 98, 43, 108, 73, 110, 111, 69, 77, 69, 103, 99, 55, 82, 111, 43, 88, 90, 67, 116, 106, 65, 73, 48, 67, 68, 49, 102, 74, 102, 74, 82, 47, 104, 73, 121, 121, 68, 109, 72, 87, 121, 89, 105, 78, 70, 98, 82, 67, 72, 57, 102, 121, 97, 114, 102, 107, 122, 103, 88, 52, 112, 48, 122, 84, 105, 122, 113, 106, 68, 84, 65, 76, 77, 65, 107, 71, 65, 49, 85, 100, 69, 119, 81, 67, 77, 65, 65, 119, 67, 103, 89, 73, 75, 111, 90, 73, 122, 106, 48, 69, 65, 119, 77, 68, 97, 81, 65, 119, 90, 103, 73, 120, 65, 76, 81, 77, 78, 117, 114, 102, 56, 116, 118, 53, 48, 108, 82, 79, 68, 53, 68, 81, 88, 72, 69, 79, 74, 74, 78, 87, 51, 81, 86, 50, 103, 57, 81, 69, 100, 68, 83, 107, 50, 77, 89, 43, 65, 111, 83, 114, 66, 83, 109, 71, 83, 78, 106, 104, 52, 111, 108, 69, 79, 104, 69, 117, 76, 103, 73, 120, 65, 74, 52, 110, 87, 102, 78, 119, 43, 66, 106, 98, 90, 109, 75, 105, 73, 105, 85, 69, 99, 84, 119, 72, 77, 104, 71, 86, 88, 97, 77, 72, 89, 47, 70, 55, 110, 51, 57, 119, 119, 75, 99, 66, 66, 83, 79, 110, 100, 78, 80, 113, 67, 112, 79, 69, 76, 108, 54, 98, 113, 51, 67, 90, 113, 81, 61, 61]);
        assert_eq!(hash, &[54, 231, 97, 210, 190, 7, 213, 205, 54, 208, 99, 79, 66, 160, 246, 154, 204, 198, 56, 162, 103, 201, 116, 248, 63, 96, 116, 7, 135, 89, 115, 215]);
        let sig = &[99, 204, 130, 58, 52, 185, 100, 173, 200, 53, 181, 142, 46, 225, 231, 227, 0, 136, 173, 230, 137, 111, 148, 177, 58, 199, 48, 100, 62, 150, 96, 181, 169, 52, 83, 243, 201, 216, 160, 154, 181, 122, 1, 19, 164, 6, 114, 120, 132, 118, 58, 42, 208, 75, 79, 171, 79, 111, 184, 188, 179, 46, 250, 71];

        assert!(x509_crt::new()
            .parse(pem)?
            .info()? // debug
            .pk_ctx()
            .verify(MD_SHA256, hash, sig)?);

        //

        // TODO
        //---- lifecycle w.r.t. `pk_context::{new,drop}`
        // #[test]
        // fn test_pk_drop() -> Result<(), c_int> {
        //---- `pk_context::{setup,set_grq,set_q}` stuff
        // #[test]
        // fn test_pk_verify_jada() -> Result<(), c_int> {
        //---- `pk_context::{sign, ...}` stuff
        // #[test]
        // fn test_pk_sign_02_00_2e() -> Result<(), c_int> {

        //

        Ok(())
    }
}