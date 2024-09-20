use crate::{utils::*, mbedtls_error};
use crate::{println, vec, Vec, c_void, c_int};
use psa_crypto::ffi::mbedtls::{self, types::raw_types};

//
// md
//

pub use mbedtls::{md_type_t, MD_SHA256, MD_SHA384, MD_SHA512, PK_ECKEY, ECP_DP_SECP256R1};
pub struct md_info(*const mbedtls::md_info_t);

impl md_info {
    pub fn from_type(ty: mbedtls::md_type_t) -> Self {
        Self(unsafe { mbedtls::md_info_from_type(ty) })
    }

    pub fn from_str(s: &str) -> Self {
        Self(unsafe { mbedtls::md_info_from_string(crate::cstr_from!(s)) })
    }

    pub fn get_type(&self) -> mbedtls::md_type_t {
        unsafe { mbedtls::md_get_type(self.0) }
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
            mbedtls::md(self.0, input.as_ptr(), input.len(), digest.as_mut_ptr())
        };
        assert_eq!(ret, 0);

        digest[..sz].to_vec()
    }
}

//
// x509_crt
//

pub struct x509_crt(mbedtls::x509_crt);

impl Drop for x509_crt {
    fn drop(&mut self) {
        unsafe { mbedtls::x509_crt_free(&mut self.0) }
    }
}

impl x509_crt {
    pub fn new() -> Self {
        let mut crt = mbedtls::x509_crt::default();
        unsafe { mbedtls::x509_crt_init(&mut crt) }

        Self(crt)
    }

    pub fn pk_ctx(&mut self) -> pk_context {
        unimplemented!();
        // FIXME error[E0609]: no field `private_pk` on type `psa_crypto::psa_crypto_sys::mbedtls::x509_crt`
        //pk_context::from(&mut self.0.private_pk as *mut mbedtls::pk_context)
    }

    pub fn parse(&mut self, buf: &[u8]) -> Result<&mut Self, mbedtls_error> {
        let buf = &crate::null_terminate_bytes!(buf);
        let ret = unsafe {
            mbedtls::x509_crt_parse(&mut self.0, buf.as_ptr(), buf.len())
        };

        if ret == 0 { Ok(self) } else { Err(ret) }
    }

    pub fn info(&mut self) -> Result<&mut Self, mbedtls_error> {
        let mut buf = [0u8; 2000];
        let ret = unsafe {
            mbedtls::x509_crt_info(
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
// ecp_group
//

pub struct ecp_group(Option<mbedtls::ecp_group>);

impl Drop for ecp_group {
    fn drop(&mut self) {
        if let Some(mut grp) = self.0 {
            unsafe { mbedtls::ecp_group_free(&mut grp) }
        }
    }
}

impl ecp_group {
    pub fn from_id(id: mbedtls::ecp_group_id) -> Result<Self, mbedtls_error> {
        let mut grp = ecp_group::new();
        grp.load(id)?;

        Ok(grp)
    }

    pub fn new() -> Self {
        let mut grp = mbedtls::ecp_group::default();
        unsafe { mbedtls::ecp_group_init(&mut grp) }

        Self(Some(grp))
    }

    pub fn into(mut self) -> mbedtls::ecp_group {
        self.0.take().unwrap()
    }

    pub fn load(&mut self, gid: mbedtls::ecp_group_id) -> Result<&mut Self, mbedtls_error> {
        if let Some(grp) = &mut self.0 {
            let ret = unsafe { mbedtls::ecp_group_load(grp, gid) };

            if ret == 0 { Ok(self) } else { Err(ret) }
        } else {
            panic!();
        }
    }
}

//
// ecp_point
//

pub struct ecp_point(Option<mbedtls::ecp_point>);

impl Drop for ecp_point {
    fn drop(&mut self) {
        if let Some(mut pt) = self.0 {
            unsafe { mbedtls::ecp_point_free(&mut pt) }
        }
    }
}

impl ecp_point {
    pub fn new() -> Self {
        let mut pt = mbedtls::ecp_point::default();
        unsafe { mbedtls::ecp_point_init(&mut pt) }

        Self(Some(pt))
    }

    pub fn into(mut self) -> mbedtls::ecp_point {
        self.0.take().unwrap()
    }

    pub fn read_binary(&mut self, grp: ecp_group, bin: &[u8]) -> Result<&mut Self, mbedtls_error> {
        if let Some(pt) = &mut self.0 {
            let ret = unsafe { mbedtls::ecp_point_read_binary(&grp.into() as *const mbedtls::ecp_group, pt, bin.as_ptr(), bin.len()) };

            if ret == 0 { Ok(self) } else { Err(ret) }
        } else {
            panic!();
        }
    }
}

//
// pk_context
//

pub struct pk_context(Option<mbedtls::pk_context>, Option<*mut mbedtls::pk_context>);

impl Drop for pk_context {
    fn drop(&mut self) {
        if let Some(pk) = &mut self.0 {
            unsafe { mbedtls::pk_free(pk) }
        }
    }
}

pub type FnRng = unsafe extern "C" fn(*mut raw_types::c_void, *mut u8, usize) -> i32;

extern "C" {
    fn rand() -> c_int;
}

impl pk_context {
    pub fn new() -> Self {
        let mut pk = mbedtls::pk_context::default();
        unsafe { mbedtls::pk_init(&mut pk) }

        Self(Some(pk), None)
    }

    pub fn from(ptr: *mut mbedtls::pk_context) -> Self {
        Self(None, Some(ptr))
    }

    fn ptr_mut(&mut self) -> *mut mbedtls::pk_context {
        if let Some(pk) = &mut self.0 {
            pk
        } else if let Some(pk) = self.1 {
            pk
        } else {
            unreachable!();
        }
    }

    pub fn set_grp(&mut self, grp: ecp_group) -> &mut Self {
        unsafe { (*self.as_keypair()).private_grp = grp.into(); }

        self
    }

    pub fn set_q(&mut self, q: ecp_point) -> &mut Self {
        unsafe { (*self.as_keypair()).private_Q = q.into(); }

        self
    }

    fn as_keypair(&mut self) -> *mut mbedtls::ecp_keypair {
        (unsafe { *self.ptr_mut() }).private_pk_ctx as *mut mbedtls::ecp_keypair
    }

    pub fn setup(&mut self, ty: mbedtls::pk_type_t) -> Result<&mut Self, mbedtls_error> {
        let ret = unsafe { mbedtls::pk_setup(self.ptr_mut(), mbedtls::pk_info_from_type(ty)) };

        if ret == 0 { Ok(self) } else { Err(ret) }
    }

    pub fn verify(&mut self, ty: mbedtls::md_type_t, hash: &[u8], sig: &[u8]) -> Result<bool, mbedtls_error> {
        let sig = if is_asn1_signature(sig) {
            sig.to_vec()
        } else {
            if let Ok(asn1) = asn1_signature_from(sig) { asn1 } else { return Ok(false); }
        };

        let ret = unsafe { mbedtls::pk_verify(
            self.ptr_mut(), ty, hash.as_ptr(), hash.len(), sig.as_ptr(), sig.len()) };

        if ret == 0 { Ok(true) } else { Err(ret) }
    }

    pub fn parse_key(
        &mut self, key: &[u8], pwd: Option<&[u8]>,
        f_rng: Option<FnRng>, p_rng: *mut c_void
    ) -> Result<&mut Self, mbedtls_error> {
        let key = &crate::null_terminate_bytes!(key);
        let (pwd_ptr, pwd_len) = if let Some(bytes) = pwd {
            (bytes.as_ptr(), bytes.len())
        } else {
            (core::ptr::null(), 0)
        };

        let ret = unsafe { mbedtls::pk_parse_key(
            self.ptr_mut(),
            key.as_ptr(), key.len(),
            pwd_ptr, pwd_len,
            f_rng, p_rng as *mut raw_types::c_void) };

        if ret == 0 { Ok(self) } else { Err(ret) }
    }

    pub fn sign(
        &mut self, ty: mbedtls::md_type_t, hash: &[u8], sig: &mut Vec<u8>,
        f_rng: Option<FnRng>, p_rng: *mut c_void
    ) -> Result<&mut Self, mbedtls_error> {
        let sz = if mbedtls::PK_SIGNATURE_MAX_SIZE > 0 {
            mbedtls::PK_SIGNATURE_MAX_SIZE as usize } else { 1024 };
        let mut sig_buf = vec![0u8; sz];
        let mut sig_out_len = 0;

        let ret = unsafe { mbedtls::pk_sign(
            self.ptr_mut(), ty,
            hash.as_ptr(), hash.len(),
            sig_buf.as_mut_ptr(), sig_buf.len(), &mut sig_out_len,
            f_rng, p_rng as *mut raw_types::c_void) };

        if ret == 0 {
            sig_buf.truncate(sig_out_len);
            *sig = sig_buf;

            Ok(self)
        } else { Err(ret) }
    }

    pub fn test_f_rng_ptr() -> FnRng {
        Self::rnd_std_rand
    }

    #[allow(unused_variables, unreachable_code)]
    extern "C" fn rnd_std_rand(rng_state: *mut raw_types::c_void, output: *mut u8, len: usize) -> i32 {
        let rng_state: *mut raw_types::c_void = core::ptr::null_mut();

        let output: &mut [u8] = unsafe { core::slice::from_raw_parts_mut(output, len) };
        for x in output.iter_mut() {
            *x = unsafe { rand() as u8 };
        }

        0
    }
}
