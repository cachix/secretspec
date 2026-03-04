// secretspec/src/provider/sops/go_interop/src/lib.rs
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

// Include the generated bindings from the go directory
include!("../go/bindings.rs");

pub struct SopsDecryptor;

impl SopsDecryptor {
    pub fn decrypt_file_with_env(
        file_path: &str,
        format: &str,
        age_key_file: Option<&str>,
        age_key: Option<&str>,
        kms_arn: Option<&str>,
        aws_profile: Option<&str>,
    ) -> Result<Vec<u8>, String> {
        let file_path_cstr =
            CString::new(file_path).map_err(|e| format!("Invalid file path: {}", e))?;
        let format_cstr = CString::new(format).map_err(|e| format!("Invalid format: {}", e))?;

        let age_key_file_cstr = age_key_file
            .map(|s| CString::new(s).map_err(|e| format!("Invalid age key file: {}", e)))
            .transpose()?;
        let age_key_cstr = age_key
            .map(|s| CString::new(s).map_err(|e| format!("Invalid age key: {}", e)))
            .transpose()?;
        let kms_arn_cstr = kms_arn
            .map(|s| CString::new(s).map_err(|e| format!("Invalid KMS ARN: {}", e)))
            .transpose()?;
        let aws_profile_cstr = aws_profile
            .map(|s| CString::new(s).map_err(|e| format!("Invalid AWS profile: {}", e)))
            .transpose()?;

        unsafe {
            let result_ptr = DecryptFileWithEnv(
                file_path_cstr.as_ptr() as *mut c_char,
                format_cstr.as_ptr() as *mut c_char,
                age_key_file_cstr
                    .as_ref()
                    .map_or(std::ptr::null_mut(), |s| s.as_ptr() as *mut c_char),
                age_key_cstr
                    .as_ref()
                    .map_or(std::ptr::null_mut(), |s| s.as_ptr() as *mut c_char),
                kms_arn_cstr
                    .as_ref()
                    .map_or(std::ptr::null_mut(), |s| s.as_ptr() as *mut c_char),
                aws_profile_cstr
                    .as_ref()
                    .map_or(std::ptr::null_mut(), |s| s.as_ptr() as *mut c_char),
            );

            if result_ptr.is_null() {
                return Err("Decryption failed".to_string());
            }

            let result_cstr = CStr::from_ptr(result_ptr);
            let result_str = result_cstr
                .to_str()
                .map_err(|e| format!("Invalid UTF-8: {}", e))?;

            if result_str.is_empty() {
                GoFree(result_ptr);
                return Err("File not found or decryption failed".to_string());
            }

            let result = result_str.as_bytes().to_vec();
            GoFree(result_ptr);
            Ok(result)
        }
    }

    pub fn decrypt_file_with_age_key(
        file_path: &str,
        format: &str,
        age_key_file: &str,
    ) -> Result<Vec<u8>, String> {
        let file_path_cstr =
            CString::new(file_path).map_err(|e| format!("Invalid file path: {}", e))?;
        let format_cstr = CString::new(format).map_err(|e| format!("Invalid format: {}", e))?;
        let age_key_file_cstr =
            CString::new(age_key_file).map_err(|e| format!("Invalid age key file: {}", e))?;

        unsafe {
            let result_ptr = DecryptFileWithAgeKey(
                file_path_cstr.as_ptr() as *mut c_char,
                format_cstr.as_ptr() as *mut c_char,
                age_key_file_cstr.as_ptr() as *mut c_char,
            );

            if result_ptr.is_null() {
                return Err("Decryption failed".to_string());
            }

            let result_cstr = CStr::from_ptr(result_ptr);
            let result_str = result_cstr
                .to_str()
                .map_err(|e| format!("Invalid UTF-8: {}", e))?;

            if result_str.is_empty() {
                GoFree(result_ptr);
                return Err("File not found or decryption failed".to_string());
            }

            let result = result_str.as_bytes().to_vec();
            GoFree(result_ptr);
            Ok(result)
        }
    }

    pub fn decrypt_data(data: &[u8], format: &str) -> Result<Vec<u8>, String> {
        let data_str = String::from_utf8_lossy(data);
        let data_cstr =
            CString::new(data_str.as_ref()).map_err(|e| format!("Invalid data: {}", e))?;
        let format_cstr = CString::new(format).map_err(|e| format!("Invalid format: {}", e))?;

        unsafe {
            let result_ptr = DecryptData(
                data_cstr.as_ptr() as *mut c_char,
                format_cstr.as_ptr() as *mut c_char,
            );

            if result_ptr.is_null() {
                return Err("Decryption failed".to_string());
            }

            let result_cstr = CStr::from_ptr(result_ptr);
            let result_str = result_cstr
                .to_str()
                .map_err(|e| format!("Invalid UTF-8: {}", e))?;

            if result_str.is_empty() {
                GoFree(result_ptr);
                return Err("Decryption returned empty result".to_string());
            }

            let result = result_str.as_bytes().to_vec();
            GoFree(result_ptr);
            Ok(result)
        }
    }

    pub fn decrypt_data_with_format(
        data: &[u8],
        input_format: &str,
        output_format: &str,
    ) -> Result<Vec<u8>, String> {
        let data_str = String::from_utf8_lossy(data);
        let data_cstr =
            CString::new(data_str.as_ref()).map_err(|e| format!("Invalid data: {}", e))?;
        let input_format_cstr =
            CString::new(input_format).map_err(|e| format!("Invalid input format: {}", e))?;
        let output_format_cstr =
            CString::new(output_format).map_err(|e| format!("Invalid output format: {}", e))?;

        unsafe {
            let result_ptr = DecryptDataWithFormat(
                data_cstr.as_ptr() as *mut c_char,
                input_format_cstr.as_ptr() as *mut c_char,
                output_format_cstr.as_ptr() as *mut c_char,
            );

            if result_ptr.is_null() {
                return Err("Decryption failed".to_string());
            }

            let result_cstr = CStr::from_ptr(result_ptr);
            let result_str = result_cstr
                .to_str()
                .map_err(|e| format!("Invalid UTF-8: {}", e))?;

            if result_str.is_empty() {
                GoFree(result_ptr);
                return Err("Decryption returned empty result".to_string());
            }

            let result = result_str.as_bytes().to_vec();
            GoFree(result_ptr);
            Ok(result)
        }
    }

    pub fn decrypt_file(file_path: &str, format: &str) -> Result<Vec<u8>, String> {
        let file_path_cstr =
            CString::new(file_path).map_err(|e| format!("Invalid file path: {}", e))?;
        let format_cstr = CString::new(format).map_err(|e| format!("Invalid format: {}", e))?;

        unsafe {
            let result_ptr = DecryptFile(
                file_path_cstr.as_ptr() as *mut c_char,
                format_cstr.as_ptr() as *mut c_char,
            );

            if result_ptr.is_null() {
                return Err("Decryption failed".to_string());
            }

            let result_cstr = CStr::from_ptr(result_ptr);
            let result_str = result_cstr
                .to_str()
                .map_err(|e| format!("Invalid UTF-8: {}", e))?;

            if result_str.is_empty() {
                GoFree(result_ptr);
                return Err("File not found or decryption failed".to_string());
            }

            let result = result_str.as_bytes().to_vec();
            GoFree(result_ptr);
            Ok(result)
        }
    }
}
