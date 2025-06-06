use base64::{decode_config, URL_SAFE_NO_PAD};
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::sha2::Sha256;
use rsa::signature::Verifier;
use rsa::RsaPublicKey;
use serde_json::Value;
use std::{
    ffi::{c_char, CStr, CString},
    ptr,
};

fn base64_url_decode(input: &str) -> Vec<u8> {
    decode_config(input, URL_SAFE_NO_PAD).unwrap()
}

fn verify_jwt_signature(jwt: &str, x5c_certs: &[&str]) -> bool {
    // Split the JWT into its three parts: header, payload, signature
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return false;
    }

    let header_and_payload = format!("{}.{}", parts[0], parts[1]);
    let tmp = base64_url_decode(parts[2]);
    let signature = tmp.as_slice();

    for cert_pem in x5c_certs {
        let certpem = x509_parser::pem::parse_x509_pem(cert_pem.as_bytes())
            .unwrap()
            .1;
        let certpem = certpem.parse_x509().unwrap();
        let public_key = certpem.public_key();
        let rsa_pub_key = RsaPublicKey::from_pkcs1_der(public_key.subject_public_key.data).unwrap();
        let is_valid = rsa::pkcs1v15::VerifyingKey::<Sha256>::new(rsa_pub_key).verify(
            header_and_payload.as_bytes(),
            &signature.try_into().unwrap(),
        );

        if is_valid.is_ok() {
            return true;
        }
    }

    // No valid signature found
    false
}

fn check_jwt_property(jwt: &str, property: &str, exp_value: &str) -> bool {
    let parts: Vec<&str> = jwt.split('.').collect();

    let header_bytes = base64_url_decode(parts[0]);
    let payload_bytes = base64_url_decode(parts[1]);

    // Parse the header and payload as JSON
    let header: Value = serde_json::from_slice(&header_bytes).unwrap();
    let payload: Value = serde_json::from_slice(&payload_bytes).unwrap();

    // Check in header
    if let Some(obj) = header.as_object() {
        if obj.contains_key(property) {
            let value = obj
                .get(property)
                .and_then(|value| value.as_str().map(|s| s.to_string()))
                .unwrap();
            return value == exp_value;
        }
    }

    // Check in body
    if let Some(obj) = payload.as_object() {
        if obj.contains_key(property) {
            let value = obj
                .get(property)
                .and_then(|value| value.as_str().map(|s| s.to_string()))
                .unwrap();
            return value == exp_value;
        }
    }

    false
}

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn get_property(
    jwt_cstr: *const c_char,
    prop_cstr: *const c_char,
) -> *mut c_char {
    if jwt_cstr.is_null() || prop_cstr.is_null() {
        return ptr::null_mut();
    }

    let jwt = match unsafe { CStr::from_ptr(jwt_cstr).to_str() } {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };

    let prop = match unsafe { CStr::from_ptr(prop_cstr).to_str() } {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };

    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return ptr::null_mut();
    }

    let payload_bytes = base64_url_decode(parts[1]);

    let payload_json: Value = match serde_json::from_slice(&payload_bytes) {
        Ok(val) => val,
        Err(_) => return ptr::null_mut(),
    };

    let val_opt = payload_json
        .get(prop)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    match val_opt {
        Some(s) => match CString::new(s) {
            Ok(cstr) => cstr.into_raw(),
            Err(_) => ptr::null_mut(),
        },
        None => ptr::null_mut(),
    }
}

/// Free a C string returned from `get_property`
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn free_string(s: *mut c_char) {
    if !s.is_null() {
        unsafe {
            drop(CString::from_raw(s));
        }
    }
}

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn verify_jwt(jwt_cstr: *const c_char) -> bool {
    let x5c_certs = [
        // This is the certificate of the attestation service, which can be
        // found in tless/attestation-service/certs/cert.pem
        r#"-----BEGIN CERTIFICATE-----
MIIFCTCCAvGgAwIBAgIUIfCvnY9eL7gCAMnilTlwJTjV1ekwDQYJKoZIhvcNAQELBQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI1MDQxMzA5MzM1MFoXDTI2MDQxMzA5MzM1MFowFDESMBAGA1UEAwwJbG9jYWxob3N0MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAxiqavAStTeJz0b2fEbIOzzJBBdxKlZhkixFd1IbHbxCwp+pAkPSoMuNr4zhbQNMOCqTWx0yIsKA2rJw2DohFtQWQSIUor8OLyMV/I2XIJydR9pcW/ZLx4LcSbv5Q9PiJXk1VB+IjYoW/2b2BHc9lCEZB+RLVDCVXGex1Wi3IeGcNhTDJHquwIojo+1HGtEH/a3K9wgRdy1D0PmDQCNCxQoBajATA0u4/TpsVsjsZzB7ZJpI020m7BCMvi7Dy68kDq18CZpAW0ZT7YsvCY1X+D0BvXd0NVNg/udqMPeQvhSXkQsiPqWar3zsR8JC5oKGVei6bHhtX17/9PiOChyIDzWwcrVNtJnmdS4jzuFdNOaBlCFGseXf3Pxkee3N/9vF3mn6RPYJfgj7yjr9qmxnRj02L8wbw3E8YjhOkznLiARDVCivzggEaHRNgDv7p3bQACkYae2gzJh+roBSm7fVmUH46Rgk8rz54uh/kKqoGpyxFV9njVZ8Q5JO+LI2aUjAxE13mZqkd89DYuvgHp7K5UDw/Bi5S2CWb/mLTX/WKur53t+B7iE3kJFx0A8G2UxLg3q9yhH+n2p64suLMq9iZcIlU+pSQj3jMSpuJH/6IHRHvJojgnx1T0bPxFtevIkXCNCXdgAHXmr+J5M60au2xIODk974QMfin8rGhwKdkpP0CAwEAAaNTMFEwHQYDVR0OBBYEFOc0rW9L90ySukKVg879piXRzDU0MB8GA1UdIwQYMBaAFOc0rW9L90ySukKVg879piXRzDU0MA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggIBAD5pxBGpsYvEfhppvVfMakn9DaEKmDp2GGs5SElJY5QS89dWjV4h4GGSVHPlPJ3TIdM9Qkvr34JMsLvkBNrAhlmPMQJAPnjqo6kuLoDCk1PNTQPZA9rO9ljoTMNcTCZue3Hu5G96PwV9z3kzGZZaBndmEnBVQ5JLXxZ/2221kyPxeV5sKoSfR2ZhfQcZiaiudY89kdJSg+2KovUoRzxoWvkZZyRz2UZX/VGF8luUbw6UFZf/SlV+JK7bcD5kNuMrFVZdm8hLu07wrRuRVSmM9wbZtdpjcRNtledNd1a7Nd9k1Oqqn/JZO3DfzoPzclje26mNh2ASNhqmO1SifoBgJDMU7ZmO4KS/Euqb2hgzQbjOG1FRflz1XJ5yKjY1T/4YwBqw8zUVVtmMUj0ksNWvYByh1+ZWZZNm03ioWkER4z+9MwTbPUVPwtg+HwnJXoV8C6Er16/blCuS1xgYMrBB5mK86MXFgNdJ3xrdvuukDhE7Eil9iC5419giya4Rli81VUdSvdzd6bldXAKQqCf0jB3kjTx0lno5CtgTG1s23Gnm/mitSWbnoy5TGjgX8wsIFdYmGhljouan7kOKiOkSgfnsbhd/aqCwt5NuU5WQMSfQ50BsIkT0HftXqaagNqXGUgQ8vrUa4wo8vlgGv5fwS6kzPDJW45w0uwIS1uEbHN1T
-----END CERTIFICATE-----"#,
    ];

    let jwt = unsafe { CStr::from_ptr(jwt_cstr).to_str().unwrap() };

    verify_jwt_signature(jwt, &x5c_certs)
}

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn check_property(
    jwt_cstr: *const c_char,
    property_cstr: *const c_char,
    exp_value_cstr: *const c_char,
) -> bool {
    let jwt = unsafe { CStr::from_ptr(jwt_cstr).to_str().unwrap() };
    let property = unsafe { CStr::from_ptr(property_cstr).to_str().unwrap() };
    let exp_value = unsafe { CStr::from_ptr(exp_value_cstr).to_str().unwrap() };

    check_jwt_property(jwt, property, exp_value)
}

/*
fn main() -> anyhow::Result<()> {
    let x5c_certs = [
    // This is the good one
    r#"-----BEGIN CERTIFICATE-----
MIIFCTCCAvGgAwIBAgIUIfCvnY9eL7gCAMnilTlwJTjV1ekwDQYJKoZIhvcNAQELBQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI1MDQxMzA5MzM1MFoXDTI2MDQxMzA5MzM1MFowFDESMBAGA1UEAwwJbG9jYWxob3N0MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAxiqavAStTeJz0b2fEbIOzzJBBdxKlZhkixFd1IbHbxCwp+pAkPSoMuNr4zhbQNMOCqTWx0yIsKA2rJw2DohFtQWQSIUor8OLyMV/I2XIJydR9pcW/ZLx4LcSbv5Q9PiJXk1VB+IjYoW/2b2BHc9lCEZB+RLVDCVXGex1Wi3IeGcNhTDJHquwIojo+1HGtEH/a3K9wgRdy1D0PmDQCNCxQoBajATA0u4/TpsVsjsZzB7ZJpI020m7BCMvi7Dy68kDq18CZpAW0ZT7YsvCY1X+D0BvXd0NVNg/udqMPeQvhSXkQsiPqWar3zsR8JC5oKGVei6bHhtX17/9PiOChyIDzWwcrVNtJnmdS4jzuFdNOaBlCFGseXf3Pxkee3N/9vF3mn6RPYJfgj7yjr9qmxnRj02L8wbw3E8YjhOkznLiARDVCivzggEaHRNgDv7p3bQACkYae2gzJh+roBSm7fVmUH46Rgk8rz54uh/kKqoGpyxFV9njVZ8Q5JO+LI2aUjAxE13mZqkd89DYuvgHp7K5UDw/Bi5S2CWb/mLTX/WKur53t+B7iE3kJFx0A8G2UxLg3q9yhH+n2p64suLMq9iZcIlU+pSQj3jMSpuJH/6IHRHvJojgnx1T0bPxFtevIkXCNCXdgAHXmr+J5M60au2xIODk974QMfin8rGhwKdkpP0CAwEAAaNTMFEwHQYDVR0OBBYEFOc0rW9L90ySukKVg879piXRzDU0MB8GA1UdIwQYMBaAFOc0rW9L90ySukKVg879piXRzDU0MA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggIBAD5pxBGpsYvEfhppvVfMakn9DaEKmDp2GGs5SElJY5QS89dWjV4h4GGSVHPlPJ3TIdM9Qkvr34JMsLvkBNrAhlmPMQJAPnjqo6kuLoDCk1PNTQPZA9rO9ljoTMNcTCZue3Hu5G96PwV9z3kzGZZaBndmEnBVQ5JLXxZ/2221kyPxeV5sKoSfR2ZhfQcZiaiudY89kdJSg+2KovUoRzxoWvkZZyRz2UZX/VGF8luUbw6UFZf/SlV+JK7bcD5kNuMrFVZdm8hLu07wrRuRVSmM9wbZtdpjcRNtledNd1a7Nd9k1Oqqn/JZO3DfzoPzclje26mNh2ASNhqmO1SifoBgJDMU7ZmO4KS/Euqb2hgzQbjOG1FRflz1XJ5yKjY1T/4YwBqw8zUVVtmMUj0ksNWvYByh1+ZWZZNm03ioWkER4z+9MwTbPUVPwtg+HwnJXoV8C6Er16/blCuS1xgYMrBB5mK86MXFgNdJ3xrdvuukDhE7Eil9iC5419giya4Rli81VUdSvdzd6bldXAKQqCf0jB3kjTx0lno5CtgTG1s23Gnm/mitSWbnoy5TGjgX8wsIFdYmGhljouan7kOKiOkSgfnsbhd/aqCwt5NuU5WQMSfQ50BsIkT0HftXqaagNqXGUgQ8vrUa4wo8vlgGv5fwS6kzPDJW45w0uwIS1uEbHN1T
-----END CERTIFICATE-----"#,
    r#"-----BEGIN CERTIFICATE-----
MIIFCTCCAvGgAwIBAgIUIfCvnY9eL7gCAMnilTlwJTjV1ekwDQYJKoZIhvcNAQELBQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI1MDQxMzA5MzM1MFoXDTI2MDQxMzA5MzM1MFowFDESMBAGA1UEAwwJbG9jYWxob3N0MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAxiqavAStTeJz0b2fEbIOzzJBBdxKlZhkixFd1IbHbxCwp+pAkPSoMuNr4zhbQNMOCqTWx0yIsKA2rJw2DohFtQWQSIUor8OLyMV/I2XIJydR9pcW/ZLx4LcSbv5Q9PiJXk1VB+IjYoW/2b2BHc9lCEZB+RLVDCVXGex1Wi3IeGcNhTDJHquwIojo+1HGtEH/a3K9wgRdy1D0PmDQCNCxQoBajATA0u4/TpsVsjsZzB7ZJpI020m7BCMvi7Dy68kDq18CZpAW0ZT7YsvCY1X+D0BvXd0NVNg/udqMPeQvhSXkQsiPqWar3zsR8JC5oKGVei6bHhtX17/9PiOChyIDzWwcrVNtJnmdS4jzuFdNOaBlCFGseXf3Pxkee3N/9vF3mn6RPYJfgj7yjr9qmxnRj02L8wbw3E8YjhOkznLiARDVCivzggEaHRNgDv7p3bQACkYae2gzJh+roBSm7fVmUH46Rgk8rz54uh/kKqoGpyxFV9njVZ8Q5JO+LI2aUjAxE13mZqkd89DYuvgHp7K5UDw/Bi5S2CWb/mLTX/WKur53t+B7iE3kJFx0A8G2UxLg3q9yhH+n2p64suLMq9iZcIlU+pSQj3jMSpuJH/6IHRHvJojgnx1T0bPxFtevIkXCNCXdgAHXmr+J5M60au2xIODk974QMfin8rGhwKdkpP0CAwEAAaNTMFEwHQYDVR0OBBYEFOc0rW9L90ySukKVg879piXRzDU0MB8GA1UdIwQYMBaAFOc0rW9L90ySukKVg879piXRzDU0MA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggIBAD5pxBGpsYvEfhppvVfMakn9DaEKmDp2GGs5SElJY5QS89dWjV4h4GGSVHPlPJ3TIdM9Qkvr34JMsLvkBNrAhlmPMQJAPnjqo6kuLoDCk1PNTQPZA9rO9ljoTMNcTCZue3Hu5G96PwV9z3kzGZZaBndmEnBVQ5JLXxZ/2221kyPxeV5sKoSfR2ZhfQcZiaiudY89kdJSg+2KovUoRzxoWvkZZyRz2UZX/VGF8luUbw6UFZf/SlV+JK7bcD5kNuMrFVZdm8hLu07wrRuRVSmM9wbZtdpjcRNtledNd1a7Nd9k1Oqqn/JZO3DfzoPzclje26mNh2ASNhqmO1SifoBgJDMU7ZmO4KS/Euqb2hgzQbjOG1FRflz1XJ5yKjY1T/4YwBqw8zUVVtmMUj0ksNWvYByh1+ZWZZNm03ioWkER4z+9MwTbPUVPwtg+HwnJXoV8C6Er16/blCuS1xgYMrBB5mK86MXFgNdJ3xrdvuukDhE7Eil9iC5419giya4Rli81VUdSvdzd6bldXAKQqCf0jB3kjTx0lno5CtgTG1s23Gnm/mitSWbnoy5TGjgX8wsIFdYmGhljouan7kOKiOkSgfnsbhd/aqCwt5NuU5WQMSfQ50BsIkT0HftXqaagNqXGUgQ8vrUa4wo8vlgGv5fwS6kzPDJW45w0uwIS1uEbHN1T
-----END CERTIFICATE-----"#,
    ];

    // Example JWT token
    let jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhdHRlc3RlZC1jbGllbnQiLCJleHAiOjE3NDQ1NTM2NjAsImF1ZCI6ImFjY2xlc3MtYXR0ZXN0YXRpb24tc2VydmljZSIsInRlZSI6InNneCIsInRlZV9pZGVudGl0eSI6Ikc0TnUxTjNfNENDTDM1NSIsImFlc19rZXlfYjY0IjoiMm1LVHZNWjd1aWVKRldHWUFyR3JZc3FjOURLUklSK3h4VkhDSzEzVCtiaz0ifQ.b5b42FyN7qLtxek1-2gFjZFawBc9NQnTVzjv4zWdSjA5-sIH6yz8USmYlv_YiwAR_-L8sPrNKmNuhpMDHu2dd6wETauMVxf1S8nLYp2gI0Ehs8zyZKUZnY_yJMoZxbAFIBAna0ZpjvkAwp_wOZW-Cw3yRF0MX90PRryFrMdaUAy-B3JI3rGorm-4S_Rqw9E-dXONYJgmHZT0Qf-u1dVpRULGz2mXLexTao0npGiUP-l3cXuMKcWqa9skkGM8hP3M8p_OWA18zB1yxVvVNKzFCA8WaMrORsqFUaj3Tg-8NsbpM0roqAgeUh63C_STab1s7NzovZ-0JhxrMJ9iwJmfXl6V6o5HoXsRwQKqN89dmk0VgYVdh4UtacByliTn-lncwoSlb6AAVuQNVDTvgOloEfTjmthaojK7TIaI2riO4r-LLC46w0TgzA9ilYSulo4WQP2D-1xnhTcJzw7QCKll8W85czQvKWVZkrNPBL7-6s4yXc_5WvYBQeRfqjdJICqz-27TvxfHaLR2OZ7zb3lfYrwcEUh-RThjlZWIkwO3tMcCgdeOhseaLyJgzObsLcNPOIJdJOLdpZeSjJzvXm51WJwENXcty5cnQ_PIjJYhj91LSfhB2Onmtna6a-FQHpswAxTOAe2GWPBGvKI5HTNyaXp78UW3_Iq5SBSuLE9S-tM";

    // Verify if the JWT is signed by any of the certificates in x5c
    let is_valid = verify_jwt_signature(jwt, &x5c_certs);

    if is_valid {
        println!("JWT signature is valid!");
    } else {
        println!("JWT signature is invalid.");
    }

    Ok(())
}
*/
