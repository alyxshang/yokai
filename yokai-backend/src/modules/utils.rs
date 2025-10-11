/*
Yokai by Alyx Shang.
Licensed under the FSL v1.
*/

use sqlx::Pool;
use chrono::Utc;
use sha2::Digest;
use sha2::Sha256;
use base64::Engine;
use sqlx::postgres;
use chrono::DateTime;
use openssl::rsa::Rsa;
use openssl::pkey::PKey;
use super::err::YokaiErr;
use openssl::pkey::Public;
use super::units::KeyPair;
use openssl::rsa::Padding;
use openssl::pkey::Private;
use sqlx::postgres::Postgres;
use openssl::encrypt::Encrypter;
use base64::engine::general_purpose;

pub fn hash_string(subject: &str) -> String {
    let mut hasher: Sha256 = Sha256::new();
    hasher.update(subject);
    format!("{:X}", hasher.finalize())
}

pub fn rfc2282() -> String {
    let now: DateTime<Utc> = Utc::now();
    now.to_rfc2822()
}

pub fn generate_keypair(
) -> Result<KeyPair, YokaiErr>{
    let keys: Rsa<Private> = match Rsa::generate(2048){
        Ok(keys) => keys,
        Err(e) => return Err::<KeyPair, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    let public_pem: Vec<u8> = match keys.public_key_to_pem_pkcs1(){
        Ok(public_pem) => public_pem,
        Err(e) => return Err::<KeyPair, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    let private_pem: Vec<u8> = match keys.private_key_to_pem(){
        Ok(private_pem) => private_pem,
        Err(e) => return Err::<KeyPair, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    let public: String = match String::from_utf8(public_pem){
        Ok(public) => public,
        Err(e) => return Err::<KeyPair, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    let private: String = match String::from_utf8(private_pem){
        Ok(public) => public,
        Err(e) => return Err::<KeyPair, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    Ok(KeyPair{ public_key: public, private_key: private })
}

pub fn decrypt_message(
    encrypted_msg: &str,
    private_key: &str
) -> Result<String, YokaiErr>{
    let cipher_bytes: Vec<u8> = match general_purpose::STANDARD.decode(encrypted_msg){
        Ok(cipher_bytes) => cipher_bytes,
        Err(e) => return Err::<String, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    let priv_key: Rsa<Private> = match Rsa::private_key_from_pem(
        private_key.to_string().as_bytes()
    ){
        Ok(priv_key_bytes) => priv_key_bytes,
        Err(e) => return Err::<String, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    let buf_len: usize = priv_key.size() as usize;
    let mut buffer: Vec<u8> = vec![0;buf_len];
    let decrypted_len: usize = match priv_key.private_decrypt(
        &cipher_bytes, 
        &mut buffer,
        Padding::PKCS1
    ){
        Ok(decrypted_len) => decrypted_len,
        Err(e) => return Err::<String, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    buffer.truncate(decrypted_len);
    let result: String = match String::from_utf8(buffer){
        Ok(result) => result,
        Err(e) => return Err::<String, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    Ok(result)
}

pub fn encrypt_message(
    msg: &str,
    public_key: &str
) -> Result<String, YokaiErr>{
    let pub_key_bytes: Rsa<Public> = match Rsa::public_key_from_pem_pkcs1(
        public_key.to_string().as_bytes()
    ){
        Ok(pub_key_bytes) => pub_key_bytes,
        Err(e) => return Err::<String, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    let pub_key_pkey: PKey<Public> = match PKey::from_rsa(pub_key_bytes){
        Ok(pub_key_pkey) => pub_key_pkey,
        Err(e) => return Err::<String, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    let mut encrypter: Encrypter = match Encrypter::new(&pub_key_pkey){
        Ok(encrypter) => encrypter,
        Err(e) => return Err::<String, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    let _: () = match encrypter.set_rsa_padding(Padding::PKCS1){
        Ok(_f) => {},
        Err(e) => return Err::<String, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    let buf_len: usize = match encrypter.encrypt_len(msg.as_bytes()){
        Ok(buf_len) => buf_len,
        Err(e) => return Err::<String, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    let mut buffer: Vec<u8> = vec![0;buf_len];
    let encryption: usize = match encrypter.encrypt(
        &msg.to_string().as_bytes(), 
        &mut buffer
    ){
        Ok(encryption) => encryption,
        Err(e) => return Err::<String, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    buffer.truncate(encryption);
    let encoded: String = general_purpose::STANDARD.encode(&buffer);
    Ok(encoded)
}

pub fn check_username(
    subject: &str
) -> bool{
    let subject_chars: Vec<char> = subject
        .to_string()
        .chars()
        .collect::<Vec<char>>();
    let mut result: bool = true;
    if subject_chars.len() >= 4 && subject_chars.len() <= 16{
        let alphabet: Vec<char> = "abcdefghijklmnopqrstuvwxyz1234567890"
            .to_string()
            .chars()
            .collect::<Vec<char>>();
        for subject_char in subject_chars {
            if !alphabet.contains(&subject_char){
                result = false;
            }
        }
    }
    else {
        result = false;
    }
    result
}

pub fn check_password(
    subject: &str
) -> bool{
    let subject_chars: Vec<char> = subject
        .to_string()
        .chars()
        .collect::<Vec<char>>();
    let mut result: bool = true;
    if subject_chars.len() > 4 && subject_chars.len() <= 16{
        let alphabet: Vec<char> = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890@_:.;"
            .to_string()
            .chars()
            .collect::<Vec<char>>();
        for subject_char in subject_chars {
            if !alphabet.contains(&subject_char){
                result = false;
            }
        }
    }
    else {
        result = false;
    }
    result
}

pub fn check_color_str(
    subject: &str
) -> bool {
    let mut result: bool = true;
    let mut subject_chars: Vec<char> = subject
        .to_string()
        .chars()
        .collect::<Vec<char>>();
    if subject_chars.len() != 7{
        result = false;
    }
    else {
        let alphabet: Vec<char> = "1234567890ABCDEF"
            .to_string()
            .chars()
            .collect::<Vec<char>>();
        if subject_chars[0] == '#'{
            subject_chars.remove(0);
            for character in subject_chars {
                if !alphabet.contains(&character){
                    result = false;
                }
            }
        }
        else {
            result = false;
        }
    }
    result
}

pub fn check_message(
    subject: &str
) -> bool {
    let msg_chars: Vec<char> = subject
        .to_string()
        .chars()
        .collect::<Vec<char>>();
    msg_chars.len() <= 245
}

pub async fn create_connection(
    db_url: &String
) -> Result<Pool<Postgres>, YokaiErr> {
    let conn = match postgres::PgPool::connect(
        db_url
    ).await{
        Ok(conn) => conn,
        Err(e) => return Err::<Pool<Postgres>, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    Ok(conn)
}
