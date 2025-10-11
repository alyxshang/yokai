/*
Yokai by Alyx Shang.
Licensed under the FSL v1.
*/

use sqlx::Pool;
use std::env::var;
use super::err::YokaiErr;
use super::units::KeyPair;
use super::utils::rfc2282;
use sqlx::postgres::Postgres;
use super::utils::hash_string;
use super::utils::check_message;
use super::utils::check_username;
use super::utils::check_password;
use super::utils::check_color_str;
use super::utils::decrypt_message;
use super::utils::encrypt_message;
use super::utils::generate_keypair;
use super::utils::create_connection;

#[tokio::test]
pub async fn test_utils(){
    let rfc_str: String = rfc2282();
    assert_eq!(rfc_str.is_empty(), false);
    let hashed_str: String = hash_string("Hello World!");
    assert_eq!(hashed_str.is_empty(), false);
    let username_chk_t: bool = check_username("alyxshang");
    assert_eq!(username_chk_t, true);
    let username_chk_f: bool = check_username("alyxshangHH");
    assert_eq!(username_chk_f, false);
    let msg_chk: bool = check_message("Hi my name is Alyx.");
    assert_eq!(msg_chk, true);
    let pwd_chk: bool = check_password("WrongCodeIsEvil");
    assert_eq!(pwd_chk, true);
    let color_chk_t: bool = check_color_str("#DF0045");
    assert_eq!(color_chk_t, true);
    let color_chk_f: bool = check_color_str("#DF00450");
    assert_eq!(color_chk_f, false);
    let keys: KeyPair = generate_keypair()
        .expect("Error making keys.");
    assert_eq!(keys.public_key.is_empty(), false);
    assert_eq!(keys.private_key.is_empty(), false);
    let db_url: String = var("YOKAI_DB_URL")
        .expect("Yokai DB URL not found.");
    let conn: Result<Pool<Postgres>, YokaiErr> = create_connection(&db_url)
        .await;
    assert_eq!(conn.is_ok(), true);
    let msg: String = "Hello World!".to_string();
    let encrypted: String = encrypt_message(&msg, &keys.public_key)
        .expect("Error encrypting.");
    let decrypted: String = decrypt_message(&encrypted, &keys.private_key)
        .expect("Error decrypting.");
    assert_eq!(msg, decrypted);
}
