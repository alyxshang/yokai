/*
Yokai by Alyx Shang.
Licensed under the FSL v1.
*/

use serde::Deserialize;

#[derive(Deserialize)]
pub struct InviteCreatePayload {
    pub api_token: String,
    pub code: String
}

#[derive(Deserialize)]
pub struct EditPayload{
    pub api_token: String,
    pub new_value: String
}

#[derive(Deserialize)]
pub struct LoginPayload{
    pub username: String,
    pub password: String
}

#[derive(Deserialize)]
pub struct LogoutPayload{
    pub api_token: String
}

#[derive(Deserialize)]
pub struct UserCreatePayload{
    pub username: String,
    pub password: String,
    pub description: String,
    pub display_name: String,
    pub primary_color: String,
    pub tertiary_color: String,
    pub secondary_color: String,
    pub invite_code: String
}

#[derive(Deserialize)]
pub struct ChangePassworPayload{
    pub api_token: String,
    pub old_password: String,
    pub new_password: String
}

#[derive(Deserialize)]
pub struct KickUserPayload{
    pub api_token: String,
    pub username: String
}

#[derive(Deserialize)]
pub struct TokenOnlyPayload{
    pub api_token: String
}

#[derive(Deserialize)]
pub struct UserFileServePayload{
    pub file_id: String,
    pub api_token: String
}
