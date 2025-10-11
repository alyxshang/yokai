/*
Yokai by Alyx Shang.
Licensed under the FSL v1.
*/

use serde::Serialize;

#[derive(Serialize)]
pub struct StatusResponse {
    pub status: bool
}

#[derive(Serialize)]
pub struct InviteCreateResponse {
    pub code: String
}

#[derive(Serialize)]
pub struct TokenResponse {
    pub api_token: String
}

#[derive(Serialize)]
pub struct UserCreateResponse {
    pub username: String,
    pub description: String,
    pub display_name: String,
    pub primary_color: String,
    pub tertiary_color: String,
    pub secondary_color: String,
}
