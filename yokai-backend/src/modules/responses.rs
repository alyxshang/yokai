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

#[derive(Serialize)]
pub struct UserContact {
    pub username: String,
    pub description: String,
    pub display_name: String,
    pub pfp_url: Option<String>
}

#[derive(Serialize)]
pub struct UserContactsResponse {
    pub contacts: Vec<UserContact>
}

#[derive(Serialize)]
pub struct FileCreateResponse{
    pub file_url: String
}

#[derive(Serialize)]
pub struct ListResponse{
    pub object_ids: Vec<String>
}

#[derive(Serialize)]
pub struct DecryptionResponse{
    pub message: String
}
