/*
Yokai by Alyx Shang.
Licensed under the FSL v1.
*/

use sqlx::FromRow;

#[derive(FromRow, Clone)]
pub struct User {
    pub username: String,
    pub password: String,
    pub is_admin: bool,
    pub public_key: String,
    pub private_key: String,
    pub description: String,
    pub display_name: String,
    pub primary_color: String,
    pub tertiary_color: String,
    pub secondary_color: String,
    pub user_pfp_id: Option<String>
}

#[derive(FromRow, Clone)]
pub struct Chat{
    pub chat_id: String,
    pub started: String,
    pub sender: String,
    pub receiver: String,
}

#[derive(FromRow, Clone)]
pub struct Message{
    pub msg_id: String,
    pub published: String,
    pub content: String,
    pub sender: String,
    pub receiver: String,
    pub attachment: Option<String>,
    pub chat_id: String
}

#[derive(FromRow, Clone)]
pub struct UserFile{
    pub file_id: String,
    pub file_path: String,
    pub file_owner: String
}

#[derive(FromRow, Clone)]
pub struct HostInformation{
    pub hostname: String,
    pub primary_color: String,
    pub secondary_color: String,
    pub tertiary_color: String
}

#[derive(FromRow, Clone)]
pub struct InviteCode {
    pub code_id: String,
    pub invite_code: String
}

#[derive(FromRow, Clone)]
pub struct UserAPIToken {
    pub token_id: String,
    pub token: String,
    pub owner: String
}
