/*
Yokai by Alyx Shang.
Licensed under the FSL v1.
*/


use sqlx::Pool;
use serde::Deserialize;
use sqlx::postgres::Postgres;
use actix_multipart::form::MultipartForm;
use actix_multipart::form::tempfile::TempFile;
use actix_multipart::form::json::Json as MPJson;


pub struct KeyPair {
    pub private_key: String,
    pub public_key: String
}

pub struct AppData {
    pub pool: Pool<Postgres>
}

pub struct Config{
    pub hostname: String,
    pub app_host: String,
    pub app_port: String,
    pub primary_color: String,
    pub secondary_color: String,
    pub tertiary_color: String,
    pub admin_username: String,
    pub admin_password: String,
    pub admin_description: String,
    pub admin_display_name: String,
    pub admin_primary_color: String,
    pub admin_tertiary_color: String,
    pub admin_secondary_color: String,
}

#[derive(Debug, Deserialize)]
pub struct FileMetadata {
    pub name: String,
    pub api_token: String
}

#[derive(Debug, MultipartForm)]
pub struct FileUploadForm {
    #[multipart(limit = "30MB")]
    pub file: TempFile,
    pub json: MPJson<FileMetadata>,
}
