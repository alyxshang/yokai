/*
Yokai by Alyx Shang.
Licensed under the FSL v1.
*/


use sqlx::Pool;
use sqlx::postgres::Postgres;

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
