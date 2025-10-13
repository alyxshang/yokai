/*
Yokai by Alyx Shang.
Licensed under the FSL v1.
*/

use sqlx::Pool;
use actix_web::App;
use actix_cors::Cors;
use super::models::User;
use super::err::YokaiErr;
use super::units::Config;
use actix_web::web::Data;
use super::units::AppData;
use actix_web::HttpServer;
use super::db::create_user;
use super::db::user_exists;
use super::db::get_host_info;
use sqlx::postgres::Postgres;
use super::config::get_config;
use super::api::login_service;
use super::api::logout_service;
use super::db::create_host_info;
use super::api::edit_bio_service;
use super::api::edit_pfp_service;
use super::api::post_file_service;
use super::api::kick_user_service;
use actix_web::middleware::Logger;
use super::models::HostInformation;
use super::api::serve_file_service;
use super::api::delete_file_service;
use super::api::create_chat_service;
use super::utils::create_connection;
use super::api::user_create_service;
use super::api::send_message_service;
use super::api::edit_password_service;
use super::api::user_contacts_service;
use super::api::invite_create_service;
use super::api::delete_account_service;
use super::api::decrypt_message_service;
use super::api::list_user_files_service;
use super::api::list_user_tokens_service;
use super::api::edit_user_primary_service;
use super::api::edit_display_name_service;
use super::api::edit_host_primary_service;
use super::api::edit_host_tertiary_service;
use super::api::edit_user_tertiary_service;
use super::api::edit_user_secondary_service;
use super::api::edit_host_secondary_service;

pub async fn run_app() -> Result<(), YokaiErr>{
    let config_vars: Config = match get_config(){
        Ok(config_vars) => config_vars,
        Err(e) => return Err::<(), YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    let db_connection: Pool<Postgres> = match create_connection(
        &config_vars.db_url
    ).await {
        Ok(db_connection) => db_connection,
        Err(e) => return Err::<(), YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };

    let admin_exists: bool = user_exists(
        &config_vars.admin_username,
        &db_connection
    ).await;
    let host_info_exists: bool = get_host_info(&db_connection)
        .await
        .is_ok();
    if !host_info_exists{
        let _h_info: HostInformation = match create_host_info(
            &config_vars.primary_color,
            &config_vars.secondary_color,
            &config_vars.tertiary_color,
            &config_vars.hostname,
            &db_connection
        ).await {
            Ok(_h_info) => _h_info,
            Err(e) => return Err::<(), YokaiErr>(
                YokaiErr::new(&e.to_string())
            )
        };
    }
    if !admin_exists{
        let _a_info: User = match create_user(
            &config_vars.admin_username,
            &config_vars.admin_password,
            &true,
            &config_vars.admin_description,
            &config_vars.admin_display_name,
            &config_vars.admin_primary_color,
            &config_vars.admin_tertiary_color,
            &config_vars.admin_secondary_color,
            &None,
            &db_connection
        ).await {
            Ok(_a_info) => _a_info,
            Err(e) => return Err::<(), YokaiErr>(
                YokaiErr::new(&e.to_string())
            )
        }; 
    }
    let app_data: AppData = AppData{
        pool: db_connection
    };
    let state_data: Data<AppData> = Data::new(app_data);
    let server_addr: String = format!("{}:{}", &config_vars.app_host, &config_vars.app_port);
    let server = match HttpServer::new(
        move || {
            let cors = Cors::default()
                .allowed_origin("*")
                .allowed_methods(vec!["GET", "POST"]);
            App::new()
                .wrap(cors)
                .wrap(Logger::new("%a %{User-Agent}i")
                .app_data(state_data.clone())
                .service(kick_user_service)
                .service(create_chat_service)
                .service(login_service)
                .service(user_create_service)
                .service(user_contacts_service)
                .service(send_message_service)
                .service(list_user_files_service)
                .service(logout_service)
                .service(invite_create_service)
                .service(list_user_tokens_service)
                .service(serve_file_service)
                .service(post_file_service)
                .service(edit_user_tertiary_service)
                .service(edit_host_tertiary_service)
                .service(edit_password_service)
                .service(edit_host_secondary_service)
                .service(edit_host_primary_service)
                .service(edit_pfp_service)
                .service(delete_file_service)
                .service(edit_display_name_service)
                .service(edit_user_secondary_service)
                .service(edit_bio_service)
                .service(edit_user_primary_service)
                .service(decrypt_message_service)
                .service(delete_account_service)
        }
    ).bind(server_addr){
        Ok(server) => server,
        Err(e) => return Err::<(), YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    let _ = server.run().await;
    Ok(())
}
