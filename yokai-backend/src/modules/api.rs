/*
Yokai by Alyx Shang.
Licensed under the FSL v1.
*/

use actix_web::post;
use super::models::User;
use actix_web::web::Data;
use super::err::YokaiErr;
use actix_web::web::Json;
use super::units::AppData;
use super::db::create_user;
use super::db::delete_token;
use actix_web::HttpResponse;
use super::db::file_on_file;
use super::db::edit_user_pfp;
use super::models::InviteCode;
use super::models::UserAPIToken;
use super::db::create_api_token;
use super::payloads::EditPayload;
use super::db::get_user_by_token;
use super::db::edit_host_primary;
use super::db::edit_user_primary;
use super::db::delete_invite_code;
use super::db::get_token_by_token;
use super::payloads::LoginPayload;
use super::db::edit_user_tertiary;
use super::db::edit_host_tertiary;
use super::db::create_invite_code;
use super::db::edit_user_password;
use super::payloads::LogoutPayload;
use super::db::edit_user_secondary;
use super::db::edit_host_secondary;
use super::responses::TokenResponse;
use super::db::edit_user_description;
use super::responses::StatusResponse;
use super::db::edit_user_display_name;
use super::payloads::UserCreatePayload;
use super::responses::UserCreateResponse;
use super::payloads::InviteCreatePayload;
use super::payloads::ChangePassworPayload;
use super::responses::InviteCreateResponse;

#[post("/invite/create")]
pub async fn invite_create_service(
    payload: Json<InviteCreatePayload>,
    data: Data<AppData>
) -> Result<HttpResponse, YokaiErr>{
    let user: User = match get_user_by_token(
       &payload.api_token,
       &data.pool
    ).await {
        Ok(user) => user,
        Err(e) => return Err::<HttpResponse, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    if user.is_admin{
        let code: InviteCode = match create_invite_code(
            &payload.code,
            &data.pool
        ).await {
            Ok(code) => code,
            Err(e) => return Err::<HttpResponse, YokaiErr>(
                YokaiErr::new(&e.to_string())
            )
        };
        let result: InviteCreateResponse = InviteCreateResponse {
            code: code.invite_code
        };
        Ok(HttpResponse::Ok().json(result))
    }
    else {
        Err::<HttpResponse, YokaiErr>(
            YokaiErr::new("User is not an administrator.")
        )
    }
}

#[post("/user/create")]
pub async fn user_create_service(
    payload: Json<UserCreatePayload>,
    data: Data<AppData>
) -> Result<HttpResponse, YokaiErr>{
    let del_code: bool = match delete_invite_code(
        &payload.invite_code, 
        &data.pool
    ).await {
        Ok(_f) => true,
        Err(_e) => false
    };
    if del_code {
        let user: User = match create_user(
            &payload.username,
            &payload.password,
            &false,
            &payload.description,
            &payload.display_name,
            &payload.primary_color,
            &payload.tertiary_color,
            &payload.secondary_color,
            &None,
            &data.pool
        ).await {
            Ok(user) => user,
            Err(e) => return Err::<HttpResponse, YokaiErr>(
                YokaiErr::new(&e.to_string())
            )
        };
        let result: UserCreateResponse = UserCreateResponse {
            username: user.username, 
            description: user.description, 
            display_name: user.display_name, 
            primary_color: user.primary_color, 
            tertiary_color: user.tertiary_color, 
            secondary_color: user.secondary_color
        };
        Ok(HttpResponse::Ok().json(result))
    }
    else {
        Err::<HttpResponse, YokaiErr>(
            YokaiErr::new("Invalid invite code used.")
        )
    }
}

#[post("/login")]
pub async fn login_service(
    payload: Json<LoginPayload>,
    data: Data<AppData>
) -> Result<HttpResponse, YokaiErr>{
    let token_obj: UserAPIToken = match create_api_token(
        &payload.username,
        &payload.password,
        &data.pool
    ).await {
        Ok(token_obj) => token_obj,
        Err(e) => return Err::<HttpResponse, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    let result: TokenResponse = TokenResponse{
        api_token: token_obj.token
    };
    Ok(HttpResponse::Ok().json(result))
}

#[post("/logout")]
pub async fn logout_service(
    payload: Json<LogoutPayload>,
    data: Data<AppData>
) -> Result<HttpResponse, YokaiErr>{
    let token_obj: UserAPIToken = match get_token_by_token(
        &payload.api_token,
        &data.pool
    ).await {
        Ok(token_obj) => token_obj,
        Err(e) => return Err::<HttpResponse, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    let del_op: bool = match delete_token(
        &token_obj.token,
        &data.pool
    ).await {
        Ok(_f) => true,
        Err(_e) => false
    };
    let result: StatusResponse = StatusResponse{
        status: del_op
    };
    Ok(HttpResponse::Ok().json(result))

}

#[post("/user/edit/password")]
pub async fn edit_password_service(
    payload: Json<ChangePassworPayload>,
    data: Data<AppData>
) -> Result<HttpResponse, YokaiErr>{
    let user: User = match get_user_by_token(
       &payload.api_token,
       &data.pool
    ).await {
        Ok(user) => user,
        Err(e) => return Err::<HttpResponse, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    let edit: bool = match edit_user_password(
        &user.username,
        &payload.old_password,
        &payload.new_password,
        &data.pool
    ).await {
        Ok(_f) => true,
        Err(_e) => false
    };
    let result: StatusResponse = StatusResponse{
        status: edit
    };
    Ok(HttpResponse::Ok().json(result))

}

#[post("/user/edit/name")]
pub async fn edit_display_name_service(
    payload: Json<EditPayload>,
    data: Data<AppData>
) -> Result<HttpResponse, YokaiErr>{
    let user: User = match get_user_by_token(
       &payload.api_token,
       &data.pool
    ).await {
        Ok(user) => user,
        Err(e) => return Err::<HttpResponse, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    let edit: bool = match edit_user_display_name(
        &user.username,
        &payload.new_value,
        &data.pool
    ).await {
        Ok(_f) => true,
        Err(_e) => false
    };
    let result: StatusResponse = StatusResponse{
        status: edit
    };
    Ok(HttpResponse::Ok().json(result))

}

#[post("/user/edit/bio")]
pub async fn edit_bio_service(
    payload: Json<EditPayload>,
    data: Data<AppData>
) -> Result<HttpResponse, YokaiErr>{
    let user: User = match get_user_by_token(
       &payload.api_token,
       &data.pool
    ).await {
        Ok(user) => user,
        Err(e) => return Err::<HttpResponse, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    let edit: bool = match edit_user_description(
        &user.username,
        &payload.new_value,
        &data.pool
    ).await {
        Ok(_f) => true,
        Err(_e) => false
    };
    let result: StatusResponse = StatusResponse{
        status: edit
    };
    Ok(HttpResponse::Ok().json(result))

}

#[post("/user/edit/primary")]
pub async fn edit_user_primary_service(
    payload: Json<EditPayload>,
    data: Data<AppData>
) -> Result<HttpResponse, YokaiErr>{
    let user: User = match get_user_by_token(
       &payload.api_token,
       &data.pool
    ).await {
        Ok(user) => user,
        Err(e) => return Err::<HttpResponse, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    let edit: bool = match edit_user_primary(
        &user.username,
        &payload.new_value,
        &data.pool
    ).await {
        Ok(_f) => true,
        Err(_e) => false
    };
    let result: StatusResponse = StatusResponse{
        status: edit
    };
    Ok(HttpResponse::Ok().json(result))
}

#[post("/user/edit/secondary")]
pub async fn edit_user_secondary_service(
    payload: Json<EditPayload>,
    data: Data<AppData>
) -> Result<HttpResponse, YokaiErr>{
    let user: User = match get_user_by_token(
       &payload.api_token,
       &data.pool
    ).await {
        Ok(user) => user,
        Err(e) => return Err::<HttpResponse, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    let edit: bool = match edit_user_secondary(
        &user.username,
        &payload.new_value,
        &data.pool
    ).await {
        Ok(_f) => true,
        Err(_e) => false
    };
    let result: StatusResponse = StatusResponse{
        status: edit
    };
    Ok(HttpResponse::Ok().json(result))
}

#[post("/user/edit/tertiary")]
pub async fn edit_user_tertiary_service(
    payload: Json<EditPayload>,
    data: Data<AppData>
) -> Result<HttpResponse, YokaiErr>{
    let user: User = match get_user_by_token(
       &payload.api_token,
       &data.pool
    ).await {
        Ok(user) => user,
        Err(e) => return Err::<HttpResponse, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    let edit: bool = match edit_user_tertiary(
        &user.username,
        &payload.new_value,
        &data.pool
    ).await {
        Ok(_f) => true,
        Err(_e) => false
    };
    let result: StatusResponse = StatusResponse{
        status: edit
    };
    Ok(HttpResponse::Ok().json(result))
}

#[post("/user/edit/pfp")]
pub async fn edit_pfp_service(
    payload: Json<EditPayload>,
    data: Data<AppData>
) -> Result<HttpResponse, YokaiErr>{
    let user: User = match get_user_by_token(
       &payload.api_token,
       &data.pool
    ).await {
        Ok(user) => user,
        Err(e) => return Err::<HttpResponse, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    let f_exists: bool = file_on_file(
        &payload.new_value, 
        &data.pool
    ).await;
    if f_exists{
        let edit: bool = match edit_user_pfp(
            &user.username,
            &payload.new_value,
            &data.pool
        ).await {
            Ok(_f) => true,
            Err(_e) => false
        };
        let result: StatusResponse = StatusResponse{
            status: edit
        };
        Ok(HttpResponse::Ok().json(result))
    }
    else {
        Err::<HttpResponse, YokaiErr>(
            YokaiErr::new("The file supplied does not exist.")
        )
    }
}

#[post("/host/edit/primary")]
pub async fn edit_host_primary_service(
    payload: Json<EditPayload>,
    data: Data<AppData>
) -> Result<HttpResponse, YokaiErr>{
    let user: User = match get_user_by_token(
       &payload.api_token,
       &data.pool
    ).await {
        Ok(user) => user,
        Err(e) => return Err::<HttpResponse, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    if user.is_admin{
        let edit: bool = match edit_host_primary(
            &payload.new_value,
            &data.pool
        ).await {
            Ok(_f) => true,
            Err(_e) => false
        };
        let result: StatusResponse = StatusResponse{
            status: edit
        };
        Ok(HttpResponse::Ok().json(result))
    }
    else {
        Err::<HttpResponse, YokaiErr>(
            YokaiErr::new("Requesting user is not an administrator.")
        )
    }
}

#[post("/host/edit/secondary")]
pub async fn edit_host_secondary_service(
    payload: Json<EditPayload>,
    data: Data<AppData>
) -> Result<HttpResponse, YokaiErr>{
    let user: User = match get_user_by_token(
       &payload.api_token,
       &data.pool
    ).await {
        Ok(user) => user,
        Err(e) => return Err::<HttpResponse, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    if user.is_admin{
        let edit: bool = match edit_host_secondary(
            &payload.new_value,
            &data.pool
        ).await {
            Ok(_f) => true,
            Err(_e) => false
        };
        let result: StatusResponse = StatusResponse{
            status: edit
        };
        Ok(HttpResponse::Ok().json(result))
    }
    else {
        Err::<HttpResponse, YokaiErr>(
            YokaiErr::new("Requesting user is not an administrator.")
        )
    }
}

#[post("/host/edit/tertiary")]
pub async fn edit_host_tertiary_service(
    payload: Json<EditPayload>,
    data: Data<AppData>
) -> Result<HttpResponse, YokaiErr>{
    let user: User = match get_user_by_token(
       &payload.api_token,
       &data.pool
    ).await {
        Ok(user) => user,
        Err(e) => return Err::<HttpResponse, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    if user.is_admin{
        let edit: bool = match edit_host_tertiary(
            &payload.new_value,
            &data.pool
        ).await {
            Ok(_f) => true,
            Err(_e) => false
        };
        let result: StatusResponse = StatusResponse{
            status: edit
        };
        Ok(HttpResponse::Ok().json(result))
    }
    else {
        Err::<HttpResponse, YokaiErr>(
            YokaiErr::new("Requesting user is not an administrator.")
        )
    }
}
