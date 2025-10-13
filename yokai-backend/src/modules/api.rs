/*
Yokai by Alyx Shang.
Licensed under the FSL v1.
*/

use actix_web::post;
use std::path::PathBuf;
use std::fs::create_dir;
use super::models::User;
use actix_web::web::Data;
use super::err::YokaiErr;
use actix_web::web::Json;
use super::units::AppData;
use super::utils::rfc2282;
use std::env::current_dir;
use super::db::user_exists;
use super::db::create_chat;
use actix_files::NamedFile;
use super::db::create_user;
use super::models::UserFile;
use super::db::delete_token;
use actix_web::HttpResponse;
use super::db::file_on_file;
use super::db::edit_user_pfp;
use super::db::get_user_by_id;
use super::models::InviteCode;
use super::db::delete_account;
use super::utils::hash_string;
use super::db::get_file_by_id;
use super::db::get_user_files;
use super::db::create_message;
use super::db::get_user_tokens;
use super::models::UserAPIToken;
use super::db::create_api_token;
use super::db::create_user_file;
use super::db::delete_user_file;
use super::payloads::EditPayload;
use super::db::get_user_by_token;
use super::db::edit_host_primary;
use super::db::edit_user_primary;
use super::db::get_user_contacts;
use super::units::FileUploadForm;
use super::payloads::FilePayload;
use super::utils::decrypt_message;
use super::utils::encrypt_message;
use super::responses::UserContact;
use super::db::delete_invite_code;
use super::db::get_token_by_token;
use super::payloads::LoginPayload;
use super::db::edit_user_tertiary;
use super::db::edit_host_tertiary;
use super::db::create_invite_code;
use super::db::edit_user_password;
use super::responses::ListResponse;
use super::payloads::LogoutPayload;
use super::db::edit_user_secondary;
use super::db::edit_host_secondary;
use super::responses::TokenResponse;
use super::payloads::KickUserPayload;
use super::db::edit_user_description;
use super::responses::StatusResponse;
use super::payloads::TokenOnlyPayload;
use super::db::edit_user_display_name;
use super::payloads::DecryptionPayload;
use super::payloads::ChatCreatePayload;
use super::payloads::UserCreatePayload;
use super::payloads::SendMessagePayload;
use actix_multipart::form::MultipartForm;
use super::responses::UserCreateResponse;
use super::payloads::InviteCreatePayload;
use super::responses::DecryptionResponse;
use super::payloads::ChangePassworPayload;
use super::responses::UserContactsResponse;
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

#[post("/user/kick")]
pub async fn kick_user_service(
    payload: Json<KickUserPayload>,
    data: Data<AppData>
) -> Result<HttpResponse, YokaiErr>{
    let admin: User = match get_user_by_token(
       &payload.api_token,
       &data.pool
    ).await {
        Ok(admin) => admin,
        Err(e) => return Err::<HttpResponse, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    if admin.is_admin{
        let user: User = match get_user_by_id(
            &payload.username,
            &data.pool
        ).await {
            Ok(user) => user,
            Err(e) => return Err::<HttpResponse, YokaiErr>(
                YokaiErr::new(&e.to_string())
            )
        };
        let edit: bool = match delete_account(
            &user.username,
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

#[post("/user/delete")]
pub async fn delete_account_service(
    payload: Json<TokenOnlyPayload>,
    data: Data<AppData>
) -> Result<HttpResponse, YokaiErr>{
    let user: User = match get_user_by_token(
       &payload.api_token,
       &data.pool
    ).await {
        Ok(admin) => admin,
        Err(e) => return Err::<HttpResponse, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    let del_op: bool = match delete_account(
        &user.username,
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

#[post("/user/contacts")]
pub async fn user_contacts_service(
    payload: Json<TokenOnlyPayload>,
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
    let contacts: Vec<User> = match get_user_contacts(
        &user.username,
        &data.pool
    ).await {
        Ok(contacts) => contacts,
        Err(e) => return Err::<HttpResponse, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    let mut contacts_vec: Vec<UserContact> = Vec::new();
    for contact in contacts {
        // TODO
        let user_contact: UserContact = UserContact{
            username: contact.username,
            display_name: contact.display_name,
            description: contact.description,
            pfp_url: contact.user_pfp_id
        };
        contacts_vec.push(user_contact);        
    }
    let result: UserContactsResponse = UserContactsResponse{
        contacts: contacts_vec
    };
    Ok(HttpResponse::Ok().json(result))
}

#[post("/files/upload")]
pub async fn post_file_service(
    MultipartForm(form): MultipartForm<FileUploadForm>,
    data: Data<AppData>
) -> Result<HttpResponse, YokaiErr>{
    let api_token: String = form.json.api_token.clone();
    let file_name: String = form.json.name.clone();
    let user: User = match get_user_by_token(
       &api_token,
       &data.pool
    ).await {
        Ok(user) => user,
        Err(e) => return Err::<HttpResponse, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    let file_id: String = hash_string(
        &format!(
            "{}{}{}",
            &file_name,
            &user.username,
            &rfc2282()
        )
    );
    let mut path_buf: PathBuf = PathBuf::new();
    let current: PathBuf = match current_dir(){
        Ok(current) => current,
        Err(e) => return Err::<HttpResponse, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    path_buf.push(current);
    path_buf.push("user_files");
    if !path_buf.exists(){         
        let _created_dir: () = match create_dir(
            &path_buf.as_path()
        ){
            Ok(_created_dir) => {},
            Err(e) => return Err::<HttpResponse, YokaiErr>(
                YokaiErr::new(&e.to_string())
            )
        };
    }
    path_buf.push(&file_id);
    let _: () = match form.file.file.persist(path_buf.as_path()){
        Ok(_f) => {},
        Err(e) => return Err::<HttpResponse, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    let user_file: bool = match create_user_file(
        &user.username,
        &path_buf.display().to_string(),
        &file_id,
        &data.pool
    ).await {
        Ok(_user_file) => true,
        Err(_e) => false
    };
    let result: StatusResponse = StatusResponse{ 
        status: user_file 
    };
    Ok(HttpResponse::Ok().json(result))
}

#[post("/file/serve")]
pub async fn serve_file_service(
    payload: Json<FilePayload>,
    data: Data<AppData>
) -> Result<NamedFile, YokaiErr>{
    let user: User = match get_user_by_token(
       &payload.api_token,
       &data.pool
    ).await {
        Ok(user) => user,
        Err(e) => return Err::<NamedFile, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    let file: UserFile = match get_file_by_id(
        &payload.file_id,
        &data.pool
    ).await {
        Ok(file) => file,
        Err(e) => return Err::<NamedFile, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    let named_file = match NamedFile::open(file.file_path){
        Ok(named_file) => named_file,
        Err(e) => return Err::<NamedFile, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    if user.username == file.file_owner{
        Ok(named_file)
    }
    else {
        Err::<NamedFile, YokaiErr>(
            YokaiErr::new("File ownership could not be verified.")
        )
    }
}

#[post("/files/delete")]
pub async fn delete_file_service(
    payload: Json<FilePayload>,
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
    let file: UserFile = match get_file_by_id(
        &payload.file_id,
        &data.pool
    ).await {
        Ok(file) => file,
        Err(e) => return Err::<HttpResponse, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    if user.username == file.file_owner {
        let del_op: bool = match delete_user_file(
            &file.file_id,
            &data.pool
        ).await {
            Ok(_f) => true,
            Err(_e) => false
        };
        let response: StatusResponse = StatusResponse{ 
            status: del_op 
        };
        Ok(HttpResponse::Ok().json(response))
    }
    else {
        Err::<HttpResponse, YokaiErr>(
            YokaiErr::new("File ownership could not be verified.")
        )
    }
}

#[post("/user/tokens")]
pub async fn list_user_tokens_service(
    payload: Json<TokenOnlyPayload>,
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
    let tokens: Vec<UserAPIToken> = match get_user_tokens(
        &user.username,
        &data.pool
    ).await {
        Ok(tokens) => tokens,
        Err(e) => return Err::<HttpResponse, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    let mut ids: Vec<String> = Vec::new();
    for token in tokens {
        ids.push(token.token_id);
    }
    let result: ListResponse = ListResponse{
        object_ids: ids
    };
    Ok(HttpResponse::Ok().json(result))
}

#[post("/user/files")]
pub async fn list_user_files_service(
    payload: Json<TokenOnlyPayload>,
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
    let files: Vec<UserFile> = match get_user_files(
        &user.username,
        &data.pool
    ).await {
        Ok(files) => files,
        Err(e) => return Err::<HttpResponse, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    let mut ids: Vec<String> = Vec::new();
    for file in files {
        ids.push(file.file_id);
    }
    let result: ListResponse = ListResponse{
        object_ids: ids
    };
    Ok(HttpResponse::Ok().json(result))
}

#[post("/chat/create")]
pub async fn create_chat_service(
    payload: Json<ChatCreatePayload>,
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
    let recv_exists: bool = user_exists(
        &payload.receiver, 
        &data.pool
    ).await;
    if recv_exists{
        let created: bool = match create_chat(
            &user.username,
            &payload.receiver,
            &data.pool
        ).await {
            Ok(_c) => true,
            Err(_e) => false
        };
        let status_response: StatusResponse = StatusResponse{ 
            status: created
        };
        Ok(HttpResponse::Ok().json(status_response))
    }
    else {
        Err::<HttpResponse, YokaiErr>(
            YokaiErr::new("User does not exist.")
        )
    }
}

#[post("/message/send")]
pub async fn send_message_service(
    payload: Json<SendMessagePayload>,
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
    let recv_exists: bool = user_exists(
        &payload.receiver, 
        &data.pool
    ).await;
    if recv_exists{
        let encrypted: String = match encrypt_message(
            &payload.msg,
            &user.public_key
        ){
            Ok(encrypted) => encrypted,
            Err(e) => return Err::<HttpResponse, YokaiErr>(
                YokaiErr::new(&e.to_string())
            )
        };
        let new_message: bool = match create_message(
            &encrypted,
            &user.username,
            &payload.chat_id,
            &payload.receiver,
            &payload.attachment,
            &data.pool
        ).await {
            Ok(_n) => true,
            Err(_e) => false
        };
        let result: StatusResponse = StatusResponse{
            status: new_message
        };
        Ok(HttpResponse::Ok().json(result))
    }
    else {
        Err::<HttpResponse, YokaiErr>(
            YokaiErr::new("Receiver does not exist.")
        )
    }
}

#[post("/message/decrypt")]
pub async fn decrypt_message_service(
    payload: Json<DecryptionPayload>,
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
    let decrypted_msg: String = match decrypt_message(
        &payload.message,
        &user.private_key
    ){
        Ok(decrypted_msg) => decrypted_msg,
        Err(e) => return Err::<HttpResponse, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    let result: DecryptionResponse = DecryptionResponse{
        message: decrypted_msg
    };
    Ok(HttpResponse::Ok().json(result))
}
