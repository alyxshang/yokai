/*
Yokai by Alyx Shang.
Licensed under the FSL v1.
*/

use sqlx::Pool;
use sqlx::query;
use bcrypt::hash;
use sqlx::query_as;
use bcrypt::verify;
use super::models::User;
use super::models::Chat;
use super::err::YokaiErr;
use bcrypt::DEFAULT_COST;
use std::fs::remove_file;
use super::utils::rfc2282;
use super::units::KeyPair;
use super::models::Message;
use super::models::UserFile;
use sqlx::postgres::Postgres;
use super::utils::hash_string;
use super::models::InviteCode;
use super::models::UserAPIToken;
use super::utils::check_message;
use super::utils::check_username;
use super::utils::check_password;
use super::utils::check_color_str;
use super::utils::encrypt_message;
use super::utils::generate_keypair;
use super::models::HostInformation;

// used.
pub async fn create_user(
    username: &str,
    password: &str,
    is_admin: &bool,
    description: &str,
    display_name: &str,
    primary_color: &str,
    tertiary_color: &str,
    secondary_color: &str,
    user_pfp_id: &Option<String>,
    pool: &Pool<Postgres>
) -> Result<User, YokaiErr>{
    if check_color_str(primary_color) &&
       check_color_str(secondary_color) &&
       check_color_str(tertiary_color) &&
       check_username(username) &&
       check_password(password)
    {
        let hashed_pwd: String = match hash(password, DEFAULT_COST){
            Ok(hashed_pwd) => hashed_pwd,
            Err(e) => return Err::<User, YokaiErr>(
                YokaiErr::new(&e.to_string())
            )
        };
        let pair: KeyPair = match generate_keypair(){
            Ok(pair) => pair,
            Err(e) => return Err::<User, YokaiErr>(
                YokaiErr::new(&e.to_string())
            )
 
        };
        let obj: User = User {
            username: username.to_string(),
            password: hashed_pwd,
            is_admin: *is_admin,
            public_key: pair.public_key,
            private_key: pair.private_key,
            description: description.to_string(),
            display_name: display_name.to_string(),
            primary_color: primary_color.to_string(),
            tertiary_color: tertiary_color.to_string(),
            secondary_color: secondary_color.to_string(),
            user_pfp_id: user_pfp_id.to_owned()
        };
        let _insert_op = match query!(
            "INSERT INTO users (username, password, is_admin, public_key, private_key, description, display_name, primary_color, tertiary_color, secondary_color, user_pfp_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
            obj.username,
            obj.password,
            obj.is_admin,
            obj.public_key,
            obj.private_key,
            obj.description,
            obj.display_name,
            obj.primary_color,
            obj.tertiary_color,
            obj.secondary_color,
            obj.user_pfp_id
        )
            .execute(pool)
            .await
        {
            Ok(_feedback) => {},
            Err(e) => return Err::<User, YokaiErr>(
                YokaiErr::new(&e.to_string())
            )
        };
        let fetched: User = match get_user_by_id(
            &obj.username,
            pool
        ).await {
            Ok(user) => user,
            Err(e) => return Err::<User, YokaiErr>(
                YokaiErr::new(&e.to_string())
            )
        };
        Ok(fetched)
    }
    else {
        Err::<User, YokaiErr>(
            YokaiErr::new("Username, colors, or password could not be verified.")
        )
    }
}

// used.
pub async fn get_user_by_id(
    user_id: &str,
    pool: &Pool<Postgres>
) -> Result<User, YokaiErr>{
    let object: User = match query_as!(
        User,
        "SELECT * FROM users WHERE username = $1",
        user_id
    )
        .fetch_one(pool)
        .await 
    {
        Ok(object) => object,
        Err(e) => return Err::<User, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    Ok(object)
}

// used.
pub async fn edit_user_password(
    username: &str,
    old_password: &str,
    new_password: &str,
    pool: &Pool<Postgres>
) -> Result<(), YokaiErr>{
    if check_password(new_password){
        let user: User = match get_user_by_id(
            username,
            pool
        ).await {
            Ok(user) => user,
            Err(e) => return Err::<(), YokaiErr>(
                YokaiErr::new(&e.to_string())
            )
        };
        let verify: bool = match verify(old_password, &user.password){
            Ok(verify) => verify,
            Err(e) => return Err::<(), YokaiErr>(
                YokaiErr::new(&e.to_string())
            )
        };
        if verify{
            let hashed_pwd: String = match hash(new_password, DEFAULT_COST){
                Ok(hashed_pwd) => hashed_pwd,
                Err(e) => return Err::<(), YokaiErr>(
                    YokaiErr::new(&e.to_string())
                )
            };
            let update_op: () = match query!(
                "UPDATE users SET password = $1 WHERE username = $2",
                hashed_pwd,
                user.username
            )
                .execute(pool)
                .await
            {
                Ok(_f) => {},
                Err(e) => return Err::<(), YokaiErr>(
                    YokaiErr::new(&e.to_string())
                )
            };
            Ok(update_op)
        }
        else {
            Err::<(), YokaiErr>(
                YokaiErr::new("Password could not be verified.")
            )
        }
    }
    else {
        Err::<(), YokaiErr>(
            YokaiErr::new("New password string is not a valid password string.")
        )
    }
}

// used.
pub async fn edit_user_display_name(
    username: &str,
    new_display_name: &str,
    pool: &Pool<Postgres>
) -> Result<(), YokaiErr>{
    let user: User = match get_user_by_id(
        username,
        pool
    ).await {
        Ok(user) => user,
        Err(e) => return Err::<(), YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    let update_op: () = match query!(
        "UPDATE users SET display_name = $1 WHERE username = $2",
        new_display_name,
        user.username
    )
        .execute(pool)
        .await
    {
        Ok(_f) => {},
        Err(e) => return Err::<(), YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    Ok(update_op)
}

// used.
pub async fn edit_user_pfp(
    username: &str,
    new_pfp_id: &str,
    pool: &Pool<Postgres>
) -> Result<(), YokaiErr>{
    let user: User = match get_user_by_id(
        username,
        pool
    ).await {
        Ok(user) => user,
        Err(e) => return Err::<(), YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    let update_op: () = match query!(
        "UPDATE users SET user_pfp_id = $1 WHERE username = $2",
        new_pfp_id,
        user.username
    )
        .execute(pool)
        .await
    {
        Ok(_f) => {},
        Err(e) => return Err::<(), YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    Ok(update_op)
}

// used.
pub async fn edit_user_description(
    username: &str,
    new_description: &str,
    pool: &Pool<Postgres>
) -> Result<(), YokaiErr>{
    let user: User = match get_user_by_id(
        username,
        pool
    ).await {
        Ok(user) => user,
        Err(e) => return Err::<(), YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    let update_op: () = match query!(
        "UPDATE users SET description = $1 WHERE username = $2",
        new_description,
        user.username
    )
        .execute(pool)
        .await
    {
        Ok(_f) => {},
        Err(e) => return Err::<(), YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    Ok(update_op)
}

// used.
pub async fn edit_user_primary(
    username: &str,
    new_primary: &str,
    pool: &Pool<Postgres>
) -> Result<(), YokaiErr>{
    if check_color_str(new_primary){
        let user: User = match get_user_by_id(
            username,
            pool
        ).await {
            Ok(user) => user,
            Err(e) => return Err::<(), YokaiErr>(
                YokaiErr::new(&e.to_string())
            )
        };
        let update_op: () = match query!(
            "UPDATE users SET primary_color = $1 WHERE username = $2",
            new_primary,
            user.username
        )
            .execute(pool)
            .await
        {
            Ok(_f) => {},
            Err(e) => return Err::<(), YokaiErr>(
                YokaiErr::new(&e.to_string())
            )
        };
        Ok(update_op)
    }
    else {
        Err::<(), YokaiErr>(
            YokaiErr::new("Supplied string not a valid color.")
        )
    }

}

// used.
pub async fn edit_user_secondary(
    username: &str,
    new_secondary: &str,
    pool: &Pool<Postgres>
) -> Result<(), YokaiErr>{
    if check_color_str(new_secondary){
        let user: User = match get_user_by_id(
            username,
            pool
        ).await {
            Ok(user) => user,
            Err(e) => return Err::<(), YokaiErr>(
                YokaiErr::new(&e.to_string())
            )
        };
        let update_op: () = match query!(
            "UPDATE users SET secondary_color = $1 WHERE username = $2",
            new_secondary,
            user.username
        )
            .execute(pool)
            .await
        {
            Ok(_f) => {},
            Err(e) => return Err::<(), YokaiErr>(
                YokaiErr::new(&e.to_string())
            )
        };
        Ok(update_op)
    }
    else {
        Err::<(), YokaiErr>(
            YokaiErr::new("Supplied string not a valid color.")
        )
    }

}

// used.
pub async fn edit_user_tertiary(
    username: &str,
    new_tertiary: &str,
    pool: &Pool<Postgres>
) -> Result<(), YokaiErr>{
    if check_color_str(new_tertiary){
        let user: User = match get_user_by_id(
            username,
            pool
        ).await {
            Ok(user) => user,
            Err(e) => return Err::<(), YokaiErr>(
                YokaiErr::new(&e.to_string())
            )
        };
        let update_op: () = match query!(
            "UPDATE users SET tertiary_color = $1 WHERE username = $2",
            new_tertiary,
            user.username
        )
            .execute(pool)
            .await
        {
            Ok(_f) => {},
            Err(e) => return Err::<(), YokaiErr>(
                YokaiErr::new(&e.to_string())
            )
        };
        Ok(update_op)
    }
    else {
        Err::<(), YokaiErr>(
            YokaiErr::new("Supplied string not a valid color.")
        )
    }
}

// used.
pub async fn delete_user(
    user_id: &str,
    pool: &Pool<Postgres>
) -> Result<(), YokaiErr>{
    let user: User = match get_user_by_id(
        user_id,
        pool
    ).await {
        Ok(user) => user,
        Err(e) => return Err::<(), YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    let del_op: () = match query!(
        "DELETE FROM users WHERE username = $1",
        user.username
    )
        .execute(pool)
        .await 
    {
        Ok(_f) => {},
        Err(e) => return Err::<(), YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    Ok(del_op)
}

pub async fn create_message(
    msg: &str,
    sender: &str,
    chat_id: &str,
    receiver: &str,
    attachment: &Option<String>,
    pool: &Pool<Postgres>
) -> Result<Message, YokaiErr>{
    if check_message(msg){
        let sender_obj: User = match get_user_by_id(
            sender,
            pool
        ).await {
            Ok(sender_obj) => sender_obj,
            Err(e) => return Err::<Message, YokaiErr>(
                YokaiErr::new(&e.to_string())
            )
        };
        let receiver_obj: User = match get_user_by_id(
            receiver,
            pool
        ).await {
            Ok(receiver_obj) => receiver_obj,
            Err(e) => return Err::<Message, YokaiErr>(
                YokaiErr::new(&e.to_string())
            )
        };
        let id: String = hash_string(
            &format!(
                "{}{}{}", 
                &sender_obj.username,
                &receiver_obj.username,
                &rfc2282()
            )
        );
        let encrypted_content: String = match encrypt_message(
            &sender_obj.public_key,
            msg
        ){
            Ok(encrypted_content) => encrypted_content,
            Err(e) => return Err::<Message, YokaiErr>(
                YokaiErr::new(&e.to_string())
            )
        };
        let chat: Chat = match get_chat_by_id(
            chat_id, 
            pool
        ).await {
            Ok(chat) => chat,
            Err(e) => return Err::<Message, YokaiErr>(
                YokaiErr::new(&e.to_string())
            )
        };
        let msg: Message = Message{
            msg_id: id,
            published: rfc2282(),
            content: encrypted_content,
            sender: sender_obj.username,
            receiver: receiver_obj.username,
            attachment: attachment.clone(),
            chat_id: chat.chat_id
        };
        let _insert_op = match query!(
            "INSERT INTO messages (msg_id, published, content, sender, receiver, attachment, chat_id) VALUES ($1, $2, $3, $4, $5, $6, $7)",
            msg.msg_id,
            msg.published,
            msg.content,
            msg.sender,
            msg.receiver,
            msg.attachment,
            msg.chat_id,
        )
            .execute(pool)
            .await
        {
            Ok(_feedback) => {},
            Err(e) => return Err::<Message, YokaiErr>(
                YokaiErr::new(&e.to_string())
            )
        };
        let fetched: Message = match get_message_by_id(
            &msg.msg_id,
            pool
        ).await {
            Ok(fetched) => fetched,
            Err(e) => return Err::<Message, YokaiErr>(
                YokaiErr::new(&e.to_string())
            )
        };
        Ok(fetched)
    }
    else {
        Err::<Message, YokaiErr>(
            YokaiErr::new("Message contains illegal characters.")
        )
    }
}

pub async fn get_message_by_id(
    message_id: &str,
    pool: &Pool<Postgres>
) -> Result<Message, YokaiErr>{
    let object: Message = match query_as!(
        Message,
        "SELECT * FROM messages WHERE msg_id = $1",
        message_id
    )
        .fetch_one(pool)
        .await 
    {
        Ok(object) => object,
        Err(e) => return Err::<Message, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    Ok(object)
}

pub async fn delete_message(
    message_id: &str,
    pool: &Pool<Postgres>
) -> Result<(), YokaiErr>{
    let msg: Message = match get_message_by_id(
        message_id,
        pool
    ).await {
        Ok(msg) => msg,
        Err(e) => return Err::<(), YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    let del_op: () = match query!(
        "DELETE FROM messages WHERE msg_id = $1",
        msg.msg_id
    )
        .execute(pool)
        .await 
    {
        Ok(_f) => {},
        Err(e) => return Err::<(), YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    Ok(del_op)
}

pub async fn create_chat(
    sender: &str,
    receiver: &str,
    pool: &Pool<Postgres>
) -> Result<Chat, YokaiErr>{
    let exists: bool = chat_exists(
        sender,
        receiver,
        pool
    ).await;
    if exists {
        let sender_obj: User = match get_user_by_id(
            sender,
            pool
        ).await {
            Ok(sender_obj) => sender_obj,
            Err(e) => return Err::<Chat, YokaiErr>(
                YokaiErr::new(&e.to_string())
            )
        };
        let receiver_obj: User = match get_user_by_id(
            receiver,
            pool
        ).await {
            Ok(receiver_obj) => receiver_obj,
            Err(e) => return Err::<Chat, YokaiErr>(
                YokaiErr::new(&e.to_string())
            )
        };
        let id: String = hash_string(
            &format!(
                "{}{}{}",
                &sender_obj.username,
                &receiver_obj.username,
                &rfc2282()
            )
        );
        let chat: Chat = Chat{
            chat_id: id,
            started: rfc2282(),
            sender: sender_obj.username.clone(),
            receiver: receiver_obj.username.clone()
        };
        let _insert_op = match query!(
            "INSERT INTO chats (chat_id, started, sender, receiver) VALUES ($1, $2, $3, $4)",
            chat.chat_id,
            chat.started,
            chat.sender,
            chat.receiver,
        )
            .execute(pool)
            .await
        {
            Ok(_feedback) => {},
            Err(e) => return Err::<Chat, YokaiErr>(
                YokaiErr::new(&e.to_string())
            )
        };
        let fetched: Chat = match get_chat_by_id(
            &chat.chat_id,
            pool
        ).await {
            Ok(fetched) => fetched,
            Err(e) => return Err::<Chat, YokaiErr>(
                YokaiErr::new(&e.to_string())
            )
        };
        Ok(fetched)
    }
    else {
        Err::<Chat, YokaiErr>(
            YokaiErr::new("Cannot duplicate chats.")
        )
    }
}

pub async fn get_chat_by_id(
    chat_id: &str,
    pool: &Pool<Postgres>
) -> Result<Chat, YokaiErr>{
    let object: Chat = match query_as!(
        Chat,
        "SELECT * FROM chats WHERE chat_id = $1",
        chat_id
    )
        .fetch_one(pool)
        .await 
    {
        Ok(object) => object,
        Err(e) => return Err::<Chat, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    Ok(object)
}

pub async fn delete_chat(
    chat_id: &str,
    pool: &Pool<Postgres>
) -> Result<(), YokaiErr>{
    let chat: Chat = match get_chat_by_id(
        chat_id,
        pool
    ).await {
        Ok(chat) => chat,
        Err(e) => return Err::<(), YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    let del_op: () = match query!(
        "DELETE FROM chats WHERE chat_id = $1",
        chat.chat_id
    )
        .execute(pool)
        .await 
    {
        Ok(_f) => {},
        Err(e) => return Err::<(), YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    Ok(del_op)
}

pub async fn chat_exists(
    sender: &str,
    receiver: &str,
    pool: &Pool<Postgres>
) -> bool{
    get_chat_by_participants(
        sender, 
        receiver, 
        pool
    )
        .await
        .is_ok()
}

pub async fn get_chat_by_participants(
    sender: &str,
    receiver: &str,
    pool: &Pool<Postgres>
) -> Result<Chat, YokaiErr>{
    let objects: Vec<Chat> = match query_as!(
        Chat,
        "SELECT * FROM chats WHERE sender = $1 AND receiver = $2",
        sender,
        receiver
    )
        .fetch_all(pool)
        .await 
    {
        Ok(objects) => objects,
        Err(e) => return Err::<Chat, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    if objects.len() == 1{
        Ok(objects[0].clone())
    }
    else {
        Err::<Chat, YokaiErr>(
            YokaiErr::new("A chat could not be found.")
        )
    }
}

// used.
pub async fn create_invite_code(
    inv_code: &str,
    pool: &Pool<Postgres>
) -> Result<InviteCode, YokaiErr>{
    let id: String = hash_string(
        &format!(
            "{}{}",
            inv_code,
            rfc2282()
        )
    );
    let code: InviteCode = InviteCode{
        code_id: id, 
        invite_code: inv_code.to_string() 
    };
    let _insert_op = match query!(
        "INSERT INTO invite_codes (code_id, invite_code) VALUES ($1, $2)",
        code.code_id,
        code.invite_code,
    )
        .execute(pool)
        .await
    {
        Ok(_feedback) => {},
        Err(e) => return Err::<InviteCode, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    let fetched: InviteCode = match get_code_by_id(
        &code.code_id,
        pool
    ).await {
        Ok(code) => code,
        Err(e) => return Err::<InviteCode, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    Ok(fetched)
}

// used.
pub async fn get_code_by_id(
    code_id: &str,
    pool: &Pool<Postgres>
) -> Result<InviteCode, YokaiErr>{
    let object: InviteCode = match query_as!(
        InviteCode,
        "SELECT * FROM invite_codes WHERE code_id = $1",
        code_id
    )
        .fetch_one(pool)
        .await 
    {
        Ok(object) => object,
        Err(e) => return Err::<InviteCode, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    Ok(object)
}

// used.
pub async fn delete_invite_code(
    code_id: &str,
    pool: &Pool<Postgres>
) -> Result<(), YokaiErr>{
    let code: InviteCode = match get_code_by_id(
        code_id,
        pool
    ).await {
        Ok(code) => code,
        Err(e) => return Err::<(), YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    let del_op: () = match query!(
        "DELETE FROM invite_codes WHERE code_id = $1",
        code.code_id
    )
        .execute(pool)
        .await 
    {
        Ok(_f) => {},
        Err(e) => return Err::<(), YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    Ok(del_op)
}

// used.
pub async fn get_file_by_id(
    file_id: &str,
    pool: &Pool<Postgres>
) -> Result<UserFile, YokaiErr>{
    let object: UserFile = match query_as!(
        UserFile,
        "SELECT * FROM user_files WHERE file_id = $1",
        file_id
    )
        .fetch_one(pool)
        .await 
    {
        Ok(object) => object,
        Err(e) => return Err::<UserFile, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    Ok(object)
}

pub async fn delete_user_file(
    file_id: &str,
    pool: &Pool<Postgres>
) -> Result<(), YokaiErr>{
    let file: UserFile = match get_file_by_id(
        file_id,
        pool
    ).await {
        Ok(file) => file,
        Err(e) => return Err::<(), YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    let _del_op: () = match query!(
        "DELETE FROM user_files WHERE file_id = $1",
        file.file_id
    )
        .execute(pool)
        .await 
    {
        Ok(_f) => {},
        Err(e) => return Err::<(), YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    let file_del_op: () = match remove_file(file.file_path){
        Ok(_f) => {},
        Err(e) => return Err::<(), YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    Ok(file_del_op)
}

// used.
pub async fn create_user_file(
    user: &str,
    file_path: &str,
    file_id: &str,
    pool: &Pool<Postgres>
) -> Result<UserFile, YokaiErr>{
    let user_obj: User = match get_user_by_id(
        user,
        pool
    ).await {
        Ok(user_obj) => user_obj,
        Err(e) => return Err::<UserFile, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    let file: UserFile = UserFile {
        file_id: file_id.to_string(), 
        file_path: file_path.to_string(), 
        file_owner: user_obj.username
    };
    let _insert_op = match query!(
        "INSERT INTO user_files (file_id, file_path, file_owner) VALUES ($1, $2, $3)",
        file.file_id,
        file.file_path,
        file.file_owner
    )
        .execute(pool)
        .await
    {
        Ok(_feedback) => {},
        Err(e) => return Err::<UserFile, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    let fetched: UserFile = match get_file_by_id(
        &file.file_id,
        pool
    ).await {
        Ok(fetched) => fetched,
        Err(e) => return Err::<UserFile, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    Ok(fetched)
}

// used.
pub async fn get_host_info(
    pool: &Pool<Postgres>
) -> Result<HostInformation, YokaiErr>{
    let objects: Vec<HostInformation> = match query_as!(
        HostInformation,
        "SELECT * FROM host_info",
    )
        .fetch_all(pool)
        .await 
    {
        Ok(object) => object,
        Err(e) => return Err::<HostInformation, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    if objects.len() == 1{
        Ok(objects[0].clone())
    }
    else {
        Err::<HostInformation, YokaiErr>(
            YokaiErr::new("Host information could not be retrieved.")
        )
    }
}

pub async fn create_host_info(
    primary_color: &str,
    secondary_color: &str,
    tertiary_color: &str,
    hostname: &str,
    pool: &Pool<Postgres>
) -> Result<HostInformation, YokaiErr>{
    if check_color_str(primary_color) &&
       check_color_str(secondary_color) &&
       check_color_str(tertiary_color)
    {
        let host_info: HostInformation = HostInformation {
            hostname: hostname.to_string(), 
            primary_color: primary_color.to_string(), 
            secondary_color: secondary_color.to_string(), 
            tertiary_color: tertiary_color.to_string()
        };
        let _insert_op = match query!(
            "INSERT INTO host_info (hostname, primary_color, secondary_color, tertiary_color) VALUES ($1, $2, $3, $4)",
            host_info.hostname,
            host_info.primary_color,
            host_info.secondary_color,
            host_info.tertiary_color
        )
            .execute(pool)
            .await
        {
            Ok(_feedback) => {},
            Err(e) => return Err::<HostInformation, YokaiErr>(
                YokaiErr::new(&e.to_string())
            )
        };
        let info: HostInformation = match get_host_info(pool).await{
            Ok(info) => info,
            Err(e) => return Err::<HostInformation, YokaiErr>(
                YokaiErr::new(&e.to_string())
            )
        };
        if info.hostname ==host_info.hostname {
            Ok(info)
        }
        else {
            Err::<HostInformation, YokaiErr>(
                YokaiErr::new("Error saving host information.")
            )
        }
    }
    else {
        Err::<HostInformation, YokaiErr>(
            YokaiErr::new("One or more invalid color strings received.")
        )
    }
}

// used.
pub async fn edit_host_primary(
    new_primary: &str,
    pool: &Pool<Postgres>
) -> Result<(), YokaiErr>{
    if check_color_str(new_primary){
        let info: HostInformation = match get_host_info(pool).await{
            Ok(info) => info,
            Err(e) => return Err::<(), YokaiErr>(
                YokaiErr::new(&e.to_string())
            )
        };
        let update_op: () = match query!(
            "UPDATE host_info SET primary_color = $1 WHERE hostname = $2",
            new_primary,
            info.hostname
        )
            .execute(pool)
            .await
        {
            Ok(_f) => {},
            Err(e) => return Err::<(), YokaiErr>(
                YokaiErr::new(&e.to_string())
            )
        };
        Ok(update_op)
    }
    else {
        Err::<(), YokaiErr>(
            YokaiErr::new("Invalid color received.")
        )
    }
}

// used.
pub async fn edit_host_secondary(
    new_secondary: &str,
    pool: &Pool<Postgres>
) -> Result<(), YokaiErr>{
    if check_color_str(new_secondary){
        let info: HostInformation = match get_host_info(pool).await{
            Ok(info) => info,
            Err(e) => return Err::<(), YokaiErr>(
                YokaiErr::new(&e.to_string())
            )
        };
        let update_op: () = match query!(
            "UPDATE host_info SET secondary_color = $1 WHERE hostname = $2",
            new_secondary,
            info.hostname
        )
            .execute(pool)
            .await
        {
            Ok(_f) => {},
            Err(e) => return Err::<(), YokaiErr>(
                YokaiErr::new(&e.to_string())
            )
        };
        Ok(update_op)
    }
    else {
        Err::<(), YokaiErr>(
            YokaiErr::new("Invalid color received.")
        )
    }
}

// used.
pub async fn edit_host_tertiary(
    new_tertiary: &str,
    pool: &Pool<Postgres>
) -> Result<(), YokaiErr>{
    if check_color_str(new_tertiary){
        let info: HostInformation = match get_host_info(pool).await{
            Ok(info) => info,
            Err(e) => return Err::<(), YokaiErr>(
                YokaiErr::new(&e.to_string())
            )
        };
        let update_op: () = match query!(
            "UPDATE host_info SET tertiary_color = $1 WHERE hostname = $2",
            new_tertiary,
            info.hostname
        )
            .execute(pool)
            .await
        {
            Ok(_f) => {},
            Err(e) => return Err::<(), YokaiErr>(
                YokaiErr::new(&e.to_string())
            )
        };
        Ok(update_op)
    }
    else {
        Err::<(), YokaiErr>(
            YokaiErr::new("Invalid color received.")
        )
    }
}

// used.
pub async fn delete_account(
    user: &str,
    pool: &Pool<Postgres>
) -> Result<(), YokaiErr>{
    let user_obj: User = match get_user_by_id(
        user,
        pool
    ).await {
        Ok(user_obj) => user_obj,
        Err(e) => return Err::<(), YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    let chats: Vec<Chat> = match get_user_chats(
        &user_obj.username,
        pool
    ).await {
        Ok(chats) => chats,
        Err(e) => return Err::<(), YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    for chat in chats {
        let messages: Vec<Message> = match get_chat_messages(
            &chat.chat_id,
            pool
        ).await {
            Ok(messages) => messages,
            Err(e) => return Err::<(), YokaiErr>(
                YokaiErr::new(&e.to_string())
            )
        };
        for message in messages {
            let _del_msg: () = match delete_message(
                &message.msg_id,
                pool
            ).await {
                Ok(_f) => {},
                Err(e) => return Err::<(), YokaiErr>(
                    YokaiErr::new(&e.to_string())
                )
            };
        }
        let _del_chat: () = match delete_chat(
            &chat.chat_id,
            pool
        ).await {
            Ok(_f) => {},
            Err(e) => return Err::<(), YokaiErr>(
                YokaiErr::new(&e.to_string())
            )
        };
    }
    let user_files: Vec<UserFile> = match get_user_files(
        &user_obj.username,
        pool
    ).await {
        Ok(user_files) => user_files,
        Err(e) => return Err::<(), YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    for file in user_files {
        let _del_file: () = match delete_user_file(
            &file.file_id,
            pool
        ).await {
            Ok(_f) => {},
            Err(e) => return Err::<(), YokaiErr>(
                YokaiErr::new(&e.to_string())
            )
        };
    }
    let user_tokens: Vec<UserAPIToken> = match get_user_tokens(
        &user_obj.username,
        pool
    ).await {
        Ok(user_tokens) => user_tokens,
        Err(e) => return Err::<(), YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    for token in user_tokens {
        let _del_token: () = match delete_token(
            &token.token_id,
            pool
        ).await {
            Ok(_f) => {},
            Err(e) => return Err::<(), YokaiErr>(
                YokaiErr::new(&e.to_string())
            )
        };
    }
    let acc_del: () = match delete_user(
        &user_obj.username,
        pool
    ).await {
        Ok(_f) => {},
        Err(e) => return Err::<(), YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    Ok(acc_del)
}

// used.
pub async fn create_api_token(
    user: &str,
    password: &str,
    pool: &Pool<Postgres>
) -> Result<UserAPIToken, YokaiErr>{
    let user_obj: User = match get_user_by_id(
        user,
        pool
    ).await {
        Ok(user_obj) => user_obj,
        Err(e) => return Err::<UserAPIToken, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    let verified: bool = match verify(
        password, 
        &user_obj.password
    ){
        Ok(verified) => verified,
        Err(e) => return Err::<UserAPIToken, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    if verified {
        let token_id: String = hash_string(
            &format!(
                "{}{}{}",
                user_obj.username,
                user_obj.display_name,
                rfc2282()
            )
        );
        let token_str: String = hash_string(&token_id);
        let token: UserAPIToken = UserAPIToken{
            token_id: token_id.clone(),
            token:token_str, 
            owner: user_obj.username
        };
        let _insert_op = match query!(
            "INSERT INTO user_api_tokens (token_id, token, owner) VALUES ($1, $2, $3)",
            token.token_id,
            token.token,
            token.owner
        )
            .execute(pool)
            .await
        {
            Ok(_feedback) => {},
            Err(e) => return Err::<UserAPIToken, YokaiErr>(
                YokaiErr::new(&e.to_string())
            )
        };
        let fetched: UserAPIToken = match get_token_by_id(
            &token.token_id,
            pool
        ).await {
            Ok(fetched) => fetched,
            Err(e) => return Err::<UserAPIToken, YokaiErr>(
                YokaiErr::new(&e.to_string())
            )
        };
        Ok(fetched)
    }
    else {
        Err::<UserAPIToken, YokaiErr>(
            YokaiErr::new("Password could not be verified.")
        )
    }
}

// used.
pub async fn get_token_by_id(
    token_id: &str,
    pool: &Pool<Postgres>
) -> Result<UserAPIToken, YokaiErr>{
    let object: UserAPIToken = match query_as!(
        UserAPIToken,
        "SELECT * FROM user_api_tokens WHERE token_id = $1",
        token_id
    )
        .fetch_one(pool)
        .await 
    {
        Ok(object) => object,
        Err(e) => return Err::<UserAPIToken, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    Ok(object)
}

// used.
pub async fn get_token_by_token(
    token: &str,
    pool: &Pool<Postgres>
) -> Result<UserAPIToken, YokaiErr>{
    let object: UserAPIToken = match query_as!(
        UserAPIToken,
        "SELECT * FROM user_api_tokens WHERE token = $1",
        token
    )
        .fetch_one(pool)
        .await 
    {
        Ok(object) => object,
        Err(e) => return Err::<UserAPIToken, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    Ok(object)
}

// used.
pub async fn get_user_by_token(
    token: &str,
    pool: &Pool<Postgres>
) -> Result<User, YokaiErr>{
    let fetched: UserAPIToken = match get_token_by_token(
        &token,
        pool
    ).await {
        Ok(fetched) => fetched,
        Err(e) => return Err::<User, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    let user_obj: User = match get_user_by_id(
        &fetched.owner,
        pool
    ).await {
        Ok(user_obj) => user_obj,
        Err(e) => return Err::<User, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    Ok(user_obj)
}

// used.
pub async fn delete_token(
    token: &str,
    pool: &Pool<Postgres>
) -> Result<(), YokaiErr>{
    let token_obj: UserAPIToken = match get_token_by_token(
        token,
        pool
    ).await {
        Ok(token_obj) => token_obj,
        Err(e) => return Err::<(), YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    let del_op: () = match query!(
        "DELETE FROM user_api_tokens WHERE token_id = $1",
        token_obj.token_id
    )
        .execute(pool)
        .await 
    {
        Ok(_f) => {},
        Err(e) => return Err::<(), YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    Ok(del_op)
}

pub async fn get_user_chats(
    user: &str,
    pool: &Pool<Postgres>
) -> Result<Vec<Chat>, YokaiErr>{
    let user_obj: User = match get_user_by_id(
        &user,
        pool
    ).await {
        Ok(user_obj) => user_obj,
        Err(e) => return Err::<Vec<Chat>, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    let mut chats_s: Vec<Chat> = match query_as!(
        Chat,
        "SELECT * FROM chats WHERE sender = $1",
        &user_obj.username
    )
        .fetch_all(pool)
        .await 
    {
        Ok(chats_s) => chats_s,
        Err(e) => return Err::<Vec<Chat>, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    let mut chats_r: Vec<Chat> = match query_as!(
        Chat,
        "SELECT * FROM chats WHERE receiver = $1",
        &user_obj.username
    )
        .fetch_all(pool)
        .await 
    {
        Ok(chats_r) => chats_r,
        Err(e) => return Err::<Vec<Chat>, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    chats_s.append(&mut chats_r);
    Ok(chats_s)
}

// used.
pub async fn get_user_contacts(
    user: &str,
    pool: &Pool<Postgres>
) -> Result<Vec<User>, YokaiErr>{
    let mut user_contacts: Vec<User> = Vec::new();
    let user_chats: Vec<Chat> = match get_user_chats(
        user,
        pool
    ).await {
        Ok(user_chats) => user_chats,
        Err(e) => return Err::<Vec<User>, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    for chat in user_chats{
        if chat.sender == user{
            let contact: User = match get_user_by_id(
                &chat.receiver,
                pool
            ).await {
                Ok(user_obj) => user_obj,
                Err(e) => return Err::<Vec<User>, YokaiErr>(
                    YokaiErr::new(&e.to_string())
                )
            };
            user_contacts.push(contact);
        }
        else {
            let contact: User = match get_user_by_id(
                &chat.sender,
                pool
            ).await {
                Ok(user_obj) => user_obj,
                Err(e) => return Err::<Vec<User>, YokaiErr>(
                    YokaiErr::new(&e.to_string())
                )
            };
            user_contacts.push(contact);
        }
    }
    Ok(user_contacts)
}

pub async fn get_user_files(
    user: &str,
    pool: &Pool<Postgres>
) -> Result<Vec<UserFile>, YokaiErr>{
    let obj: User = match get_user_by_id(
        &user,
        pool
    ).await {
        Ok(user_obj) => user_obj,
        Err(e) => return Err::<Vec<UserFile>, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    let files: Vec<UserFile> = match query_as!(
        UserFile,
        "SELECT * FROM user_files WHERE file_owner = $1",
        obj.username
    )
        .fetch_all(pool)
        .await 
    {
        Ok(files) => files,
        Err(e) => return Err::<Vec<UserFile>, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    Ok(files)    
}

pub async fn get_chat_messages(
    chat_id: &str,
    pool: &Pool<Postgres>
) -> Result<Vec<Message>, YokaiErr>{
    let chat: Chat = match get_chat_by_id(
        chat_id,
        pool
    ).await {
        Ok(chat) => chat,
        Err(e) => return Err::<Vec<Message>, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    let msgs: Vec<Message> = match query_as!(
        Message,
        "SELECT * FROM messages WHERE chat_id = $1",
        chat.chat_id
    )
        .fetch_all(pool)
        .await 
    {
        Ok(msgs) => msgs,
        Err(e) => return Err::<Vec<Message>, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    Ok(msgs)
}

pub async fn get_user_tokens(
    user: &str,
    pool: &Pool<Postgres>
) -> Result<Vec<UserAPIToken>, YokaiErr>{
    let obj: User = match get_user_by_id(
        &user,
        pool
    ).await {
        Ok(user_obj) => user_obj,
        Err(e) => return Err::<Vec<UserAPIToken>, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    let tokens: Vec<UserAPIToken> = match query_as!(
        UserAPIToken,
        "SELECT * FROM user_api_tokens WHERE owner = $1",
        obj.username
    )
        .fetch_all(pool)
        .await 
    {
        Ok(files) => files,
        Err(e) => return Err::<Vec<UserAPIToken>, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    Ok(tokens)    
}

pub async fn user_exists(
    user: &str,
    pool: &Pool<Postgres>
) -> bool {
    get_user_by_id(
        user,
        pool
    ).await.is_ok()
}

pub async fn file_on_file(
    file_id: &str,
    pool: &Pool<Postgres>
) -> bool {
    get_file_by_id(
        file_id,
        pool
    ).await.is_ok()
}
