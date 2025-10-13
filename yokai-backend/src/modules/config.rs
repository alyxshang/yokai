/*
Yokai by Alyx Shang.
Licensed under the FSL v1.
*/

use std::env::var;
use super::err::YokaiErr;
use super::units::Config;
use super::utils::check_username;
use super::utils::check_password;
use super::utils::check_color_str;

pub fn get_config() -> Result<Config, YokaiErr>{
    let db_url: String = match var("YOKAI_DB_URL"){
        Ok(db_url) => db_url,
        Err(e) => return Err::<Config, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    let hostname: String = match var("YOKAI_HOSTNAME"){
        Ok(hostname) => hostname,
        Err(e) => return Err::<Config, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    let app_port: String = match var("YOKAI_APP_PORT"){
        Ok(app_port) => app_port,
        Err(e) => return Err::<Config, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    let app_host: String = match var("YOKAI_APP_HOST"){
        Ok(app_port) => app_port,
        Err(e) => return Err::<Config, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    let primary_color: String = match var("YOKAI_INST_PRIMARY"){
        Ok(primary_color) => primary_color,
        Err(e) => return Err::<Config, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    let secondary_color: String = match var("YOKAI_INST_SECONDARY"){
        Ok(secondary_color) => secondary_color,
        Err(e) => return Err::<Config, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    let tertiary_color: String = match var("YOKAI_INST_TERTIARY"){
        Ok(secondary_color) => secondary_color,
        Err(e) => return Err::<Config, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    let admin_username: String = match var("YOKAI_ADMIN_USERNAME"){
        Ok(admin_username) => admin_username,
        Err(e) => return Err::<Config, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    let admin_password: String = match var("YOKAI_ADMIN_PASSWORD"){
        Ok(admin_password) => admin_password,
        Err(e) => return Err::<Config, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    let admin_description: String = match var("YOKAI_ADMIN_DESCRIPTION"){
        Ok(admin_description) => admin_description,
        Err(e) => return Err::<Config, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    let admin_display_name: String = match var("YOKAI_ADMIN_DISPLAY_NAME"){
        Ok(admin_display_name) => admin_display_name,
        Err(e) => return Err::<Config, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    let admin_primary_color: String = match var("YOKAI_ADMIN_PRIMARY_COLOR"){
        Ok(admin_primary_color) => admin_primary_color,
        Err(e) => return Err::<Config, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    let admin_secondary_color: String = match var("YOKAI_ADMIN_SECONDARY_COLOR"){
        Ok(admin_secondary_color) => admin_secondary_color,
        Err(e) => return Err::<Config, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    let admin_tertiary_color: String = match var("YOKAI_ADMIN_TERTIARY_COLOR"){
        Ok(admin_tertiary_color) => admin_tertiary_color,
        Err(e) => return Err::<Config, YokaiErr>(
            YokaiErr::new(&e.to_string())
        )
    };
    if check_username(&admin_username) &&
       check_password(&admin_password) &&
       check_color_str(&primary_color) &&
       check_color_str(&secondary_color) &&
       check_color_str(&tertiary_color) &&
       check_color_str(&admin_primary_color) &&
       check_color_str(&admin_secondary_color) &&
       check_color_str(&admin_tertiary_color)
    {
        let config_vars: Config = Config {
            db_url: db_url,
            hostname: hostname,
            app_host: app_host,
            app_port: app_port,
            primary_color: primary_color,
            secondary_color: secondary_color,
            tertiary_color: tertiary_color,
            admin_username: admin_username,
            admin_password: admin_password,
            admin_description: admin_description,
            admin_display_name: admin_display_name,
            admin_primary_color: admin_primary_color,
            admin_secondary_color: admin_secondary_color,
            admin_tertiary_color: admin_tertiary_color
        };
        Ok(config_vars)
    }
    else {
        Err::<Config, YokaiErr>(
            YokaiErr::new(
                "Some colors or the administrator password or username have invalid values."
            )
        )
    }

}
