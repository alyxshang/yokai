/*
Yokai by Alyx Shang.
Licensed under the FSL v1.
*/

/// Importing the main
/// function to run the 
/// backend of Yokai.
use yokai_backend::run_app;

/// The main point of
/// entry for the Rust
/// compiler.
#[actix_web::main]
async fn main(){
    match run_app().await {
        Ok(_f) => {},
        Err(e) => println!("{}", &e.to_string())
    };
}
