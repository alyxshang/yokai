/*
Yokai by Alyx Shang.
Licensed under the FSL v1.
*/

use actix_web::error;
use serde::Serialize;
use std::fmt::Result;
use std::fmt::Display;
use std::error::Error;
use std::fmt::Formatter;
use actix_web::HttpResponse;

#[derive(Serialize)]
pub struct ErrDetails {
    pub details: String
}

#[derive(Clone,Eq,PartialEq, Debug)]
pub struct YokaiErr{
    pub details: String
}

impl YokaiErr{

    pub fn new(details: &str) -> YokaiErr {
        YokaiErr{
            details: details.to_owned()
        }
    }

    pub fn to_string(self) -> String {
        self.details.to_string()
    }
}

impl Error for YokaiErr {
    fn description(&self) -> &str {
        &self.details
    }
}

impl Display for YokaiErr{
    fn fmt(
        &self, 
        f: &mut Formatter
    ) -> Result {
        write!(f,"{}",self.details)
    }
}

impl error::ResponseError for YokaiErr {
    fn error_response(&self) -> HttpResponse {
        let resp: ErrDetails = ErrDetails{ 
            details: (*((&self.details).clone())).to_string()
        };
        HttpResponse::Ok().json(resp)
    }
}
