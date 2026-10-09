/*
Yokai by Alyx Shang.
Licensed under the FSL v1.
*/

/// Importing the "Result"
/// type because it is needed
/// by the "Display" trait.
use std::fmt::Result;

/// Importing the "Display"
/// trait to implement for
/// the error structure.
use std::fmt::Display;

/// Importing the "Error"
/// trait to implement it
/// for the error structure.
use std::error::Error;

/// Importing the "Formatter"
/// entity because it is needed
/// by the "Display" trait.
use std::fmt::Formatter;

/// A data structure to
/// store information about
/// errors.
#[derive(Clone,Eq,PartialEq, Debug)]
pub struct YokaiErr {
    pub details: String
}

/// Implementing
/// function(s) for
/// the `YokaiErr`
/// structure.
impl YokaiErr {

    /// A function to create
    /// and return a new
    /// instance of the `YokaiErr`
    /// structure.
    pub fn new(
        details: &str
    ) -> YokaiErr {
        YokaiErr {
            details: details.to_owned()
        }
    }

}

/// Implementing the `Error`
/// trait for the `YokaiErr`
/// structure.
impl Error for YokaiErr {

    /// The function that
    /// implements the `Error`
    /// trait for the `YokaiErr`
    /// structure.
    fn description(
        &self
    ) -> &str {
        &self.details
    }
}

/// Implementing the `Display`
/// trait for the `YokaiErr`
/// structure.
impl Display for YokaiErr {

    /// The function that
    /// implements the `Display`
    /// trait for the `YokaiErr`
    /// structure.
    fn fmt(
        &self, 
        f: &mut Formatter
    ) -> Result {
        write!(f,"{}",self.details)
    }
}