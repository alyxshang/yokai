/*
Yokai by Alyx Shang.
Licensed under the FSL v1.
*/

#![deny(clippy::all)]
#![allow(clippy::ptr_arg)]
#![allow(clippy::borrowed_box)]
#![allow(clippy::if_same_then_else)]
#![allow(clippy::redundant_field_names)]

/// Declaring the "modules"
/// directory as a module.
pub mod modules;

/// Re-exporting the module
/// containing the structure
/// to catch and handle errors.
pub use modules::err::*;

/// Re-exporting the module
/// containing Yokai's
/// lexer.
pub use modules::lexer::*;

/// Re-exporting the module
/// containing the parser
/// structure for Yokai
/// source code.
pub use modules::parser::*;

/// Re-exporting the module
/// containing the function
/// to split Yokai source code
/// into either `Code` or `Text`
/// snippets.
pub use modules::splitter::*;

/// Re-exporting the module
/// containing the Serializer
/// that reads a Rust data 
/// structure and inserts  and 
/// evaluates template expressions.
pub use modules::renderer::*;
