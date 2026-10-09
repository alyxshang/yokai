/*
Yokai by Alyx Shang.
Licensed under the FSL v1.
*/

/// Exporting the module
/// containing the structure
/// to catch and handle errors.
pub mod err;

/// Exporting the module
/// containing Yokai's
/// lexer.
pub mod lexer;

/// Exporting the module
/// containing the parser
/// structure for Yokai
/// source code.
pub mod parser;

/// Exporting the module
/// containing the function
/// to split Yokai source code
/// into either `Code` or `Text`
/// snippets.
pub mod splitter;

/// Exporting the module
/// containing the Serializer
/// that reads a Rust data 
/// structure and inserts  and 
/// evaluates template expressions.
pub mod renderer;
