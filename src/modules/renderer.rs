/*
Yokai by Alyx Shang.
Licensed under the FSL v1.
*/

/// Importing the trait
/// to serialize a Rust
/// data structure's data
/// into a Yokai template
/// string.
use serde::Serialize;

/// Importing the structure
/// to catch and handle errors.
use super::err::YokaiErr;

/// Importing the enumeration that
/// "lists" all possible block-level
/// statements in Yokai source code.
use super::parser::BlockStatement;

/// A structure that renders
/// a Yokai template string into
/// a string filled with values
/// from the supplied data structure
/// containing data.
pub struct Renderer<T>{
    pub context: T,
    pub cursor: usize, 
    pub tree: Vec<BlockStatement>
}

/// Implementing functions for
/// the `Renderer` structure.
impl<T: Serialize> Renderer<T>{

    /// A function to create a new
    /// instance of the `Renderer`
    /// given a type parameter and
    /// return this new instance.
    pub fn new(
        context: T,
        tree: &Vec<BlockStatement>
    ) -> Renderer<T> {
        Renderer{
            cursor: 0,
            context: context,
            tree: tree.to_vec(),
        }
    } 
}
