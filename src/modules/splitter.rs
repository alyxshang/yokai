/*
Yokai by Alyx Shang.
Licensed under the FSL v1.
*/

/// Importing the structure
/// to catch and handle errors.
use super::err::YokaiErr;

/// An enumeration to "list"
/// all possible types of snippets
/// in Yokai code.
pub enum SnippetType {
    Code,
    Text
}

/// A structure to encapsulate
/// data about a captured snippet
/// of Yokai code.
pub struct Snippet {
    pub contents: String,
    pub snippet_type: SnippetType
}

/// A function to split Yokai code
/// into a series of snippets, which
/// are returned as a vector of instances
/// of the `Snippet` structure. If the stream
/// of text ends unexpectedly, an error is 
/// returned.
pub fn split_source(
    sub: &str
) -> Result<Vec<Snippet>, YokaiErr> {
    let mut cursor: usize = 0;
    let subject: Vec<char> = sub
        .to_string()
        .chars()
        .into_iter()
        .collect::<Vec<char>>();
    let mut result: Vec<Snippet> = Vec::new();
    while cursor < subject.len() {
        if subject.get(cursor) == Some(&'{') &&
           subject.get(cursor + 1) == Some(&'%')
        {
            let mut char_buf: Vec<char> = Vec::new();
            while subject.get(cursor) != Some(&'%') &&
                  subject.get(cursor + 1) == Some(&'}') 
            {
                let character: char = match subject.get(cursor){
                    Some(character) => *character,
                    None => return Err::<Vec<Snippet>, YokaiErr>(
                        YokaiErr::new("Unexpected end of template string.")
                    )
                };
                char_buf.push(character);
                cursor = cursor + 1;
            }
            let joined: String = char_buf
                .iter()
                .collect::<String>();
            let snippet: Snippet = Snippet{
                contents: joined,
                snippet_type: SnippetType::Code
            };
            result.push(snippet);
        }
        else {
             let mut char_buf: Vec<char> = Vec::new();
            while subject.get(cursor) != Some(&'{') &&
                  subject.get(cursor + 1) == Some(&'%') 
            {
                let character: char = match subject.get(cursor){
                    Some(character) => *character,
                    None => return Err::<Vec<Snippet>, YokaiErr>(
                        YokaiErr::new("Unexpected end of template string.")
                    )
                };
                char_buf.push(character);
                cursor = cursor + 1;
            }
            let joined: String = char_buf
                .iter()
                .collect::<String>();
            let snippet: Snippet = Snippet{
                contents: joined,
                snippet_type: SnippetType::Text
            };
            result.push(snippet);
        }
    }
    Ok(result)
}
