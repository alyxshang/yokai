/*
Yokai by Alyx Shang.
Licensed under the FSL v1.
*/

/// Importing the structure
/// to catch and handle errors.
use super::err::YokaiErr;

/// Importing the structure
/// to encapsulate data about
/// captured snippets of Yokai
/// source code.
use super::splitter::Snippet;

/// Importing the enumeration
/// that lists all possible types
/// of snippets that can be in a 
/// string of Yokai source code.
use super::splitter::SnippetType;

/// An enumeration
/// that lists all
/// possible token
/// types that can
/// exist in Yokai
/// source code.
#[derive(PartialEq, Clone)]
pub enum TokenType {
    Dot,
    True,
    Space,
    False,
    IsEqual,
    OpenSig,
    NotEqual,
    CloseSig,
    InKeyword,
    IfKeyword,
    UserIdent,
    UserString,
    ForKeyword,
    TextSnippet,
    ElseKeyword,
    EndIfKeyword,
    EndForKeyword,
    IncludeKeyword
}

/// A structure to encapsulate
/// data about a captured token.
#[derive(Clone)]
pub struct Token {
    pub value: Option<String>,
    pub token_type: TokenType
}

/// A function to tokenize
/// a snippet containing Yokai
/// templating expressions. If
/// the operation is successful,
/// a vector containing instances
/// of  the `Token` structure is
/// returned. If the string is empty
/// or an unexpected token is
/// encountered, an error is returned.
pub fn tokenize(
    snippets: &Vec<Snippet>
) -> Result<Vec<Token>, YokaiErr>{
    let mut result: Vec<Token> = Vec::new();
    for snippet in snippets {
        match snippet.snippet_type {
            SnippetType::Code => {
                let tokenized: Vec<Token> = tokenize_code_snippet(&snippet)?;
                result.extend(tokenized);
            },
            SnippetType::Text => result.push(
                Token{
                    value: Some(snippet.contents.clone()),
                    token_type: TokenType::TextSnippet
                }
            )
        };
    }
    Ok(result)
}

/// A function to tokenize a snippet of
/// text containing templating code. If
/// the operation is successful, a vector
/// containing instances of the `Token`
/// structure. If an unexpected end of
/// the character stream is encountered,
/// an error is returned.
pub fn tokenize_code_snippet(
    snippet: &Snippet
) -> Result<Vec<Token>, YokaiErr>{
    let mut cursor: usize = 0;
    let mut result: Vec<Token> = Vec::new();
    let subject: Vec<char> = snippet
        .contents
        .clone()
        .to_string()
        .chars()
        .into_iter()
        .collect::<Vec<char>>();
    let subject_length: usize = subject.len();
    while cursor < subject_length {
        if subject.get(cursor) == Some(&'.') {
            result.push(Token{ value: None, token_type: TokenType::Dot });
            cursor = cursor + 1;
        }
        else if subject.get(cursor) == Some(&' ') {
            result.push(Token{ value: None, token_type: TokenType::Space });
            cursor = cursor + 1;
        }
        else if subject.get(cursor) == Some(&'{') &&
           subject.get(cursor + 1) == Some(&'%')
        {
            result.push(Token{ value: None, token_type: TokenType::OpenSig });
            cursor = cursor + 2;
        }
        else if subject.get(cursor) == Some(&'%') &&
           subject.get(cursor + 1) == Some(&'}')
        {
            result.push(Token{ value: None, token_type: TokenType::CloseSig });
            cursor = cursor + 2;
        }
        else if subject.get(cursor) == Some(&'i') &&
           subject.get(cursor + 1) == Some(&'f')
        {
            result.push(Token{ value: None, token_type: TokenType::IfKeyword });
            cursor = cursor + 2;
        }
        else if subject.get(cursor) == Some(&'i') &&
           subject.get(cursor + 1) == Some(&'n')
        {
            result.push(Token{ value: None, token_type: TokenType::InKeyword });
            cursor = cursor + 2;
        }
        else if subject.get(cursor) == Some(&'!') &&
           subject.get(cursor + 1) == Some(&'=')
        {
            result.push(Token{ value: None, token_type: TokenType::NotEqual });
            cursor = cursor + 2;
        }
        else if subject.get(cursor) == Some(&'=') &&
           subject.get(cursor + 1) == Some(&'=')
        {
            result.push(Token{ value: None, token_type: TokenType::IsEqual });
            cursor = cursor + 2;
        }
        else if subject.get(cursor) == Some(&'e') &&
           subject.get(cursor + 1) == Some(&'l') &&
           subject.get(cursor + 2) == Some(&'s') &&
           subject.get(cursor + 3) == Some(&'e')
        {
            result.push(Token{ value: None, token_type: TokenType::ElseKeyword });
            cursor = cursor + 4;
        }
        else if subject.get(cursor) == Some(&'f') &&
           subject.get(cursor + 1) == Some(&'o') &&
           subject.get(cursor + 2) == Some(&'r')
        {
            result.push(Token{ value: None, token_type: TokenType::ForKeyword });
            cursor = cursor + 3;
        }
        else if subject.get(cursor) == Some(&'e') &&
           subject.get(cursor + 1) == Some(&'n') &&
           subject.get(cursor + 2) == Some(&'d') &&
           subject.get(cursor + 3) == Some(&'i') &&
           subject.get(cursor + 4) == Some(&'f')
        {
            result.push(Token{ value: None, token_type: TokenType::EndIfKeyword });
            cursor = cursor + 5;
        }
        else if subject.get(cursor) == Some(&'e') &&
           subject.get(cursor + 1) == Some(&'n') &&
           subject.get(cursor + 2) == Some(&'d') &&
           subject.get(cursor + 3) == Some(&'f') &&
           subject.get(cursor + 4) == Some(&'o') &&
           subject.get(cursor + 5) == Some(&'r')
        {
            result.push(Token{ value: None, token_type: TokenType::EndForKeyword });
            cursor = cursor + 6;
        }
        else if subject.get(cursor) == Some(&'i') &&
           subject.get(cursor + 1) == Some(&'n') &&
           subject.get(cursor + 2) == Some(&'c') &&
           subject.get(cursor + 3) == Some(&'l') &&
           subject.get(cursor + 4) == Some(&'u') &&
           subject.get(cursor + 5) == Some(&'d') &&
           subject.get(cursor + 6) == Some(&'e')
        {
            result.push(Token{ value: None, token_type: TokenType::IncludeKeyword });
            cursor = cursor + 7;
        }
        else if subject.get(cursor) == Some(&'"'){
            let mut buffer: Vec<char> = Vec::new();
            while subject.get(cursor) != Some(&'"'){
                let character: char = match subject.get(cursor){
                    Some(character) => *character,
                    None => return Err::<Vec<Token>, YokaiErr>(
                        YokaiErr::new("Unexpected character.")
                    )
                };
                buffer.push(character);
                cursor = cursor + 1;
            }
            cursor = cursor + 1;
            let token: Token = Token{
                value: Some(buffer.into_iter().collect::<String>()),
                token_type: TokenType::UserString
            };
            result.push(token);

        }
        else if is_ident_char(&subject.get(cursor))?{
            let mut buffer: Vec<char> = Vec::new();
            while is_ident_char(&subject.get(cursor))?{
                let character: char = match subject.get(cursor){
                    Some(character) => *character,
                    None => return Err::<Vec<Token>, YokaiErr>(
                        YokaiErr::new("Unexpected character.")
                    )
                };
                buffer.push(character);
                cursor = cursor + 1;
            }
            cursor = cursor + 1;
            let token: Token = Token{
                value: Some(buffer.into_iter().collect::<String>()),
                token_type: TokenType::UserIdent
            };
            result.push(token);
        }
        else {
            return Err::<Vec<Token>, YokaiErr>(
                YokaiErr::new("Unexpected character.")
            );
        }

    }
    Ok(result)
}

/// A function to check whether a supplied
/// character is part of an identifier or
/// not. If it is, a boolean `true` is returned.
/// If it is not, a boolean `false` is returned.
/// If the supplied `Option<char>` is empty, an
/// error is returned.
pub fn is_ident_char(
    sub: &Option<&char>
) -> Result<bool, YokaiErr>{
    let alphabet: Vec<char> = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_"
        .to_string()
        .chars()
        .into_iter()
        .collect::<Vec<char>>();
    let character: &char = match sub{
        Some(character) => character,
        None => return Err::<bool, YokaiErr>(
            YokaiErr::new("Could not retrieve character.")
        )
    };
    for letter in alphabet {
        if &letter == character {
            return Ok(true);
        }
    }
    return Ok(false);
}
