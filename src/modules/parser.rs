/*
Yokai by Alyx Shang.
Licensed under the FSL v1.
*/

/// Importing the structure
/// that encapsulates data
/// about a captured token.
use super::lexer::Token;

/// Importing the structure
/// to catch and handle errors.
use super::err::YokaiErr;

/// Importing the enumeration
/// that lists all possible types
/// of tokens in Yokai source code.
use super::lexer::TokenType;

/// An enumeration to "list"
/// all possible binary 
/// operators in Yokai source
/// code.
#[derive(Clone)]
pub enum Operator {
    IsEqual,
    NotEqual
}

/// A structure to encapsulate
/// data about a parsed binary
/// operation.
#[derive(Clone)]
pub struct BinaryOperation{
    pub operator: Operator,
    pub left: Box<Expression>,
    pub right: Box<Expression>,
}

/// A structure to encapsulate
/// data about a loop block, including
/// expressions to render and the
/// iterable to loop over.
#[derive(Clone)]
pub struct LoopBlock{
    pub closure_var: String,
    pub iterable: Expression,
    pub render_expressions: Box<Vec<BlockStatement>>
}

/// A structure to encapsulate
/// data about conditional block.
#[derive(Clone)]
pub struct ConditionalBlock{
    pub condition: Expression,
    pub if_blocks: Box<Vec<BlockStatement>>,
    pub else_blocks: Box<Vec<BlockStatement>>,

}

/// An enumeration that
/// lists all possible block-level
/// statements in Yokai source
/// code.
#[derive(Clone)]
pub enum BlockStatement {
    Import(String),
    TextSnippet(String),
    LoopBlock(LoopBlock), 
    Expression(Expression),
    ConditionalBlock(ConditionalBlock), 
}

/// An enumeration that lists
/// all possible expression-level
/// stataments in Yokai source code.
#[derive(Clone)]
pub enum Expression {
    Boolean(bool),
    VariableAccess(Vec<String>),
    BinaryOperation(BinaryOperation) 
}

/// A structure holding all
/// neccessary information
/// for parsing a stream of
/// tokens obtained from Yokai
/// source code.
pub struct Parser{
    pub cursor: usize,
    pub stream: Vec<Token>
}

/// Implementing all functions
/// needed by Yokai's parser.
impl Parser {

    pub fn new(
        stream: Vec<Token>
    ) -> Parser {
        Parser {
            cursor: 0,
            stream: stream
        }
    }

    pub fn advance(
        &mut self,
    ) {
        self.cursor = self.cursor + 1;
    }

    pub fn is_done(
        &self
    ) -> bool {
        self.cursor == self.stream.len()
    }

    pub fn peek_n(
        &self,
        n: usize
    ) -> Result<Token, YokaiErr> {
        let new_cursor: usize = self.cursor + n;
        if new_cursor <= self.cursor {
            let token: Token = match self.stream.get(self.cursor){
                Some(token) => token.clone(),
                None => return Err::<Token, YokaiErr>(
                    YokaiErr::new("Unexpected end of token stream:")
                )
            };
            Ok(token)
        }
        else {
            Err::<Token, YokaiErr>(
                YokaiErr::new("Unexpected end of token stream.")
            )
        }
    }

    pub fn expect(
        &mut self,
        expected: &TokenType
    ) -> Result<Token, YokaiErr> {
        if self.cursor <= self.stream.len() {
            let token: Token = match self.stream.get(self.cursor){
                Some(token) => token.clone(),
                None => return Err::<Token, YokaiErr>(
                    YokaiErr::new("Unexpected end of token stream:")
                )
            };
            if &token.token_type == expected {
                self.advance();
                Ok(token)
            }
            else {
                Err::<Token, YokaiErr>(
                    YokaiErr::new("Unexpected token.")
                )
            }
        }
        else {
            Err::<Token, YokaiErr>(
                YokaiErr::new("Unexpected end of token stream.")
            )
        }
    }

    pub fn parse(
        &mut self
    ) -> Result<Vec<BlockStatement>, YokaiErr>{
        let mut blocks: Vec<BlockStatement> = Vec::new();
        while !self.is_done(){
            blocks.push(self.parse_block()?);
        }
        Ok(blocks)
    }

    pub fn parse_block(
        &mut self,
    ) -> Result<BlockStatement, YokaiErr> {
        let peeked: Token = self.peek_n(0)?;
        match peeked.token_type {
            TokenType::OpenSig => Ok(
                self.parse_template_expr()?
            ),
            TokenType::TextSnippet => Ok(
                self.parse_text_snippet()?
            ),
            _ => Err::<BlockStatement, YokaiErr>(
                YokaiErr::new("Unexpected token.")
            )
        }
    }

    pub fn parse_text_snippet(
        &mut self
    ) -> Result<BlockStatement, YokaiErr>{
        let snippet: Token = self.expect(&TokenType::TextSnippet)?;
        let text: String = match snippet.value {
            Some(text) => text.clone(),
            None => return Err::<BlockStatement, YokaiErr>(
                YokaiErr::new("Expected text snippet.")
            )
        };
        Ok(BlockStatement::TextSnippet(text))
    }

    pub fn parse_template_expr(
        &mut self
    ) -> Result<BlockStatement, YokaiErr>{
        if self.peek_n(0)?.token_type == TokenType::OpenSig &&
           self.peek_n(1)?.token_type == TokenType::Space
        {
            let peeked: Token = self.peek_n(2)?;
            match peeked.token_type {
                TokenType::IncludeKeyword => Ok(self.parse_import()?),
                TokenType::IfKeyword => Ok(self.parse_conditional()?),
                TokenType::ForKeyword => Ok(self.parse_loop_block()?),
                _ => Ok(
                    BlockStatement::Expression(self.parse_expression()?)
                )
            }
        }
        else {
            Err::<BlockStatement, YokaiErr>(
                YokaiErr::new("Unexpected token.")
            )
        }
    }

    pub fn parse_import(
        &mut self
    ) -> Result<BlockStatement, YokaiErr>{
        let _open_sig: Token = self.expect(&TokenType::OpenSig)?;
        let _space_o: Token = self.expect(&TokenType::Space)?;
        let _include_kw: Token = self.expect(&TokenType::IncludeKeyword)?;
        let imp_path_token: Token = self.expect(&TokenType::UserString)?;
        let _space_c: Token = self.expect(&TokenType::Space)?;
        let _close_sig: Token = self.expect(&TokenType::CloseSig)?;
        let imp_path: String = match imp_path_token.value {
            Some(imp_path) => imp_path,
            None => return Err::<BlockStatement, YokaiErr>(
                YokaiErr::new("Expected an import path.")
            )
        };
        Ok(BlockStatement::Import(imp_path))
    }

    pub fn parse_conditional(
        &mut self
    ) -> Result<BlockStatement, YokaiErr>{
        let _open_sig: Token = self.expect(&TokenType::OpenSig)?;
        let _space_o: Token = self.expect(&TokenType::Space)?;
        let _if_kw: Token = self.expect(&TokenType::IfKeyword)?;
        let if_condition: Expression = self.parse_expression()?;
        let _space_c: Token = self.expect(&TokenType::Space)?;
        let _close_sig: Token = self.expect(&TokenType::CloseSig)?;
        let mut if_blocks: Vec<BlockStatement> = Vec::new();
        while self.peek_n(0)?.token_type != TokenType::ElseKeyword {
            if_blocks.push(self.parse_block()?);
        }
        let _else_kw: Token = self.expect(&TokenType::ElseKeyword)?;
        let mut else_blocks: Vec<BlockStatement> = Vec::new();
        while self.peek_n(0)?.token_type != TokenType::EndIfKeyword {
            else_blocks.push(self.parse_block()?);
        }
        let _else_kw: Token = self.expect(&TokenType::EndIfKeyword)?;
        let conditional: ConditionalBlock = ConditionalBlock {
            condition: if_condition,
            if_blocks: Box::new(if_blocks),
            else_blocks: Box::new(else_blocks)
        };
        Ok(BlockStatement::ConditionalBlock(conditional))
    }

    pub fn parse_loop_block(
        &mut self
    ) -> Result<BlockStatement, YokaiErr>{
        let _open_sig: Token = self.expect(&TokenType::OpenSig)?;
        let _space_o: Token = self.expect(&TokenType::Space)?;
        let _for_kw: Token = self.expect(&TokenType::ForKeyword)?;
        let temp_var_token: Token = self.expect(&TokenType::UserIdent)?;
        let _in_token: Token = self.expect(&TokenType::InKeyword)?;
        let iterable: Expression = self.parse_expression()?;
        let _space_c: Token = self.expect(&TokenType::Space)?;
        let _close_sig: Token = self.expect(&TokenType::CloseSig)?;
        let mut for_blocks: Vec<BlockStatement> = Vec::new();
        while self.peek_n(0)?.token_type != TokenType::EndForKeyword {
            for_blocks.push(self.parse_block()?);
        }
        let _endfor_kw: Token = self.expect(&TokenType::EndForKeyword)?;
        let temp_var: String = match temp_var_token.value {
            Some(temp_var) => temp_var,
            None => return Err::<BlockStatement, YokaiErr>(
                YokaiErr::new("No temporary variable received.")
            )
        };
        let loop_block: LoopBlock = LoopBlock {
            closure_var: temp_var,
            iterable: iterable,
            render_expressions: Box::new(for_blocks)
        };
        Ok(BlockStatement::LoopBlock(loop_block))
    }

    pub fn parse_expression(
        &mut self
    ) -> Result<Expression, YokaiErr> {
        let left: Expression = self.parse_atom()?;
        let operator: Option<Operator> = match self.peek_n(0)?.token_type{
            TokenType::IsEqual => Some(Operator::IsEqual),
            TokenType::NotEqual => Some(Operator::NotEqual),
            _ => None
        };
        if let Some(op) = operator {
            self.advance();
            let right: Expression = self.parse_atom()?; 
            let bin_op: BinaryOperation = BinaryOperation{
                operator: op,
                left: Box::new(left),
                right: Box::new(right)
            };
            Ok(Expression::BinaryOperation(bin_op))
        }
        else {
            Ok(left)
        }
    }

    pub fn parse_atom(
        &mut self
    ) -> Result<Expression, YokaiErr>{
        let peeked: Token = self.peek_n(0)?;
        match peeked.token_type {
            TokenType::True => Ok(self.parse_boolean_true()?),
            TokenType::False => Ok(self.parse_boolean_false()?),
            TokenType::UserIdent => Ok(self.parse_var_access()?),
            _ => Err::<Expression, YokaiErr>(
                YokaiErr::new("Unexpected token.")
            )
        }
    }

    pub fn parse_boolean_true(
        &mut self
    ) -> Result<Expression, YokaiErr>{
        let _true_token: Token = self.expect(&TokenType::True)?;
        Ok(Expression::Boolean(true))
    }

    pub fn parse_boolean_false(
        &mut self
    ) -> Result<Expression, YokaiErr>{
        let _true_token: Token = self.expect(&TokenType::False)?;
        Ok(Expression::Boolean(false))
    }

    pub fn parse_var_access(
        &mut self
    ) -> Result<Expression, YokaiErr>{
        let mut idents: Vec<String> = Vec::new();
        while self.peek_n(0)?.token_type == TokenType::UserIdent &&
              self.peek_n(1)?.token_type == TokenType::Dot
        {
            let user_ident: Token = self.expect(&TokenType::UserIdent)?;
            let ident: String = match user_ident.value {
                Some(ident) => ident,
                None => return Err::<Expression, YokaiErr>(
                    YokaiErr::new("Unexpected end of stream")
                )
            };
            let _dot_token: Token = self.expect(&TokenType::Dot)?;
            idents.push(ident);
        }
        let final_ident_token: Token = self.expect(&TokenType::UserIdent)?;
        let f_ident: String = match final_ident_token.value {
            Some(f_ident) => f_ident,
            None => return Err::<Expression, YokaiErr>(
                YokaiErr::new("Unexpected end of stream")
            )
        };
        idents.push(f_ident);
        Ok(Expression::VariableAccess(idents))
    }
}
