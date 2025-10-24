use super::{Expr, UserAttribute};

mod lexer;

use lexer::{Token, lex};

pub struct Parser {
    tokens: Vec<Token>,
    attrs: Vec<UserAttribute>,
    negs: Vec<bool>,
    curr: usize,
    is_neg: bool,
    err_msg: Option<String>,
    had_error: bool,
}

impl Parser {
    fn new(tokens: Vec<Token>) -> Self {
        Parser {
            tokens,
            attrs: Vec::new(),
            negs: Vec::new(),
            curr: 0,
            is_neg: false,
            err_msg: None,
            had_error: false,
        }
    }

    fn set_err_msg(&mut self, msg: &str) {
        if !self.had_error {
            self.err_msg = Some(String::from(msg));
        }
        self.had_error = true;
    }

    fn advance(&mut self) {
        self.curr += 1;
    }

    fn next(&mut self) -> Option<Token> {
        let t = self.peek();
        self.advance();
        t
    }

    fn try_next(&mut self, token: Token) -> Option<()> {
        let t = self.peek()?;
        if t == token {
            self.advance();
            Some(())
        } else {
            None
        }
    }

    fn peek(&mut self) -> Option<Token> {
        if self.curr >= self.tokens.len() {
            None
        } else {
            let t = self.tokens[self.curr].clone();
            Some(t)
        }
    }

    fn require(&mut self, token: Token) -> Option<()> {
        let t = self.next()?;
        if t == token {
            Some(())
        } else {
            self.set_err_msg(&format!(
                "Found token '{:?}' but '{:?}' was expected",
                t, token
            ));
            None
        }
    }

    pub fn parse_policy(
        input: &str,
    ) -> Result<(Expr<(bool, UserAttribute)>, Vec<UserAttribute>, Vec<bool>), String> {
        let tokens = lex(input);
        let mut parser = Parser::new(tokens);

        let res = parser.or();
        if parser.had_error {
            return Err(parser.err_msg.as_ref().unwrap().clone());
        }
        match res {
            None => panic!("Unreachable"),
            Some(exp) => Ok((exp, parser.attrs, parser.negs)),
        }
    }

    pub fn parse_user_attr(attr: &str) -> Result<(String, String, String), String> {
        let tokens = lex(attr);
        let mut parser = Parser::new(tokens);
        let res = parser.lit();
        if parser.had_error {
            return Err(parser.err_msg.as_ref().unwrap().clone());
        }
        match res {
            Some(Expr::Lit((_, user_attr))) => Ok((user_attr.auth, user_attr.lbl, user_attr.attr)),
            _ => panic!("Unreachable"),
        }
    }

    fn or(&mut self) -> Option<Expr<(bool, UserAttribute)>> {
        let mut lhs = self.and()?;
        while let Some(_) = self.try_next(Token::Or) {
            let rhs = self.and()?;
            if self.is_neg {
                lhs = Expr::And(Box::new(lhs), Box::new(rhs));
            } else {
                lhs = Expr::Or(Box::new(lhs), Box::new(rhs));
            }
        }
        Some(lhs)
    }

    fn and(&mut self) -> Option<Expr<(bool, UserAttribute)>> {
        let mut lhs = self.not()?;
        while let Some(_) = self.try_next(Token::And) {
            let rhs = self.not()?;
            if self.is_neg {
                lhs = Expr::Or(Box::new(lhs), Box::new(rhs))
            } else {
                lhs = Expr::And(Box::new(lhs), Box::new(rhs))
            }
        }
        Some(lhs)
    }

    fn not(&mut self) -> Option<Expr<(bool, UserAttribute)>> {
        if let Some(_) = self.try_next(Token::Not) {
            self.is_neg = !self.is_neg;
            let exp = self.not()?;
            self.is_neg = !self.is_neg;
            return Some(exp);
        }
        self.prim()
    }

    fn prim(&mut self) -> Option<Expr<(bool, UserAttribute)>> {
        if let Some(_) = self.try_next(Token::LParen) {
            let exp = self.or()?;
            self.require(Token::RParen);
            return Some(exp);
        }
        self.lit()
    }

    fn lit(&mut self) -> Option<Expr<(bool, UserAttribute)>> {
        if let Some(Token::Ident(auth)) = self.next() {
            self.require(Token::Dot);
            if let Some(Token::Ident(lbl)) = self.next() {
                self.require(Token::Colon);
                if let Some(Token::Ident(attr)) = self.next() {
                    let user_attr = UserAttribute::new(&auth, &lbl, &attr);
                    self.attrs.push(user_attr.clone());
                    self.negs.push(self.is_neg);
                    return Some(Expr::Lit((self.is_neg, user_attr)));
                }
            }
        }
        None
    }
}

#[test]
fn test_parser() {
    fn pos(s: &str) -> Expr<(bool, UserAttribute)> {
        let user_attr = UserAttribute::parse(s).unwrap();
        Expr::Lit((false, user_attr))
    }

    fn neg(s: &str) -> Expr<(bool, UserAttribute)> {
        let user_attr = UserAttribute::parse(s).unwrap();
        Expr::Lit((true, user_attr))
    }

    fn and<T>(lhs: Expr<T>, rhs: Expr<T>) -> Expr<T> {
        Expr::And(Box::new(lhs), Box::new(rhs))
    }

    fn or<T>(lhs: Expr<T>, rhs: Expr<T>) -> Expr<T> {
        Expr::Or(Box::new(lhs), Box::new(rhs))
    }

    let policy = "x.b:a & !(!x.b:a2 | orr.y:u) | anda.z:z";
    let (expr, _, _) = Parser::parse_policy(&policy).unwrap();

    assert_eq!(
        expr,
        or(
            and(pos("x.b:a"), and(pos("x.b:a2"), neg("orr.y:u"))),
            pos("anda.z:z")
        )
    );
}
