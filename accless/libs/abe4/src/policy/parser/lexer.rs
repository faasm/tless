use std::str::from_utf8;

#[derive(PartialEq, Debug, Clone)]
pub enum Token {
    LParen,
    RParen,
    And,
    Or,
    Not,
    Colon,
    Dot,
    Ident(String),
}

pub fn lex(input: &str) -> Vec<Token> {
    if !input.is_ascii() {
        panic!("Lexing error: policy must only contain ASCII character");
    }
    let mut tokens = Vec::new();
    let mut idx = 0;
    let input = input.as_bytes();
    while idx < input.len() {
        match input[idx] {
            b' ' | b'\r' | b'\t' | b'\n' => idx = idx + 1,
            b'(' => {
                tokens.push(Token::LParen);
                idx = idx + 1
            }
            b')' => {
                tokens.push(Token::RParen);
                idx = idx + 1
            }
            b':' => {
                tokens.push(Token::Colon);
                idx = idx + 1
            }
            b'.' => {
                tokens.push(Token::Dot);
                idx = idx + 1
            }
            b'!' => {
                tokens.push(Token::Not);
                idx = idx + 1
            }
            b'&' => {
                tokens.push(Token::And);
                idx = idx + 1
            }
            b'|' => {
                tokens.push(Token::Or);
                idx = idx + 1
            }
            _ => {
                let (token, i) = ident(input, idx);
                tokens.push(token);
                idx = i
            }
        }
    }
    return tokens;
}

fn ident(input: &[u8], start: usize) -> (Token, usize) {
    let mut end = start;
    while end < input.len() && (input[end].is_ascii_alphanumeric() || input[end] == b'_') {
        end = end + 1;
    }
    let str = from_utf8(&input[start..end]).unwrap();
    if str.is_empty() {
        panic!(
            "Illegal character '{}' found at index {}",
            from_utf8(&input[start..start + 1]).unwrap(),
            end
        );
    }
    (Token::Ident(String::from(str)), end)
}

#[test]
fn test_lexer() {
    let input = "x.b:a & (!x.b:a2 | orr.y:u) | anda.z:z";
    let tokens = lex(input);
    assert_eq!(tokens.len(), 26);
    assert_eq!(tokens[0], Token::Ident(String::from("x")));
    assert_eq!(tokens[1], Token::Dot);
    assert_eq!(tokens[2], Token::Ident(String::from("b")));
    assert_eq!(tokens[3], Token::Colon);
    assert_eq!(tokens[4], Token::Ident(String::from("a")));
    assert_eq!(tokens[5], Token::And);
    assert_eq!(tokens[6], Token::LParen);
    assert_eq!(tokens[7], Token::Not);
    assert_eq!(tokens[8], Token::Ident(String::from("x")));
    assert_eq!(tokens[9], Token::Dot);
    assert_eq!(tokens[10], Token::Ident(String::from("b")));
    assert_eq!(tokens[11], Token::Colon);
    assert_eq!(tokens[12], Token::Ident(String::from("a2")));
    assert_eq!(tokens[13], Token::Or);
    assert_eq!(tokens[14], Token::Ident(String::from("orr")));
    assert_eq!(tokens[15], Token::Dot);
    assert_eq!(tokens[16], Token::Ident(String::from("y")));
    assert_eq!(tokens[17], Token::Colon);
    assert_eq!(tokens[18], Token::Ident(String::from("u")));
    assert_eq!(tokens[19], Token::RParen);
    assert_eq!(tokens[20], Token::Or);
    assert_eq!(tokens[21], Token::Ident(String::from("anda")));
    assert_eq!(tokens[22], Token::Dot);
    assert_eq!(tokens[23], Token::Ident(String::from("z")));
    assert_eq!(tokens[24], Token::Colon);
    assert_eq!(tokens[25], Token::Ident(String::from("z")));
}
