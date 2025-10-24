use ark_std::iterable::Iterable;
use core::fmt;
use std::fmt::{Debug, Write};

#[derive(PartialEq)]
pub struct Policy {
    expr: Expr<(bool, UserAttribute)>,
    attrs: Vec<UserAttribute>,
    negs: Vec<bool>,
}

impl Policy {
    pub fn len(&self) -> usize {
        self.attrs.len()
    }

    pub fn get(&self, idx: usize) -> (UserAttribute, bool) {
        (self.attrs[idx].clone(), self.negs[idx])
    }

    pub fn parse(s: &str) -> Result<Self, String> {
        let (expr, attrs, negs) = parser::Parser::parse_policy(s)?;
        Ok(Policy { expr, attrs, negs })
    }

    pub fn conjunction_of(user_attrs: &Vec<UserAttribute>, num_negs: usize) -> Self {
        if num_negs > user_attrs.len() {
            panic!("Cannot have more negated attributes than total length of policy");
        }
        let mut negs = 0;
        let mut expr = if negs >= num_negs {
            Expr::Lit((false, user_attrs[0].clone()))
        } else {
            negs += 1;
            Expr::Lit((true, user_attrs[0].clone()))
        };
        // the parser produces left-associative Expr trees, so we do the same here
        for ua in user_attrs.iter().skip(1) {
            expr = if negs >= num_negs {
                Expr::And(Box::new(expr), Box::new(Expr::Lit((false, ua.clone()))))
            } else {
                negs += 1;
                Expr::And(Box::new(expr), Box::new(Expr::Lit((true, ua.clone()))))
            };
        }
        let attrs = user_attrs.clone();
        let mut negs = vec![false; user_attrs.len()];
        for i in 0..num_negs {
            negs[i] = true;
        }
        Policy { expr, attrs, negs }
    }

    pub fn share_secret(&self) -> Vec<(UserAttribute, Vec<i64>)> {
        secret_sharing::share_secret(self)
    }

    pub fn reconstruct_secret(&self, user_attrs: &Vec<UserAttribute>) -> Option<Vec<usize>> {
        secret_sharing::reconstruct_secret(user_attrs, self)
    }
}

fn fmt_expr(
    expr: &Expr<(bool, UserAttribute)>,
    f: &mut std::fmt::Formatter<'_>,
) -> std::fmt::Result {
    match expr {
        Expr::Lit((is_neg, t)) => {
            if *is_neg {
                write!(f, "!")?;
            }
            write!(f, "{:?}", t)
        }
        Expr::And(lhs, rhs) => {
            fmt_expr(lhs, f)?;
            write!(f, " & ")?;
            fmt_expr(rhs, f)
        }
        Expr::Or(_, _) => {
            panic!("Not implemented")
        }
    }
}

impl fmt::Debug for Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt_expr(&self.expr, f)
    }
}

#[derive(PartialEq, Clone)]
pub struct UserAttribute {
    pub auth: String,
    pub lbl: String,
    pub attr: String,
}

impl UserAttribute {
    pub fn new(auth: &str, lbl: &str, attr: &str) -> Self {
        UserAttribute {
            auth: String::from(auth),
            lbl: String::from(lbl),
            attr: String::from(attr),
        }
    }

    pub fn parse(s: &str) -> Result<Self, String> {
        let (auth, lbl, attr) = parser::Parser::parse_user_attr(s)?;
        Ok(UserAttribute { auth, lbl, attr })
    }

    pub fn auth_lbl_attr(&self) -> (String, String, String) {
        (self.auth.clone(), self.lbl.clone(), self.attr.clone())
    }

    pub fn auth_attr(&self) -> (String, String) {
        (self.auth.clone(), self.attr.clone())
    }

    pub fn auth_lbl(&self) -> (String, String) {
        (self.auth.clone(), self.lbl.clone())
    }
}

impl Debug for UserAttribute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.auth)?;
        f.write_char('.')?;
        f.write_str(&self.lbl)?;
        f.write_char(':')?;
        f.write_str(&self.attr)
    }
}

#[derive(Debug, PartialEq)]
enum Expr<T> {
    Lit(T),
    And(Box<Expr<T>>, Box<Expr<T>>),
    Or(Box<Expr<T>>, Box<Expr<T>>),
}

mod parser;
mod secret_sharing;
