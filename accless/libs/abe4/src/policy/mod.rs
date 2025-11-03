use anyhow::Result;
use ark_std::iterable::Iterable;
use core::fmt;
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Write};

mod parser;
mod secret_sharing;

// -----------------------------------------------------------------------------------------------
// Structure And Enum Definitions
// -----------------------------------------------------------------------------------------------

#[derive(Debug, PartialEq)]
enum Expr<T> {
    Lit(T),
    And(Box<Expr<T>>, Box<Expr<T>>),
    Or(Box<Expr<T>>, Box<Expr<T>>),
}

/// Structure representing a user attribute in decentralized CP-ABE. A user
/// attribute is a triple of strings: (authority, label, attribute) indicating
/// the authority that provides keys for this attribute, the attribute label,
/// and the value itself.
#[derive(PartialEq, Clone, Serialize, Deserialize)]
pub struct UserAttribute {
    authority: String,
    label: String,
    attribute: String,
}

/// Structure representing an access control policy.
#[derive(PartialEq)]
pub struct Policy {
    expr: Expr<(bool, UserAttribute)>,
    attrs: Vec<UserAttribute>,
    negs: Vec<bool>,
}

// -----------------------------------------------------------------------------------------------
// Implementations
// -----------------------------------------------------------------------------------------------

impl UserAttribute {
    pub fn new(auth: &str, lbl: &str, attr: &str) -> Self {
        UserAttribute {
            authority: String::from(auth),
            label: String::from(lbl),
            attribute: String::from(attr),
        }
    }

    pub fn authority(&self) -> &str {
        &self.authority
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn attribute(&self) -> &str {
        &self.attribute
    }

    pub fn parse(s: &str) -> Result<Self, String> {
        let (auth, lbl, attr) = parser::Parser::parse_user_attr(s)?;
        Ok(UserAttribute {
            authority: auth,
            label: lbl,
            attribute: attr,
        })
    }

    pub fn auth_lbl_attr(&self) -> (String, String, String) {
        (
            self.authority.clone(),
            self.label.clone(),
            self.attribute.clone(),
        )
    }

    pub fn auth_attr(&self) -> (String, String) {
        (self.authority.clone(), self.attribute.clone())
    }

    pub fn auth_lbl(&self) -> (String, String) {
        (self.authority.clone(), self.label.clone())
    }
}

impl Debug for UserAttribute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.authority)?;
        f.write_char('.')?;
        f.write_str(&self.label)?;
        f.write_char(':')?;
        f.write_str(&self.attribute)
    }
}
impl Policy {
    pub fn len(&self) -> usize {
        self.attrs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.attrs.is_empty()
    }

    pub fn get(&self, idx: usize) -> (UserAttribute, bool) {
        (self.attrs[idx].clone(), self.negs[idx])
    }

    pub fn parse(s: &str) -> Result<Self> {
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
        for neg in negs.iter_mut() {
            *neg = true;
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

/// Helper method to format an expression.
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
            write!(f, "(")?;
            fmt_expr(lhs, f)?;
            write!(f, " & ")?;
            fmt_expr(rhs, f)?;
            write!(f, ")")
        }
        Expr::Or(lhs, rhs) => {
            write!(f, "(")?;
            fmt_expr(lhs, f)?;
            write!(f, " | ")?;
            fmt_expr(rhs, f)?;
            write!(f, ")")
        }
    }
}

impl fmt::Debug for Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt_expr(&self.expr, f)
    }
}
