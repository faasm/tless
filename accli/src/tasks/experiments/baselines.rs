use crate::tasks::experiments::color::get_color_from_label;
use anyhow::Result;
use clap::ValueEnum;
use plotters::prelude::RGBColor;
use std::{fmt, str::FromStr};

#[derive(Clone, Debug, ValueEnum, PartialEq, Eq, PartialOrd, Ord)]
pub enum SystemBaseline {
    Faasm,
    SgxFaasm,
    AcclessFaasm,
    Knative,
    SnpKnative,
    AcclessKnative,
}

impl fmt::Display for SystemBaseline {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SystemBaseline::Faasm => write!(f, "faasm"),
            SystemBaseline::SgxFaasm => write!(f, "sgx-faasm"),
            SystemBaseline::AcclessFaasm => write!(f, "accless-faasm"),
            SystemBaseline::Knative => write!(f, "knative"),
            SystemBaseline::SnpKnative => write!(f, "snp-knative"),
            SystemBaseline::AcclessKnative => write!(f, "accless-knative"),
        }
    }
}

impl FromStr for SystemBaseline {
    type Err = ();

    fn from_str(input: &str) -> Result<SystemBaseline, Self::Err> {
        match input {
            "faasm" => Ok(SystemBaseline::Faasm),
            "sgx-faasm" => Ok(SystemBaseline::SgxFaasm),
            "accless-faasm" => Ok(SystemBaseline::AcclessFaasm),
            "knative" => Ok(SystemBaseline::Knative),
            "snp-knative" => Ok(SystemBaseline::SnpKnative),
            "accless-knative" => Ok(SystemBaseline::AcclessKnative),
            _ => Err(()),
        }
    }
}

impl SystemBaseline {
    pub fn iter_variants() -> std::slice::Iter<'static, SystemBaseline> {
        static VARIANTS: [SystemBaseline; 6] = [
            SystemBaseline::Faasm,
            SystemBaseline::SgxFaasm,
            SystemBaseline::AcclessFaasm,
            SystemBaseline::Knative,
            SystemBaseline::SnpKnative,
            SystemBaseline::AcclessKnative,
        ];
        VARIANTS.iter()
    }

    pub fn get_color(&self) -> Result<RGBColor> {
        match self {
            SystemBaseline::Faasm => get_color_from_label("dark-orange"),
            SystemBaseline::SgxFaasm => get_color_from_label("dark-green"),
            SystemBaseline::AcclessFaasm => get_color_from_label("accless"),
            SystemBaseline::Knative => get_color_from_label("dark-blue"),
            SystemBaseline::SnpKnative => get_color_from_label("dark-yellow"),
            SystemBaseline::AcclessKnative => get_color_from_label("accless"),
        }
    }
}

#[derive(Clone, Debug, ValueEnum, PartialEq, Eq, PartialOrd, Ord)]
pub enum EscrowBaseline {
    Trustee,
    ManagedHSM,
    Accless,
    AcclessMaa,
    AcclessSingleAuth,
}

impl fmt::Display for EscrowBaseline {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EscrowBaseline::Trustee => write!(f, "trustee"),
            EscrowBaseline::ManagedHSM => write!(f, "managed-hsm"),
            EscrowBaseline::Accless => write!(f, "accless"),
            EscrowBaseline::AcclessMaa => write!(f, "accless-maa"),
            EscrowBaseline::AcclessSingleAuth => write!(f, "accless-single-auth"),
        }
    }
}

impl FromStr for EscrowBaseline {
    type Err = ();

    fn from_str(input: &str) -> Result<EscrowBaseline, Self::Err> {
        match input {
            "trustee" => Ok(EscrowBaseline::Trustee),
            "managed-hsm" => Ok(EscrowBaseline::ManagedHSM),
            "accless-maa" => Ok(EscrowBaseline::AcclessMaa),
            "accless" => Ok(EscrowBaseline::Accless),
            _ => Err(()),
        }
    }
}

impl EscrowBaseline {
    pub fn iter_variants() -> std::slice::Iter<'static, EscrowBaseline> {
        static VARIANTS: [EscrowBaseline; 4] = [
            EscrowBaseline::Trustee,
            EscrowBaseline::ManagedHSM,
            EscrowBaseline::AcclessMaa,
            EscrowBaseline::Accless,
        ];
        VARIANTS.iter()
    }

    pub fn get_color(&self) -> Result<RGBColor> {
        match self {
            EscrowBaseline::Trustee => get_color_from_label("dark-orange"),
            EscrowBaseline::ManagedHSM => get_color_from_label("dark-green"),
            EscrowBaseline::Accless => get_color_from_label("accless"),
            EscrowBaseline::AcclessMaa | EscrowBaseline::AcclessSingleAuth => {
                get_color_from_label("dark-blue")
            }
        }
    }
}
