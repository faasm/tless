use anyhow::Result;
use log::error;
use plotters::prelude::RGBColor;

pub static FONT_SIZE: i32 = 28;
pub static STROKE_WIDTH: u32 = 5;

pub fn get_color_from_label(label: &str) -> Result<RGBColor> {
    match label {
        "dark-red" | "accless" => Ok(RGBColor(130, 1, 1)),
        "dark-blue" | "accless-maa" => Ok(RGBColor(1, 6, 130)),
        "dark-green" => Ok(RGBColor(0, 97, 29)),
        "dark-orange" => Ok(RGBColor(163, 99, 2)),
        "dark-yellow" => Ok(RGBColor(179, 176, 0)),
        _ => {
            error!("unrecognized label for color (label={label})");
            anyhow::bail!("unrecognized label (label={label})");
        }
    }
}
