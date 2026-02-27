use anyhow::Result;
use log::error;
use plotters::prelude::RGBColor;

pub static FONT_SIZE: i32 = 28;
pub static STROKE_WIDTH: u32 = 5;

pub fn get_color_from_label(label: &str) -> Result<RGBColor> {
    match label {
        // "dark-red" | "accless" => Ok(RGBColor(130, 1, 1)),
        "dark-red" | "accless" => Ok(RGBColor(213, 94, 0)),
        // "dark-blue" | "accless-maa" => Ok(RGBColor(1, 6, 130)),
        "dark-blue" | "accless-maa" => Ok(RGBColor(0, 114, 178)),
        // "dark-green" => Ok(RGBColor(0, 97, 29)),
        "dark-green" => Ok(RGBColor(0, 158, 115)),
        // "dark-orange" => Ok(RGBColor(163, 99, 2)),
        "dark-orange" => Ok(RGBColor(230, 159, 0)),
        // "dark-yellow" => Ok(RGBColor(179, 176, 0)),
        "dark-yellow" => Ok(RGBColor(240, 228, 66)),
        _ => {
            error!("unrecognized label for color (label={label})");
            anyhow::bail!("unrecognized label (label={label})");
        }
    }
}
