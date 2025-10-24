use plotters::prelude::*;

pub static FONT_SIZE: i32 = 28;
pub static STROKE_WIDTH: u32 = 5;

// TODO: make colors really stand out
pub fn get_color_from_label(label: &str) -> RGBColor {
    match label {
        "dark-red" | "accless" => RGBColor(130, 1, 1),
        "dark-blue" | "accless-maa" => RGBColor(1, 6, 130),
        "dark-green" => RGBColor(0, 97, 29),
        "dark-orange" => RGBColor(163, 99, 2),
        "dark-yellow" => RGBColor(179, 176, 0),
        _ => panic!("invrs: unrecognised label: {label}"),
    }
}
