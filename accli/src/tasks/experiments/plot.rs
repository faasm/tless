use crate::{
    env::Env,
    tasks::experiments::{
        Experiment,
        baselines::{EscrowBaseline, SystemBaseline},
        color::{FONT_SIZE, STROKE_WIDTH},
        ubench::{REQUEST_COUNTS_MHSM, REQUEST_COUNTS_TRUSTEE},
        workflows::Workflow,
    },
};
use anyhow::Result;
use csv::ReaderBuilder;
use log::{debug, error, info};
use plotters::prelude::*;
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    env,
    fs::{self, File},
    io::{BufRead, BufReader},
    path::PathBuf,
    str,
};

fn get_all_data_files(exp: &Experiment) -> Result<Vec<PathBuf>> {
    let data_path = format!("{}/{exp}/data", Env::experiments_root().display());

    // Collect all CSV files in the directory
    let mut csv_files = Vec::new();
    for entry in fs::read_dir(&data_path).map_err(|e| {
        let reason = format!("error reading from directory (path={data_path}, error={e:?})");
        error!("{reason}");
        anyhow::anyhow!(reason)
    })? {
        match entry {
            Ok(entry) => {
                if entry.path().extension().and_then(|e| e.to_str()) == Some("csv") {
                    csv_files.push(entry.path());
                }
            }
            Err(e) => {
                let reason = format!("error opening directory entry (error={e:?})");
                error!("{reason}");
                anyhow::bail!(reason);
            }
        }
    }

    Ok(csv_files)
}

fn plot_e2e_latency(plot_version: &str, exp: &Experiment, data_files: &Vec<PathBuf>) -> Result<()> {
    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct Record {
        #[allow(dead_code)]
        run: u32,
        time_ms: u64,
    }

    let baselines = match plot_version {
        "faasm" => {
            vec![
                SystemBaseline::Faasm,
                SystemBaseline::SgxFaasm,
                SystemBaseline::AcclessFaasm,
            ]
        }
        "knative" => {
            vec![
                SystemBaseline::Knative,
                SystemBaseline::SnpKnative,
                SystemBaseline::AcclessKnative,
            ]
        }
        _ => {
            unreachable! {}
        }
    };

    // Initialize the structure to hold the data
    let mut data = BTreeMap::<Workflow, BTreeMap<SystemBaseline, f64>>::new();
    for workflow in Workflow::iter_variants() {
        let mut inner_map = BTreeMap::<SystemBaseline, f64>::new();
        for baseline in &baselines {
            inner_map.insert(baseline.clone(), 0.0);
        }
        data.insert(workflow.clone(), inner_map);
    }

    let num_workflows = Workflow::iter_variants().len();
    let num_baselines = baselines.len();
    let mut y_max = 0.0;
    let x_max = (num_baselines * num_workflows + num_workflows) as f64 - 0.5;

    // Collect data
    for csv_file in data_files {
        let file_name = csv_file
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or_default();
        debug!("file: {file_name}");

        let file_name_len = file_name.len();
        let file_name_no_ext = &file_name[0..file_name_len - 4];

        let wflow: Workflow = file_name_no_ext.split("_").collect::<Vec<&str>>()[1]
            .parse()
            .unwrap();
        let baseline: SystemBaseline = file_name_no_ext.split("_").collect::<Vec<&str>>()[0]
            .parse()
            .unwrap();

        if !baselines.contains(&baseline) {
            continue;
        }

        // Open the CSV and deserialize records
        let mut reader = ReaderBuilder::new()
            .has_headers(true)
            .from_path(csv_file)
            .unwrap();
        let mut total_time = 0;
        let mut count = 0;

        for result in reader.deserialize() {
            let record: Record = result.unwrap();
            total_time += record.time_ms;
            count += 1;
        }

        let average_time = data.get_mut(&wflow).unwrap().get_mut(&baseline).unwrap();
        *average_time = total_time as f64 / count as f64;

        if *average_time > y_max {
            y_max = *average_time;
        }
    }

    let mut plot_path = env::current_dir().expect("invrs: failed to get current directory");
    plot_path.push("eval");
    plot_path.push(format!("{exp}"));
    plot_path.push("plots");
    plot_path.push(format!("{plot_version}.svg"));

    // Plot data
    let chart_width_px = 400;
    let root = SVGBackend::new(&plot_path, (chart_width_px, 300)).into_drawing_area();
    root.fill(&WHITE).unwrap();

    let x_min = -0.5;
    let y_max = match plot_version {
        "faasm" => 10.0,
        "knative" => 5.0,
        _ => unreachable!(),
    };
    let mut chart = ChartBuilder::on(&root)
        .x_label_area_size(40)
        .y_label_area_size(40)
        .margin(10)
        .margin_top(40)
        .build_cartesian_2d(x_min..x_max, 0f64..y_max)
        .unwrap();

    chart
        .configure_mesh()
        .light_line_style(WHITE)
        .y_labels(10)
        .y_label_style(("sans-serif", FONT_SIZE).into_font())
        .x_desc("")
        .x_label_formatter(&|_| String::new())
        .disable_x_mesh()
        .disable_x_axis()
        .y_label_formatter(&|y| format!("{:.0}", y))
        .draw()
        .unwrap();

    // Manually draw the y-axis label with a custom font and size
    root.draw(&Text::new(
        "Slowdown",
        (5, 200),
        ("sans-serif", FONT_SIZE)
            .into_font()
            .transform(FontTransform::Rotate270)
            .color(&BLACK),
    ))
    .unwrap();

    fn get_coordinate_for_workflow_label(workflow: &Workflow) -> (f64, f64) {
        // Replicate order in Workflow::iter_variants()
        let y_label = -0.25;
        match workflow {
            Workflow::Finra => (0.0, y_label),
            Workflow::MlTraining => (3.5, y_label),
            Workflow::MlInference => (8.0, y_label),
            Workflow::WordCount => (12.75, y_label),
        }
    }

    // Draw bars
    for (w_idx, (workflow, workflow_data)) in data.iter().enumerate() {
        let x_orig = (w_idx * (num_baselines + 1)) as f64;

        // Work-out the fastest value for each set of baselines
        let y_ref = match plot_version {
            "faasm" => *workflow_data.get(&SystemBaseline::Faasm).unwrap(),
            "knative" => *workflow_data.get(&SystemBaseline::Knative).unwrap(),
            _ => unreachable!(),
        };

        /* Un-comment to print the overhead claimed in the paper
        info!("{workflow}: knative overhead: {:.2} %",
                 ((*workflow_data.get(&SystemBaseline::TlessKnative).unwrap() /
                 *workflow_data.get(&SystemBaseline::CcKnative).unwrap()) - 1.0) * 100.0
                );
        if *workflow == Workflow::MlInference {
            info!("{} vs {}",
                 *workflow_data.get(&SystemBaseline::TlessKnative).unwrap(),
                 *workflow_data.get(&SystemBaseline::CcKnative).unwrap());
        }
        info!("{workflow}: faasm overhead: {:.2} %",
                 ((*workflow_data.get(&SystemBaseline::TlessFaasm).unwrap() /
                 *workflow_data.get(&SystemBaseline::SgxFaasm).unwrap()) - 1.0) * 100.0
                );
        */

        // Draw bars
        let margin_px = 2;
        chart
            .draw_series((0..).zip(workflow_data.iter()).map(|(x, (baseline, y))| {
                let bar_style = ShapeStyle {
                    color: baseline.get_color().unwrap().into(),
                    filled: true,
                    stroke_width: 2,
                };

                let this_y = y / y_ref;
                let mut bar = Rectangle::new(
                    [
                        (x_orig + x as f64, 0 as f64),
                        (x_orig + x as f64 + 1.0, this_y),
                    ],
                    bar_style,
                );
                bar.set_margin(0, 0, margin_px, margin_px);
                bar
            }))
            .unwrap();

        let x_axis_range = 0.0..x_max;
        let margin_units: f64 =
            margin_px as f64 * (x_axis_range.end - x_axis_range.start) / chart_width_px as f64;

        // Draw solid lines arround bars
        chart
            .draw_series((0..).zip(workflow_data.iter()).map(|(x, (_, y))| {
                let this_y = y / y_ref;
                PathElement::new(
                    vec![
                        (x_orig + x as f64 + margin_units, 0.0),
                        (x_orig + x as f64 + 1.0 - margin_units, 0.0),
                        (x_orig + x as f64 + 1.0 - margin_units, this_y),
                        (x_orig + x as f64 + margin_units, this_y),
                        (x_orig + x as f64 + margin_units, 0.0),
                    ],
                    BLACK,
                )
            }))
            .unwrap();

        for (x, (_baseline, y)) in (0..).zip(workflow_data.iter()) {
            let this_y = y / y_ref;

            // Add text for bars that overflow
            let y_offset = match plot_version {
                "faasm" => -3.0,
                "knative" => -1.5,
                _ => unreachable!(),
            };
            let x_orig_pixel = chart
                .plotting_area()
                .map_coordinate(&(x_orig + x as f64, y_max + y_offset));
            if this_y > y_max {
                let width = 20;
                let height = match plot_version {
                    "faasm" => 50,
                    "knative" => 35,
                    _ => unreachable!(),
                };
                root.draw(&Rectangle::new(
                    [
                        (x_orig_pixel.0, x_orig_pixel.1),
                        (x_orig_pixel.0 + width, x_orig_pixel.1 - height),
                    ],
                    WHITE.filled(),
                ))
                .unwrap();
                root.draw(&PathElement::new(
                    [
                        (x_orig_pixel.0, x_orig_pixel.1),
                        (x_orig_pixel.0 + width, x_orig_pixel.1),
                        (x_orig_pixel.0 + width, x_orig_pixel.1 - height),
                        (x_orig_pixel.0, x_orig_pixel.1 - height),
                        (x_orig_pixel.0, x_orig_pixel.1),
                    ],
                    BLACK,
                ))
                .unwrap();
                chart
                    .plotting_area()
                    .draw(&Text::new(
                        format!("{:.1}", this_y),
                        (x_orig + x as f64, y_max + y_offset),
                        ("sans-serif", FONT_SIZE - 2)
                            .into_font()
                            .transform(FontTransform::Rotate270),
                    ))
                    .unwrap();
            }
        }

        // Add label for the workflow
        root.draw(&Text::new(
            match workflow {
                Workflow::Finra => format!("{workflow}"),
                Workflow::MlTraining => "ml-train".to_string(),
                Workflow::MlInference => "ml-inf".to_string(),
                Workflow::WordCount => "wc".to_string(),
            },
            chart
                .plotting_area()
                .map_coordinate(&get_coordinate_for_workflow_label(workflow)),
            ("sans-serif", FONT_SIZE).into_font(),
        ))
        .unwrap();
    }

    // Add red line for slowdown
    chart
        .plotting_area()
        .draw(&PathElement::new(
            vec![(x_min, 1.0), (x_max, 1.0)],
            RED.stroke_width(STROKE_WIDTH),
        ))
        .unwrap();

    // Add solid frames
    chart
        .plotting_area()
        .draw(&PathElement::new(
            vec![(x_min, 100.0), (x_max, 100.0)],
            BLACK,
        ))
        .unwrap();
    chart
        .plotting_area()
        .draw(&PathElement::new(vec![(x_max, 0.0), (x_max, 100.0)], BLACK))
        .unwrap();
    chart
        .plotting_area()
        .draw(&PathElement::new(vec![(x_min, 0.0), (x_max, 0.0)], BLACK))
        .unwrap();

    fn legend_label_pos_for_baseline(baseline: &SystemBaseline) -> (i32, i32) {
        let legend_x_start = 10;
        let legend_y_pos = 6;

        match baseline {
            SystemBaseline::Faasm => (legend_x_start, legend_y_pos),
            SystemBaseline::SgxFaasm => (legend_x_start + 120, legend_y_pos),
            SystemBaseline::AcclessFaasm => (legend_x_start + 280, legend_y_pos),
            SystemBaseline::Knative => (legend_x_start, legend_y_pos),
            SystemBaseline::SnpKnative => (legend_x_start + 120, legend_y_pos),
            SystemBaseline::AcclessKnative => (legend_x_start + 280, legend_y_pos),
        }
    }

    // Manually draw the legend outside the grid, above the chart
    for baseline in &baselines {
        // Calculate position for each legend item
        let (x_pos, y_pos) = legend_label_pos_for_baseline(baseline);

        // Draw the color box (Rectangle) + frame
        root.draw(&Rectangle::new(
            [(x_pos, y_pos), (x_pos + 20, y_pos + 20)],
            baseline.get_color()?.filled(),
        ))
        .unwrap();
        root.draw(&PathElement::new(
            vec![(x_pos, y_pos), (x_pos + 20, y_pos)],
            BLACK,
        ))
        .unwrap();
        root.draw(&PathElement::new(
            vec![(x_pos + 20, y_pos), (x_pos + 20, y_pos + 20)],
            BLACK,
        ))
        .unwrap();
        root.draw(&PathElement::new(
            vec![(x_pos, y_pos), (x_pos, y_pos + 20)],
            BLACK,
        ))
        .unwrap();
        root.draw(&PathElement::new(
            vec![(x_pos, y_pos + 20), (x_pos + 20, y_pos + 20)],
            BLACK,
        ))
        .unwrap();

        let mut label = format!("{baseline}");
        if baseline == &SystemBaseline::AcclessKnative || baseline == &SystemBaseline::AcclessFaasm
        {
            label = "accless".to_string();
        }

        // Draw the baseline label (Text)
        root.draw(&Text::new(
            label,
            (x_pos + 30, y_pos + 1), // Adjust text position
            ("sans-serif", FONT_SIZE).into_font(),
        ))
        .unwrap();
    }

    root.present()?;
    info!("generated plot at: {}", plot_path.display());

    Ok(())
}

fn plot_scale_up_latency(plot_version: &str, data_files: &Vec<PathBuf>) {
    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct Record {
        #[allow(dead_code)]
        run: u32,
        time_ms: u64,
    }

    const NUM_POINTS: usize = 10;
    let num_parallel_funcs = match plot_version {
        "knative" => vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
        "faasm" => vec![1, 10, 20, 40, 50, 60, 70, 80, 90, 100],
        _ => panic!(),
    };

    let baselines = match plot_version {
        "faasm" => {
            vec![
                SystemBaseline::Faasm,
                SystemBaseline::SgxFaasm,
                SystemBaseline::AcclessFaasm,
            ]
        }
        "knative" => {
            vec![
                SystemBaseline::Knative,
                SystemBaseline::SnpKnative,
                SystemBaseline::AcclessKnative,
            ]
        }
        _ => {
            unreachable! {}
        }
    };

    // Collect data
    let mut data = BTreeMap::<SystemBaseline, [u64; NUM_POINTS]>::new();
    for baseline in &baselines {
        data.insert(baseline.clone(), [0; NUM_POINTS]);
    }

    for csv_file in data_files {
        let file_name = csv_file
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or_default();
        debug!("file name: {file_name}");

        let file_name_len = file_name.len();
        let file_name_no_ext = &file_name[0..file_name_len - 4];
        let parts: Vec<&str> = file_name_no_ext.split("_").collect();
        let workload_parts: Vec<&str> = parts[1].split("-").collect();

        let baseline: SystemBaseline = parts[0].parse().unwrap();
        if !baselines.contains(&baseline) {
            continue;
        }

        let _workload: &str = workload_parts[0];
        let scale_up_factor: usize = workload_parts[1].parse().unwrap();

        if !num_parallel_funcs.contains(&scale_up_factor) {
            continue;
        }

        // Open the CSV and deserialize records
        let mut reader = ReaderBuilder::new()
            .has_headers(true)
            .from_path(csv_file)
            .unwrap();
        let mut count = 0;
        let avg_times = data.get_mut(&baseline).unwrap();

        let idx = num_parallel_funcs
            .iter()
            .position(|&x| x == scale_up_factor)
            .unwrap();
        for result in reader.deserialize() {
            let record: Record = result.unwrap();

            avg_times[idx] += record.time_ms;
            count += 1;
        }

        avg_times[idx] /= count;
    }

    let y_max: f64 = 125.0;
    let mut plot_path = Env::experiments_root();
    plot_path.push(Experiment::SCALE_UP_LATENCY_NAME);
    plot_path.push("plots");
    fs::create_dir_all(plot_path.clone()).unwrap();
    plot_path.push(format!("{plot_version}.svg"));

    // Plot data
    let root = SVGBackend::new(&plot_path, (400, 300)).into_drawing_area();
    root.fill(&WHITE).unwrap();

    let x_max = num_parallel_funcs[num_parallel_funcs.len() - 1];
    let mut chart = ChartBuilder::on(&root)
        .x_label_area_size(40)
        .y_label_area_size(40)
        .margin(10)
        .margin_top(40)
        .margin_left(40)
        .margin_right(20)
        .build_cartesian_2d(0..(x_max) as u32, 0f64..y_max)
        .unwrap();

    chart
        .configure_mesh()
        .light_line_style(WHITE)
        .x_labels(8)
        .y_labels(6)
        .x_label_style(("sans-serif", FONT_SIZE).into_font())
        .y_label_style(("sans-serif", FONT_SIZE).into_font())
        .x_desc("")
        .y_label_formatter(&|y| format!("{:.0}", y))
        .draw()
        .unwrap();

    // Manually draw the X/Y-axis label with a custom font and size
    root.draw(&Text::new(
        "Execution time [s]",
        (5, 245),
        ("sans-serif", FONT_SIZE)
            .into_font()
            .transform(FontTransform::Rotate270)
            .color(&BLACK),
    ))
    .unwrap();
    root.draw(&Text::new(
        "# of audit functions",
        (120, 280),
        ("sans-serif", FONT_SIZE).into_font().color(&BLACK),
    ))
    .unwrap();

    for (baseline, values) in data {
        chart
            .draw_series(LineSeries::new(
                (0..values.len())
                    .zip(values.iter())
                    .map(|(x, y)| (num_parallel_funcs[x] as u32, *y as f64 / 1000.0)),
                baseline.get_color().unwrap().stroke_width(STROKE_WIDTH),
            ))
            .unwrap();

        chart
            .draw_series((0..values.len()).zip(values.iter()).map(|(x, y)| {
                Circle::new(
                    (num_parallel_funcs[x] as u32, *y as f64 / 1000.0),
                    5,
                    baseline.get_color().unwrap().filled(),
                )
            }))
            .unwrap();
    }

    // Add solid frames
    chart
        .plotting_area()
        .draw(&PathElement::new(
            vec![(0, y_max), (x_max as u32, y_max)],
            BLACK,
        ))
        .unwrap();
    chart
        .plotting_area()
        .draw(&PathElement::new(
            vec![(x_max as u32, 0.0), (x_max as u32, y_max)],
            BLACK,
        ))
        .unwrap();

    fn legend_label_pos_for_baseline(baseline: &SystemBaseline) -> (i32, i32) {
        let legend_x_start = 10;
        let legend_y_pos = 6;

        match baseline {
            SystemBaseline::Faasm => (legend_x_start, legend_y_pos),
            SystemBaseline::SgxFaasm => (legend_x_start + 120, legend_y_pos),
            SystemBaseline::AcclessFaasm => (legend_x_start + 280, legend_y_pos),
            SystemBaseline::Knative => (legend_x_start, legend_y_pos),
            SystemBaseline::SnpKnative => (legend_x_start + 120, legend_y_pos),
            SystemBaseline::AcclessKnative => (legend_x_start + 280, legend_y_pos),
        }
    }

    for baseline in &baselines {
        // Calculate position for each legend item
        let (x_pos, y_pos) = legend_label_pos_for_baseline(baseline);

        // Draw the color box (Rectangle)
        root.draw(&Rectangle::new(
            [(x_pos, y_pos), (x_pos + 20, y_pos + 20)],
            baseline.get_color().unwrap().filled(),
        ))
        .unwrap();
        root.draw(&PathElement::new(
            vec![(x_pos, y_pos), (x_pos + 20, y_pos)],
            BLACK,
        ))
        .unwrap();
        root.draw(&PathElement::new(
            vec![(x_pos + 20, y_pos), (x_pos + 20, y_pos + 20)],
            BLACK,
        ))
        .unwrap();
        root.draw(&PathElement::new(
            vec![(x_pos, y_pos), (x_pos, y_pos + 20)],
            BLACK,
        ))
        .unwrap();
        root.draw(&PathElement::new(
            vec![(x_pos, y_pos + 20), (x_pos + 20, y_pos + 20)],
            BLACK,
        ))
        .unwrap();

        let mut label = format!("{baseline}");
        if baseline == &SystemBaseline::AcclessKnative || baseline == &SystemBaseline::AcclessFaasm
        {
            label = "accless".to_string();
        }

        // Draw the baseline label (Text)
        root.draw(&Text::new(
            label,
            (x_pos + 30, y_pos + 5),
            ("sans-serif", FONT_SIZE).into_font(),
        ))
        .unwrap();
    }

    root.present().unwrap();
    info!("generated plot at: {}", plot_path.display());
}

fn compute_cdf(samples: &[u64]) -> Vec<(f64, f64)> {
    let mut sorted = samples.to_owned();
    sorted.sort_unstable();

    let n = sorted.len() as f64;
    sorted
        .iter()
        .enumerate()
        .map(|(i, &x)| {
            let cdf = (i + 1) as f64 / n;
            (x as f64, cdf)
        })
        .collect()
}

fn plot_cold_start_cdf(plot_version: &str, data_files: &Vec<PathBuf>) {
    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct Record {
        #[allow(dead_code)]
        run: usize,
        time_ms: u64,
    }

    let baselines = match plot_version {
        "faasm" => {
            vec![
                SystemBaseline::Faasm,
                SystemBaseline::SgxFaasm,
                SystemBaseline::AcclessFaasm,
            ]
        }
        "knative" => {
            vec![
                SystemBaseline::Knative,
                SystemBaseline::SnpKnative,
                SystemBaseline::AcclessKnative,
            ]
        }
        _ => {
            unreachable! {}
        }
    };

    // Collect data
    let mut data = BTreeMap::<SystemBaseline, Vec<u64>>::new();
    for baseline in &baselines {
        data.insert(baseline.clone(), vec![]);
    }

    for csv_file in data_files {
        let file_name = csv_file
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or_default();
        debug!("file name: {file_name}");

        let file_name_len = file_name.len();
        let baseline: SystemBaseline = file_name[0..file_name_len - 4].parse().unwrap();
        if !baselines.contains(&baseline) {
            continue;
        }

        // Open the CSV and deserialize records
        let mut reader = ReaderBuilder::new()
            .has_headers(true)
            .from_path(csv_file)
            .unwrap();

        for result in reader.deserialize() {
            debug!("{baseline}: {csv_file:?}");
            let record: Record = result.unwrap();
            data.get_mut(&baseline).unwrap().push(record.time_ms);
        }
    }

    let mut plot_path = Env::experiments_root();
    plot_path.push(Experiment::COLD_START_NAME);
    plot_path.push("plots");
    fs::create_dir_all(plot_path.clone()).unwrap();
    plot_path.push(format!("{plot_version}.svg"));

    // Plot data
    let root = SVGBackend::new(&plot_path, (400, 300)).into_drawing_area();
    root.fill(&WHITE).unwrap();

    // X axis in ms
    let x_max = match plot_version {
        "faasm" => 2000,
        "knative" => 20000,
        _ => panic!(),
    };
    let y_max: f64 = 100.0;

    fn legend_label_pos_for_baseline(baseline: &SystemBaseline) -> (i32, i32) {
        let legend_x_start = 10;
        let legend_y_pos = 6;

        match baseline {
            SystemBaseline::Faasm => (legend_x_start, legend_y_pos),
            SystemBaseline::SgxFaasm => (legend_x_start + 110, legend_y_pos),
            SystemBaseline::AcclessFaasm => (legend_x_start + 270, legend_y_pos),
            SystemBaseline::Knative => (legend_x_start, legend_y_pos),
            SystemBaseline::SnpKnative => (legend_x_start + 110, legend_y_pos),
            SystemBaseline::AcclessKnative => (legend_x_start + 270, legend_y_pos),
        }
    }

    if plot_version == "faasm" {
        let mut chart = ChartBuilder::on(&root)
            .x_label_area_size(40)
            .y_label_area_size(40)
            .margin(10)
            .margin_top(50)
            .margin_left(40)
            .margin_right(25)
            .margin_bottom(20)
            .build_cartesian_2d((0..x_max).log_scale(), 0f64..y_max)
            .unwrap();

        chart
            .configure_mesh()
            .light_line_style(WHITE)
            .x_labels(8)
            .y_labels(6)
            .y_label_formatter(&|v| format!("{:.0}", v))
            .x_label_style(("sans-serif", FONT_SIZE).into_font())
            .y_label_style(("sans-serif", FONT_SIZE).into_font())
            .x_desc("")
            .draw()
            .unwrap();

        // Manually draw the X/Y-axis label with a custom font and size
        root.draw(&Text::new(
            "CDF [%]",
            (5, 200),
            ("sans-serif", FONT_SIZE)
                .into_font()
                .transform(FontTransform::Rotate270)
                .color(&BLACK),
        ))
        .unwrap();
        root.draw(&Text::new(
            "Latency [ms]",
            (175, 275),
            ("sans-serif", FONT_SIZE).into_font().color(&BLACK),
        ))
        .unwrap();

        for (baseline, values) in data {
            // Draw line
            let values_cdf = compute_cdf(&values);
            chart
                .draw_series(LineSeries::new(
                    values_cdf.into_iter().map(|(x, y)| (x as i32, y * 100.0)),
                    SystemBaseline::get_color(&baseline)
                        .unwrap()
                        .stroke_width(STROKE_WIDTH),
                ))
                .unwrap();
        }

        // Add solid frames
        chart
            .plotting_area()
            .draw(&PathElement::new(vec![(0, y_max), (x_max, y_max)], BLACK))
            .unwrap();
        chart
            .plotting_area()
            .draw(&PathElement::new(vec![(x_max, 0.0), (x_max, y_max)], BLACK))
            .unwrap();

        for baseline in &baselines {
            // Calculate position for each legend item
            let (x_pos, y_pos) = legend_label_pos_for_baseline(baseline);

            // Draw the color box (Rectangle) + frame
            let square_side = 20;
            root.draw(&Rectangle::new(
                [(x_pos, y_pos), (x_pos + square_side, y_pos + square_side)],
                SystemBaseline::get_color(baseline).unwrap().filled(),
            ))
            .unwrap();
            root.draw(&PathElement::new(
                vec![(x_pos, y_pos), (x_pos + 20, y_pos)],
                BLACK,
            ))
            .unwrap();
            root.draw(&PathElement::new(
                vec![(x_pos + 20, y_pos), (x_pos + 20, y_pos + 20)],
                BLACK,
            ))
            .unwrap();
            root.draw(&PathElement::new(
                vec![(x_pos, y_pos), (x_pos, y_pos + 20)],
                BLACK,
            ))
            .unwrap();
            root.draw(&PathElement::new(
                vec![(x_pos, y_pos + 20), (x_pos + 20, y_pos + 20)],
                BLACK,
            ))
            .unwrap();

            // Draw the baseline label (Text)
            root.draw(&Text::new(
                match baseline {
                    SystemBaseline::AcclessFaasm | SystemBaseline::AcclessKnative => {
                        "accless".to_string()
                    }
                    _ => format!("{baseline}"),
                },
                (x_pos + 30, y_pos + 2), // Adjust text position
                ("sans-serif", FONT_SIZE).into_font(),
            ))
            .unwrap();
        }

        root.present().unwrap();
    } else {
        let mut chart = ChartBuilder::on(&root)
            .x_label_area_size(40)
            .y_label_area_size(40)
            .margin(10)
            .margin_top(50)
            .margin_left(40)
            .margin_right(25)
            .margin_bottom(20)
            .build_cartesian_2d(0..x_max, 0f64..y_max)
            .unwrap();

        chart
            .configure_mesh()
            .light_line_style(WHITE)
            .x_labels(8)
            .y_labels(6)
            .y_label_formatter(&|v| format!("{:.0}", v))
            .x_label_style(("sans-serif", FONT_SIZE).into_font())
            .y_label_style(("sans-serif", FONT_SIZE).into_font())
            .x_desc("")
            .draw()
            .unwrap();

        // Manually draw the X/Y-axis label with a custom font and size
        root.draw(&Text::new(
            "CDF [%]",
            (5, 200),
            ("sans-serif", FONT_SIZE)
                .into_font()
                .transform(FontTransform::Rotate270)
                .color(&BLACK),
        ))
        .unwrap();
        root.draw(&Text::new(
            "Latency [ms]",
            (175, 275),
            ("sans-serif", FONT_SIZE).into_font().color(&BLACK),
        ))
        .unwrap();

        for (baseline, values) in data {
            // Draw line
            let values_cdf = compute_cdf(&values);
            chart
                .draw_series(LineSeries::new(
                    values_cdf.into_iter().map(|(x, y)| (x as i32, y * 100.0)),
                    SystemBaseline::get_color(&baseline)
                        .unwrap()
                        .stroke_width(STROKE_WIDTH),
                ))
                .unwrap();
        }

        // Add solid frames
        chart
            .plotting_area()
            .draw(&PathElement::new(vec![(0, y_max), (x_max, y_max)], BLACK))
            .unwrap();
        chart
            .plotting_area()
            .draw(&PathElement::new(vec![(x_max, 0.0), (x_max, y_max)], BLACK))
            .unwrap();

        for baseline in &baselines {
            // Calculate position for each legend item
            let (x_pos, y_pos) = legend_label_pos_for_baseline(baseline);

            // Draw the color box (Rectangle) + frame
            let square_side = 20;
            root.draw(&Rectangle::new(
                [(x_pos, y_pos), (x_pos + square_side, y_pos + square_side)],
                SystemBaseline::get_color(baseline).unwrap().filled(),
            ))
            .unwrap();
            root.draw(&PathElement::new(
                vec![(x_pos, y_pos), (x_pos + 20, y_pos)],
                BLACK,
            ))
            .unwrap();
            root.draw(&PathElement::new(
                vec![(x_pos + 20, y_pos), (x_pos + 20, y_pos + 20)],
                BLACK,
            ))
            .unwrap();
            root.draw(&PathElement::new(
                vec![(x_pos, y_pos), (x_pos, y_pos + 20)],
                BLACK,
            ))
            .unwrap();
            root.draw(&PathElement::new(
                vec![(x_pos, y_pos + 20), (x_pos + 20, y_pos + 20)],
                BLACK,
            ))
            .unwrap();

            // Draw the baseline label (Text)
            root.draw(&Text::new(
                match baseline {
                    SystemBaseline::AcclessFaasm | SystemBaseline::AcclessKnative => {
                        "accless".to_string()
                    }
                    _ => format!("{baseline}"),
                },
                (x_pos + 30, y_pos + 2), // Adjust text position
                ("sans-serif", FONT_SIZE).into_font(),
            ))
            .unwrap();
        }

        root.present().unwrap();
    }

    info!("generated plot at: {}", plot_path.display());
}

fn plot_escrow_xput(data_files: &Vec<PathBuf>) {
    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct Record {
        #[allow(dead_code)]
        num_requests: usize,
        time_elapsed: f64,
    }

    // Collect data
    let mut data = BTreeMap::<EscrowBaseline, [f64; REQUEST_COUNTS_TRUSTEE.len()]>::new();
    for baseline in EscrowBaseline::iter_variants() {
        // Temporarily skip plotting Accless Maa.
        if baseline == &EscrowBaseline::AcclessMaa {
            continue;
        }

        data.insert(baseline.clone(), [0.0; REQUEST_COUNTS_TRUSTEE.len()]);
    }

    for csv_file in data_files {
        let file_name = csv_file
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or_default();
        debug!("file name: {file_name}");

        let file_name_len = file_name.len();
        let baseline: EscrowBaseline = file_name[0..file_name_len - 4].parse().unwrap();

        // For the moment we do not plot the AcclessMaa baseline.
        if baseline == EscrowBaseline::AcclessMaa {
            continue;
        };

        // Open the CSV and deserialize records
        let mut reader = ReaderBuilder::new()
            .has_headers(true)
            .from_path(csv_file)
            .unwrap();
        let mut count = 0;

        for result in reader.deserialize() {
            debug!("{baseline}: {csv_file:?}");
            let record: Record = result.unwrap();

            let agg_times = data.get_mut(&baseline).unwrap();

            count += 1;
            let n_req = record.num_requests;
            let request_counts = match baseline {
                EscrowBaseline::Trustee
                | EscrowBaseline::Accless
                | EscrowBaseline::AcclessMaa
                | EscrowBaseline::AcclessSingleAuth => REQUEST_COUNTS_TRUSTEE,
                EscrowBaseline::ManagedHSM => REQUEST_COUNTS_MHSM,
            };
            let idx = request_counts
                .iter()
                .position(|&x| n_req == x)
                .expect("num. requests not found!");
            agg_times[idx] += record.time_elapsed;
        }

        let num_repeats: f64 = (count / REQUEST_COUNTS_TRUSTEE.len()) as f64;

        let average_times = data.get_mut(&baseline).unwrap();
        for time in average_times {
            *time /= num_repeats;
        }
    }

    let mut plot_path = Env::experiments_root();
    plot_path.push(Experiment::ESCROW_XPUT_NAME);
    plot_path.push("plots");
    fs::create_dir_all(plot_path.clone()).unwrap();
    plot_path.push(format!("{}.svg", Experiment::ESCROW_XPUT_NAME));

    // Plot data
    let root = SVGBackend::new(&plot_path, (400, 300)).into_drawing_area();
    root.fill(&WHITE).unwrap();

    let x_max = 200;
    let y_max: f64 = 2.0;
    let mut chart = ChartBuilder::on(&root)
        .x_label_area_size(40)
        .y_label_area_size(40)
        .margin(10)
        .margin_top(40)
        .margin_left(50)
        .margin_right(25)
        .margin_bottom(20)
        .build_cartesian_2d(0..x_max, 0f64..y_max)
        .unwrap();

    chart
        .configure_mesh()
        .light_line_style(WHITE)
        .x_labels(8)
        .y_labels(6)
        .x_label_style(("sans-serif", FONT_SIZE).into_font())
        .y_label_style(("sans-serif", FONT_SIZE).into_font())
        .x_desc("")
        .draw()
        .unwrap();

    // Manually draw the X/Y-axis label with a custom font and size
    root.draw(&Text::new(
        "Latency [s]",
        (5, 200),
        ("sans-serif", FONT_SIZE)
            .into_font()
            .transform(FontTransform::Rotate270)
            .color(&BLACK),
    ))
    .unwrap();
    root.draw(&Text::new(
        "Throughput [RPS]",
        (125, 275),
        ("sans-serif", FONT_SIZE).into_font().color(&BLACK),
    ))
    .unwrap();

    for (baseline, values) in data {
        // Draw line
        let mut point_exceeded: Option<(i32, f64)> = None;
        chart
            .draw_series(LineSeries::new(
                (0..values.len())
                    .zip(values[0..].iter())
                    // .filter(|(_, y)| **y <= y_max)
                    .map(|(x, y)| {
                        // Draw the line until the last point that exceeds y_max.
                        if let Some(point_exceeded) = point_exceeded {
                            return point_exceeded;
                        }
                        let point = (
                            match baseline {
                                EscrowBaseline::Trustee
                                | EscrowBaseline::Accless
                                | EscrowBaseline::AcclessMaa
                                | EscrowBaseline::AcclessSingleAuth => {
                                    REQUEST_COUNTS_TRUSTEE[x] as i32
                                }
                                EscrowBaseline::ManagedHSM => REQUEST_COUNTS_MHSM[x] as i32,
                            },
                            *y,
                        );

                        if point_exceeded.is_none() & (*y > y_max) {
                            point_exceeded = Some(point);
                        }

                        point
                    }),
                EscrowBaseline::get_color(&baseline)
                    .unwrap()
                    .stroke_width(STROKE_WIDTH),
            ))
            .unwrap();

        // Draw data point on line
        chart
            .draw_series(
                (0..values.len())
                    .zip(values[0..].iter())
                    .filter(|(_, y)| **y <= y_max)
                    .map(|(x, y)| {
                        Circle::new(
                            (
                                match baseline {
                                    EscrowBaseline::Trustee
                                    | EscrowBaseline::Accless
                                    | EscrowBaseline::AcclessMaa
                                    | EscrowBaseline::AcclessSingleAuth => {
                                        REQUEST_COUNTS_TRUSTEE[x] as i32
                                    }
                                    EscrowBaseline::ManagedHSM => REQUEST_COUNTS_MHSM[x] as i32,
                                },
                                *y,
                            ),
                            5,
                            EscrowBaseline::get_color(&baseline).unwrap().filled(),
                        )
                    }),
            )
            .unwrap();
    }

    // Add solid frames
    chart
        .plotting_area()
        .draw(&PathElement::new(vec![(0, y_max), (x_max, y_max)], BLACK))
        .unwrap();
    chart
        .plotting_area()
        .draw(&PathElement::new(vec![(x_max, 0.0), (x_max, y_max)], BLACK))
        .unwrap();

    fn legend_label_pos_for_baseline(baseline: &EscrowBaseline) -> (i32, i32) {
        let legend_x_start = 20;
        let legend_y_pos = 6;

        match baseline {
            EscrowBaseline::ManagedHSM => (legend_x_start, legend_y_pos),
            EscrowBaseline::Trustee => (legend_x_start + 220, legend_y_pos),
            _ => panic!(),
        }
    }

    // NOTE: we combine the labels with the figure that is placed side-by-side
    for baseline in [EscrowBaseline::ManagedHSM, EscrowBaseline::Trustee] {
        // Calculate position for each legend item
        let (x_pos, y_pos) = legend_label_pos_for_baseline(&baseline);

        // Draw the color box (Rectangle) + frame
        let square_side = 20;
        root.draw(&Rectangle::new(
            [(x_pos, y_pos), (x_pos + square_side, y_pos + square_side)],
            EscrowBaseline::get_color(&baseline).unwrap().filled(),
        ))
        .unwrap();
        root.draw(&PathElement::new(
            vec![(x_pos, y_pos), (x_pos + 20, y_pos)],
            BLACK,
        ))
        .unwrap();
        root.draw(&PathElement::new(
            vec![(x_pos + 20, y_pos), (x_pos + 20, y_pos + 20)],
            BLACK,
        ))
        .unwrap();
        root.draw(&PathElement::new(
            vec![(x_pos, y_pos), (x_pos, y_pos + 20)],
            BLACK,
        ))
        .unwrap();
        root.draw(&PathElement::new(
            vec![(x_pos, y_pos + 20), (x_pos + 20, y_pos + 20)],
            BLACK,
        ))
        .unwrap();

        // Draw the baseline label (Text)
        root.draw(&Text::new(
            format!("{baseline}"),
            (x_pos + 30, y_pos + 2), // Adjust text position
            ("sans-serif", FONT_SIZE).into_font(),
        ))
        .unwrap();
    }

    root.present().unwrap();
    info!(
        "plot_escrow_xput(): generated plot at: {}",
        plot_path.display()
    );
}

fn get_escrow_cost_data(path: &str, n: usize) -> Vec<f64> {
    let file = File::open(path).expect("get_escrow_cost_data(): could not open file (path={path})");
    let reader = BufReader::new(file);

    // 1. Parse the file and filter for NumRequests == 1
    let data: Vec<f64> = reader
        .lines()
        .skip(1) // Skip CSV header
        .filter_map(|line| line.ok()) // Unwrap lines safely
        .filter_map(|line| {
            let parts: Vec<&str> = line.split(',').collect();

            // Check if first column (NumRequests) is "1"
            if parts.first()?.trim() == "1" {
                // Parse second column (TimeElapsed)
                parts.get(1)?.trim().parse::<f64>().ok()
            } else {
                None
            }
        })
        .collect();

    if data.is_empty() {
        panic!("get_escrow_cost_data(): no entries for 1 request found (path={path})");
    }

    // 2. Cycle through the data to fill N positions
    data.into_iter().cycle().take(n).collect()
}

fn plot_escrow_cost() {
    // Rounded monthly cost (in USD) of a Standard_DCas_v5 as of 17/04/2025.
    const UNIT_MONTHLY_COST_DC2: u32 = 62;

    let trustee_latency_single_req = get_escrow_cost_data(
        &format!(
            "{}/escrow-xput/data/{}.csv",
            Env::experiments_root().display(),
            EscrowBaseline::Trustee
        ),
        1_usize,
    )[0];

    // Variables:
    let trustee_unit_cost = UNIT_MONTHLY_COST_DC2;
    let accless_unit_cost = UNIT_MONTHLY_COST_DC2 * 3;
    let accless_single_auth_unit_cost = UNIT_MONTHLY_COST_DC2;
    let num_max_users = 10;
    let accless_latency_ys = get_escrow_cost_data(
        &format!(
            "{}/escrow-xput/data/{}.csv",
            Env::experiments_root().display(),
            EscrowBaseline::Accless
        ),
        num_max_users as usize,
    );
    let accless_latency: Vec<(u32, f64)> = (1..=accless_latency_ys.len() as u32)
        .map(|x| (x, accless_latency_ys[x as usize - 1]))
        .collect();

    let mut plot_path = Env::experiments_root()
        .join(Experiment::ESCROW_COST_NAME)
        .join("plots");
    fs::create_dir_all(plot_path.clone()).unwrap();
    plot_path.push(format!("{}.svg", Experiment::ESCROW_COST_NAME));
    let root = SVGBackend::new(&plot_path, (400, 300)).into_drawing_area();
    root.fill(&WHITE).unwrap();

    let y_max = 75.0;
    let mut chart = ChartBuilder::on(&root)
        .margin(10)
        .margin_top(40)
        .margin_left(40)
        .margin_bottom(20)
        .margin_right(45)
        .x_label_area_size(40)
        .y_label_area_size(40)
        .right_y_label_area_size(40)
        .build_cartesian_2d(1u32..num_max_users, 0.0f64..y_max)
        .unwrap()
        .set_secondary_coord(
            1u32..num_max_users,
            0f64..(num_max_users * trustee_unit_cost) as f64,
        ); // Right axis for cost

    // Draw meshes
    chart
        .configure_mesh()
        .light_line_style(WHITE)
        .x_label_style(("sans-serif", FONT_SIZE).into_font())
        .x_labels(8)
        .y_labels(6)
        .y_label_formatter(&|y| format!("{:.0}", y))
        .y_label_style(("sans-serif", FONT_SIZE).into_font())
        .draw()
        .unwrap();

    chart
        .configure_secondary_axes()
        .label_style(("sans-serif", FONT_SIZE).into_font())
        .y_label_formatter(&|y| format!("{:.0}", y))
        .y_labels(6)
        .draw()
        .unwrap();

    // Manually draw the X/Y-axis label with a custom font and size
    root.draw(&Text::new(
        "Latency [ms]",
        (5, 215),
        ("sans-serif", FONT_SIZE)
            .into_font()
            .transform(FontTransform::Rotate270)
            .color(&BLACK),
    ))
    .unwrap();
    root.draw(&Text::new(
        "# of users ",
        (120, 280),
        ("sans-serif", FONT_SIZE).into_font().color(&BLACK),
    ))
    .unwrap();
    root.draw(&Text::new(
        "Op. Cost [$/month]",
        (390, 35),
        ("sans-serif", FONT_SIZE)
            .into_font()
            .transform(FontTransform::Rotate90)
            .color(&BLACK),
    ))
    .unwrap();

    chart
        .draw_series(LineSeries::new(
            (1..=num_max_users).map(|x| (x, trustee_latency_single_req * 1000.0)),
            EscrowBaseline::get_color(&EscrowBaseline::Trustee)
                .unwrap()
                .stroke_width(STROKE_WIDTH),
        ))
        .unwrap();

    chart
        .draw_series(LineSeries::new(
            accless_latency
                .clone()
                .into_iter()
                .map(|(x, y)| (x, y * 1000.0)),
            EscrowBaseline::get_color(&EscrowBaseline::Accless)
                .unwrap()
                .stroke_width(STROKE_WIDTH),
        ))
        .unwrap();

    // Cost: Trustee (linear y = unit_cost * x)
    let trustee_cost: Vec<(u32, f64)> = (1..=num_max_users)
        .map(|x| (x, (trustee_unit_cost * x) as f64))
        .collect();
    let trustee_cost_style = EscrowBaseline::get_color(&EscrowBaseline::Trustee)
        .unwrap()
        .stroke_width(STROKE_WIDTH);
    chart
        .draw_secondary_series(LineSeries::new(trustee_cost.clone(), trustee_cost_style))
        .unwrap();
    chart
        .draw_secondary_series(trustee_cost.into_iter().map(|(x, y)| {
            Circle::new(
                (x, y),
                7,
                EscrowBaseline::get_color(&EscrowBaseline::Trustee)
                    .unwrap()
                    .filled(),
            )
        }))
        .unwrap();

    // Accless cost
    let accless_cost: Vec<(u32, f64)> = (1..=num_max_users)
        .map(|x| (x, (accless_unit_cost) as f64))
        .collect();
    chart
        .draw_secondary_series(LineSeries::new(
            accless_cost.clone(),
            EscrowBaseline::get_color(&EscrowBaseline::Accless)
                .unwrap()
                .stroke_width(STROKE_WIDTH),
        ))
        .unwrap();
    chart
        .draw_secondary_series(accless_cost.into_iter().map(|(x, y)| {
            Circle::new(
                (x, y),
                7,
                EscrowBaseline::get_color(&EscrowBaseline::Accless)
                    .unwrap()
                    .filled(),
            )
        }))
        .unwrap();

    // Accless-single-auth cost
    let accless_cost: Vec<(u32, f64)> = (1..=num_max_users)
        .map(|x| (x, (accless_single_auth_unit_cost) as f64))
        .collect();
    chart
        .draw_secondary_series(LineSeries::new(
            accless_cost.clone(),
            EscrowBaseline::get_color(&EscrowBaseline::AcclessSingleAuth)
                .unwrap()
                .stroke_width(STROKE_WIDTH),
        ))
        .unwrap();
    chart
        .draw_secondary_series(accless_cost.into_iter().map(|(x, y)| {
            Circle::new(
                (x, y),
                7,
                EscrowBaseline::get_color(&EscrowBaseline::AcclessSingleAuth)
                    .unwrap()
                    .filled(),
            )
        }))
        .unwrap();

    // Draw black frame.
    chart
        .plotting_area()
        .draw(&PathElement::new(
            vec![(1u32, y_max), (num_max_users, y_max)],
            BLACK,
        ))
        .unwrap();
    chart
        .plotting_area()
        .draw(&PathElement::new(
            vec![(num_max_users, 0.0), (num_max_users, y_max)],
            BLACK,
        ))
        .unwrap();

    fn legend_label_pos_for_baseline(baseline: &EscrowBaseline) -> (i32, i32) {
        let legend_x_start = 20;
        let legend_y_pos = 2;

        match baseline {
            EscrowBaseline::Accless => (legend_x_start, legend_y_pos),
            EscrowBaseline::AcclessSingleAuth => (legend_x_start + 120, legend_y_pos),
            _ => panic!(),
        }
    }

    for baseline in &[EscrowBaseline::Accless, EscrowBaseline::AcclessSingleAuth] {
        // Calculate position for each legend item
        let (x_pos, y_pos) = legend_label_pos_for_baseline(baseline);

        // Draw the color box (Rectangle)
        root.draw(&Rectangle::new(
            [(x_pos, y_pos), (x_pos + 20, y_pos + 20)],
            baseline.get_color().unwrap().filled(),
        ))
        .unwrap();
        root.draw(&PathElement::new(
            vec![
                (x_pos, y_pos),
                (x_pos + 20, y_pos),
                (x_pos + 20, y_pos + 20),
                (x_pos, y_pos + 20),
                (x_pos, y_pos),
            ],
            BLACK,
        ))
        .unwrap();

        // Draw the baseline label (Text)
        root.draw(&Text::new(
            format!("{baseline}"),
            (x_pos + 30, y_pos + 5),
            ("sans-serif", FONT_SIZE).into_font(),
        ))
        .unwrap();
    }

    root.present().unwrap();
    info!(
        "plot_escrow_cost(): generated plot at: {}",
        plot_path.display()
    );
}

pub fn plot(exp: &Experiment) -> Result<()> {
    match exp {
        Experiment::ColdStart { .. } => {
            let data_files = get_all_data_files(exp)?;
            plot_cold_start_cdf("faasm", &data_files);
            plot_cold_start_cdf("knative", &data_files);
        }
        Experiment::E2eLatency { .. } => {
            let data_files = get_all_data_files(exp)?;
            plot_e2e_latency("faasm", exp, &data_files)?;
            plot_e2e_latency("knative", exp, &data_files)?;
        }
        Experiment::E2eLatencyCold { .. } => {
            let data_files = get_all_data_files(exp)?;
            plot_e2e_latency("faasm", exp, &data_files)?;
            plot_e2e_latency("knative", exp, &data_files)?;
        }
        Experiment::EscrowCost { .. } => {
            plot_escrow_cost();
        }
        Experiment::EscrowXput { .. } => {
            let data_files = get_all_data_files(exp)?;
            plot_escrow_xput(&data_files);
        }
        Experiment::ScaleUpLatency { .. } => {
            let data_files = get_all_data_files(exp)?;
            plot_scale_up_latency("faasm", &data_files);
            plot_scale_up_latency("knative", &data_files);
        }
    }

    Ok(())
}
