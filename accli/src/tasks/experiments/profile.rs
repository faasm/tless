use crate::{env::Env, tasks::experiments::Experiment};
use abe4::{
    Policy, UserAttribute, decrypt_hybrid, encrypt_hybrid,
    iota::Iota,
    keygen,
    scheme::types::{MPK, USK},
    setup,
};
use anyhow::Result;
use ark_std::rand::{SeedableRng, rngs::StdRng};
use clap::Args;
use csv::Writer;
use indicatif::{ProgressBar, ProgressStyle};
use log::{error, info};
use rand::{seq::SliceRandom, thread_rng};
use std::{
    fs::{self, File},
    path::PathBuf,
    time::Instant,
};

const USER_ID: &str = "policy-decryption-user";
const WORKFLOW_ID: &str = "wf";
const NODE_ID: &str = "node";
const DEFAULT_PLAINTEXT: &[u8] = b"policy-decryption-payload";
const DEFAULT_AAD: &[u8] = b"policy-decryption-aad";
const POLICY_SIZES: &[usize] = &[1, 2, 4, 8, 12, 16];

#[derive(Debug, Args)]
pub struct ProfileRunArgs {
    #[arg(long, default_value_t = 5)]
    pub num_warmup_runs: u32,
    #[arg(long, default_value_t = 20)]
    pub num_runs: u32,
}

#[derive(Clone, Copy)]
enum PolicyShape {
    Conjunction,
    Disjunction,
}

impl PolicyShape {
    fn file_stem(&self) -> &'static str {
        match self {
            PolicyShape::Conjunction => "conjunction",
            PolicyShape::Disjunction => "disjunction",
        }
    }
}

#[derive(Clone, Copy)]
enum AttributeFlavor {
    AllAuthorities,
    SingleAuthorityOnly,
}

impl AttributeFlavor {
    fn file_suffix(&self) -> &'static str {
        match self {
            AttributeFlavor::AllAuthorities => "",
            AttributeFlavor::SingleAuthorityOnly => "-single-authority",
        }
    }
}

#[derive(serde::Serialize)]
struct Record {
    #[serde(rename = "NumAuthorities")]
    num_authorities: usize,
    #[serde(rename = "Run")]
    run: u32,
    #[serde(rename = "EncryptMs")]
    encrypt_ms: f64,
    #[serde(rename = "DecryptMs")]
    decrypt_ms: f64,
}

fn build_authorities(num: usize) -> Vec<String> {
    (0..num).map(|idx| format!("as{idx:02}")).collect()
}

fn build_user_attributes(
    authorities: &[String],
    flavor: AttributeFlavor,
) -> Result<Vec<UserAttribute>> {
    let mut user_attrs = Vec::new();
    match flavor {
        AttributeFlavor::AllAuthorities => {
            for auth in authorities {
                user_attrs.push(UserAttribute::parse(&format!("{auth}.wf:{WORKFLOW_ID}"))?);
                user_attrs.push(UserAttribute::parse(&format!("{auth}.node:{NODE_ID}"))?);
            }
        }
        AttributeFlavor::SingleAuthorityOnly => {
            // Pick an attribute at random.
            let mut rng = thread_rng();
            if let Some(auth) = authorities.choose(&mut rng) {
                user_attrs.push(UserAttribute::parse(&format!("{auth}.wf:{WORKFLOW_ID}"))?);
                user_attrs.push(UserAttribute::parse(&format!("{auth}.node:{NODE_ID}"))?);
            } else {
                anyhow::bail!("cannot build user attributes without authorities");
            };
        }
    };
    Ok(user_attrs)
}

fn build_policy(authorities: &[String], shape: PolicyShape) -> Result<Policy> {
    let mut clauses = Vec::new();
    for auth in authorities {
        clauses.push(format!("({auth}.wf:{WORKFLOW_ID} & {auth}.node:{NODE_ID})"));
    }

    let op = match shape {
        PolicyShape::Conjunction => " & ",
        PolicyShape::Disjunction => " | ",
    };
    let policy_str = clauses.join(op);
    Policy::parse(&policy_str)
}

fn ensure_data_dir() -> Result<PathBuf> {
    let mut data_dir = Env::experiments_root();
    data_dir.push(Experiment::POLICY_DECRYPTION_NAME);
    data_dir.push("data");
    fs::create_dir_all(&data_dir)?;
    Ok(data_dir)
}

fn measure_single_run(
    rng: &mut StdRng,
    policy: &Policy,
    usk: &USK,
    mpk: &MPK,
) -> Result<(f64, f64)> {
    let enc_start = Instant::now();
    let ct = encrypt_hybrid(rng, mpk, policy, DEFAULT_PLAINTEXT, DEFAULT_AAD)?;
    let enc_ms = enc_start.elapsed().as_secs_f64() * 1_000.0;

    let dec_start = Instant::now();
    let pt = decrypt_hybrid(usk, USER_ID, policy, &ct.abe_ct, &ct.sym_ct, DEFAULT_AAD)?;
    let dec_ms = dec_start.elapsed().as_secs_f64() * 1_000.0;

    if pt.as_slice() != DEFAULT_PLAINTEXT {
        let reason = "decrypt_hybrid() returned unexpected plaintext";
        error!("{reason}");
        anyhow::bail!(reason);
    }

    Ok((enc_ms, dec_ms))
}

fn run_shape(shape: PolicyShape, args: &ProfileRunArgs) -> Result<()> {
    // Skip unsupported combinations.
    if matches!(shape, PolicyShape::Conjunction) {
        return run_shape_with_flavor(shape, AttributeFlavor::AllAuthorities, args);
    }
    run_shape_with_flavor(shape, AttributeFlavor::AllAuthorities, args)?;
    run_shape_with_flavor(shape, AttributeFlavor::SingleAuthorityOnly, args)
}

fn run_shape_with_flavor(
    shape: PolicyShape,
    flavor: AttributeFlavor,
    args: &ProfileRunArgs,
) -> Result<()> {
    if matches!(
        (shape, flavor),
        (
            PolicyShape::Conjunction,
            AttributeFlavor::SingleAuthorityOnly
        )
    ) {
        info!("Skipping single-authority flavour for conjunction policy");
        return Ok(());
    }

    let data_dir = ensure_data_dir()?;
    let mut csv_path = data_dir;
    csv_path.push(format!("{}{}.csv", shape.file_stem(), flavor.file_suffix()));
    let mut writer = Writer::from_writer(File::create(csv_path)?);
    let total_iters = (POLICY_SIZES.len() as u64) * (args.num_warmup_runs + args.num_runs) as u64;
    let pb = ProgressBar::new(total_iters).with_message(format!(
        "{}{}",
        shape.file_stem(),
        flavor.file_suffix()
    ));
    pb.set_style(
        ProgressStyle::with_template("{msg} [{bar:40.cyan/blue}] {pos}/{len}")
            .unwrap()
            .progress_chars("=>-"),
    );

    for &num_auth in POLICY_SIZES {
        let authorities = build_authorities(num_auth);
        let user_attrs = build_user_attributes(&authorities, flavor)?;
        let auths_ref: Vec<&str> = authorities.iter().map(|s| s.as_str()).collect();

        let mut rng = StdRng::seed_from_u64(1337 + num_auth as u64);
        let (msk, mpk) = setup(&mut rng, &auths_ref);

        let iota = Iota::new(&user_attrs);
        let usk = keygen(&mut rng, USER_ID, &msk, &user_attrs, &iota);
        let policy = build_policy(&authorities, shape)?;

        for _ in 0..args.num_warmup_runs {
            let _ = measure_single_run(&mut rng, &policy, &usk, &mpk)?;
            pb.inc(1);
        }

        for run_idx in 0..args.num_runs {
            let (encrypt_ms, decrypt_ms) = measure_single_run(&mut rng, &policy, &usk, &mpk)?;
            writer.serialize(Record {
                num_authorities: num_auth,
                run: run_idx,
                encrypt_ms,
                decrypt_ms,
            })?;
            pb.inc(1);
        }
    }

    pb.finish_and_clear();
    writer.flush()?;

    Ok(())
}

pub fn run(args: &ProfileRunArgs) -> Result<()> {
    info!(
        "Running policy-decryption profile (warmups={}, runs={})",
        args.num_warmup_runs, args.num_runs
    );

    run_shape(PolicyShape::Conjunction, args)?;
    run_shape(PolicyShape::Disjunction, args)?;

    Ok(())
}
