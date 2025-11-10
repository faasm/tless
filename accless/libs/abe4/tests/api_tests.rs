use abe4::{Gt, Policy, UserAttribute, decrypt, encrypt, iota::Iota, keygen, setup, tau::Tau};
use std::collections::HashSet;

const USER_ID: &str = "TEST_USER_ID";

fn prepare_test(user_attrs: &Vec<&str>, policy: &str) -> (Vec<String>, Vec<UserAttribute>, Policy) {
    let policy = Policy::parse(policy).unwrap();
    let user_attrs: Vec<UserAttribute> = user_attrs
        .iter()
        .map(|ua| UserAttribute::parse(ua).unwrap())
        .collect();
    let mut auths: HashSet<String> = HashSet::new();
    for ua in user_attrs.iter() {
        auths.insert(ua.authority().to_string());
    }
    for idx in 0..policy.len() {
        auths.insert(policy.get(idx).0.authority().to_string());
    }
    if auths.is_empty() {
        panic!(
            "Fatal error: cannot execute test case if both user attributes and policy are empty"
        );
    }
    (auths.into_iter().collect(), user_attrs, policy)
}

fn test_scheme(user_attrs: Vec<&str>, policy: &str) -> (Gt, Option<Gt>) {
    let (auths, user_attrs, policy) = prepare_test(&user_attrs, &policy);
    let mut rng = ark_std::test_rng();
    let auths: Vec<&str> = auths.iter().map(|s| s as &str).collect();
    let iota = Iota::new(&user_attrs);
    let (msk, mpk) = setup(&mut rng, &auths);
    let usk = keygen(&mut rng, USER_ID, &msk, &user_attrs, &iota);
    let tau = Tau::new(&policy);
    let (k_enc, ct) = encrypt(&mut rng, &mpk, &policy, &tau);
    let k_dec = decrypt(&usk, USER_ID, &iota, &tau, &policy, &ct);
    (k_enc, k_dec)
}

pub fn assert_decryption_ok(user_attrs: Vec<&str>, policy: &str) {
    let (k_enc, k_dec) = test_scheme(user_attrs, policy);
    assert!(k_dec.is_some_and(|k| Gt::eq(&k_enc, &k)));
}

pub fn assert_decryption_fail(user_attrs: Vec<&str>, policy: &str) {
    let (_, k_dec) = test_scheme(user_attrs, policy);
    assert!(k_dec.is_none());
}

// Handcrafted test cases (single auth)

#[test]
fn single_auth_single_ok() {
    let user_attrs = vec!["A.a:0"];
    let policy = "A.a:0";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn single_auth_single_multi_attr_ok() {
    let user_attrs = vec!["A.a:0", "A.a:0"];
    let policy = "A.a:0";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn single_auth_single_fail() {
    let user_attrs = vec![];
    let policy = "A.a:0";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn single_auth_conjunction_ok() {
    let user_attrs = vec!["A.a:0", "A.b:0"];
    let policy = "A.a:0 & A.b:0";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn single_auth_conjunction_no_left_fail() {
    let user_attrs = vec!["A.b:0"];
    let policy = "A.a:rainy & A.b:0";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn single_auth_conjunction_no_right_fail() {
    let user_attrs = vec!["A.a:0"];
    let policy = "A.a:0 & A.b:0";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn single_auth_negation_ok() {
    let user_attrs = vec!["A.a:0"];
    let policy = "!A.a:1";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn single_auth_negation_multi_alternative_ok() {
    let user_attrs = vec!["A.a:1", "A.a:2", "A.a:3"];
    let policy = "!A.a:0";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn single_auth_negation_contradiction_fail() {
    let user_attrs = vec!["A.a:1"];
    let policy = "!A.a:1";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn single_auth_negation_no_alternative_fail() {
    let user_attrs = vec!["A.b:0"];
    let policy = "!A.a:1";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn single_auth_disjunction_left_ok() {
    let user_attrs = vec!["A.a:0"];
    let policy = "A.a:0 | A.a:1";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn single_auth_disjunction_right_ok() {
    let user_attrs = vec!["A.a:1"];
    let policy = "A.a:0 | A.a:1";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn single_auth_disjunction_both_ok() {
    let user_attrs = vec!["A.a:0", "A.a:1"];
    let policy = "A.a:0 | A.a:1";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn single_auth_disjunction_fail() {
    let user_attrs = vec![];
    let policy = "A.a:0 | A.b:0";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn single_auth_conjunction_left_negated_ok() {
    let user_attrs = vec!["A.a:1", "A.b:0"];
    let policy = "!A.a:0 & A.b:0";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn single_auth_conjunction_left_negated_contradiction_fail() {
    let user_attrs = vec!["A.a:0", "A.b:0"];
    let policy = "!A.a:0 & A.b:0";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn single_auth_conjunction_left_negated_no_alternative_fail() {
    let user_attrs = vec!["A.b:0"];
    let policy = "!A.a:0 & A.b:0";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn single_auth_conjunction_left_negated_no_right_fail() {
    let user_attrs = vec!["A.a:2"];
    let policy = "!A.a:0 & A.b:0";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn single_auth_conjunction_both_negated_ok() {
    let user_attrs = vec!["A.a:2", "A.b:1"];
    let policy = "!A.a:0 & !A.b:0";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn single_auth_disjunction_right_negated_ok() {
    let user_attrs = vec!["A.b:1"];
    let policy = "A.a:1 | !A.b:0";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn single_auth_disjunction_right_negated_both_ok() {
    let user_attrs = vec!["A.a:1", "A.b:0"];
    let policy = "A.a:1 | !A.b:0";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn single_auth_disjunction_right_negated_contradiction_fail() {
    let user_attrs = vec!["A.b:0"];
    let policy = "A.a:1 | !A.b:0";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn single_auth_disjunction_right_negated_no_alternative_fail() {
    let user_attrs = vec![];
    let policy = "A.a:1 | !A.b:0";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn single_auth_disjunction_both_negated_ok() {
    let user_attrs = vec!["A.a:1", "A.b:0"];
    let policy = "!A.a:0 | !A.b:0";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn single_auth_complex_1_ok() {
    let user_attrs = vec!["A.a:0", "A.c:0"];
    let policy = "A.a:0 | (!A.b:0 & A.a:2) & !(A.c:1 | A.c:2)";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn single_auth_complex_2_ok() {
    let user_attrs = vec!["A.a:2", "A.b:1", "A.c:0"];
    let policy = "A.a:0 | (!A.b:0 & A.a:2) & !(A.c:1 | A.c:2)";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn single_auth_complex_fail() {
    let user_attrs = vec!["A.a:2", "A.c:2"];
    let policy = "A.a:0 | (!A.b:0 & A.a:2) & !(A.c:1 | A.c:2)";
    assert_decryption_fail(user_attrs, policy);
}

// Handcrafted test cases (multi auth)

#[test]
fn multi_auth_disjunction_left_ok() {
    let user_attrs = vec!["A.a:0"];
    let policy = "A.a:0 | B.a:0";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn multi_auth_disjunction_right_ok() {
    let user_attrs = vec!["B.a:0"];
    let policy = "A.a:0 | B.a:0";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn multi_auth_disjunction_both_ok() {
    let user_attrs = vec!["A.a:0", "B.a:0"];
    let policy = "A.a:0 | B.a:0";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn multi_auth_disjunction_wrong_auth_fail() {
    let user_attrs = vec!["C.a:0"];
    let policy = "A.a:0 | B.a:0";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn multi_auth_conjunction_ok() {
    let user_attrs = vec!["A.a:0", "B.a:0"];
    let policy = "A.a:0 & B.a:0";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn multi_auth_conjunction_missing_left_fail() {
    let user_attrs = vec!["B.a:0"];
    let policy = "A.a:0 & B.a:0";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn multi_auth_conjunction_missing_right_fail() {
    let user_attrs = vec!["A.a:0"];
    let policy = "A.a:0 & B.a:0";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn multi_auth_negation_ok() {
    let user_attrs = vec!["A.a:1", "A.a:2", "A.a:3", "A.a:4", "A.a:5", "B.a:0"];
    let policy = "!A.a:0";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn multi_auth_negation_cross_auth_fail() {
    let user_attrs = vec!["B.a:0"];
    let policy = "!A.a:0";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn multi_auth_complex_1_ok() {
    let user_attrs = vec!["A.a:0", "A.b:2", "A.c:1", "B.b:0", "B.b:1"];
    let policy = "A.a:1 | (!A.a:1 & A.b:2) & !(B.b:2 | A.c:2)";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn multi_auth_complex_2_ok() {
    let user_attrs = vec!["A.a:2", "A.b:1", "A.c:0", "B.c:0", "C.c:0", "C.c:1"];
    let policy = "A.a:0 | (!A.b:0 & A.a:2) & !(B.c:1 | A.c:2)";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn multi_auth_complex_fail() {
    let user_attrs = vec!["A.a:2", "A.c:1", "B.c:2"];
    let policy = "A.a:0 | (!A.b:0 & A.a:2) & !(A.c:1 | A.c:2)";
    assert_decryption_fail(user_attrs, policy);
}

// Auto-generated test cases

#[test]
fn generated_test_case_000_ok() {
    let user_attrs = vec!["C.a:6"];
    let policy = "(B.a:0 | C.a:6)";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_000_fail() {
    let user_attrs = vec![];
    let policy = "(B.a:0 | C.a:6)";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_001_ok() {
    let user_attrs = vec!["D.c:1"];
    let policy = "(D.c:1 | (A.e:5 & B.b:2))";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_001_fail() {
    let user_attrs = vec![];
    let policy = "(D.c:1 | (A.e:5 & B.b:2))";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_002_ok() {
    let user_attrs = vec!["D.e:0"];
    let policy = "(A.e:6 | D.e:0)";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_002_fail() {
    let user_attrs = vec![];
    let policy = "(A.e:6 | D.e:0)";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_003_ok() {
    let user_attrs = vec!["B.a:3"];
    let policy = "B.a:3";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_003_fail() {
    let user_attrs = vec![];
    let policy = "B.a:3";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_004_ok() {
    let user_attrs = vec!["A.a:0", "B.d:1", "A.d:5_00", "A.d:5_01", "A.d:5_02"];
    let policy = "(!B.c:0 | ((A.a:0 & B.d:1) & (((B.d:5 | (A.d:5 & (C.a:1 | ((B.a:3 & (C.c:2 & A.a:5)) | C.b:2)))) | C.c:1) | !A.d:5)))";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_004_fail() {
    let user_attrs = vec!["A.a:0", "A.d:5_01"];
    let policy = "(!B.c:0 | ((A.a:0 & B.d:1) & (((B.d:5 | (A.d:5 & (C.a:1 | ((B.a:3 & (C.c:2 & A.a:5)) | C.b:2)))) | C.c:1) | !A.d:5)))";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_005_ok() {
    let user_attrs = vec!["B.d:0"];
    let policy = "(B.d:0 | D.a:6)";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_005_fail() {
    let user_attrs = vec![];
    let policy = "(B.d:0 | D.a:6)";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_006_ok() {
    let user_attrs = vec!["C.a:5"];
    let policy = "(C.a:5 | ((!A.c:2 & C.a:0) & (D.b:0 | (C.a:0 | ((C.b:0 & B.a:1) & A.c:1)))))";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_006_fail() {
    let user_attrs = vec![];
    let policy = "(C.a:5 | ((!A.c:2 & C.a:0) & (D.b:0 | (C.a:0 | ((C.b:0 & B.a:1) & A.c:1)))))";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_007_ok() {
    let user_attrs = vec!["B.c:0"];
    let policy = "(B.c:0 | ((C.a:6 | A.d:2) | (B.d:6 & B.a:2)))";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_007_fail() {
    let user_attrs = vec![];
    let policy = "(B.c:0 | ((C.a:6 | A.d:2) | (B.d:6 & B.a:2)))";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_008_ok() {
    let user_attrs = vec!["A.c:2"];
    let policy = "((!C.a:3 | (!D.b:2 & ((D.e:6 | (A.e:6 & (D.a:1 | (B.a:4 | A.d:4)))) & D.e:1))) | (D.c:1 | A.c:2))";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_008_fail() {
    let user_attrs = vec![];
    let policy = "((!C.a:3 | (!D.b:2 & ((D.e:6 | (A.e:6 & (D.a:1 | (B.a:4 | A.d:4)))) & D.e:1))) | (D.c:1 | A.c:2))";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_009_ok() {
    let user_attrs = vec!["C.d:0", "A.e:0"];
    let policy = "((B.c:0 & C.e:5) | (C.d:0 & A.e:0))";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_009_fail() {
    let user_attrs = vec!["C.d:0"];
    let policy = "((B.c:0 & C.e:5) | (C.d:0 & A.e:0))";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_010_ok() {
    let user_attrs = vec!["D.b:5_00", "D.b:5_01", "D.b:5_02", "D.b:5_03"];
    let policy = "!D.b:5";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_010_fail() {
    let user_attrs = vec![];
    let policy = "!D.b:5";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_011_ok() {
    let user_attrs = vec!["D.b:6", "D.d:2_00", "C.c:3"];
    let policy = "((D.b:6 & !D.d:2) & C.c:3)";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_011_fail() {
    let user_attrs = vec!["C.c:3", "D.d:2_00"];
    let policy = "((D.b:6 & !D.d:2) & C.c:3)";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_012_ok() {
    let user_attrs = vec![
        "C.b:4_00", "C.b:4_01", "D.a:0", "A.d:6", "A.e:4_00", "A.e:4_01", "A.e:4_02", "A.e:4_03",
    ];
    let policy = "((!C.b:4 & (D.b:6 | (D.a:0 & A.d:6))) & !A.e:4)";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_012_fail() {
    let user_attrs = vec![
        "A.d:6", "A.e:4_00", "A.e:4_03", "A.e:4_02", "C.b:4_01", "A.e:4_01",
    ];
    let policy = "((!C.b:4 & (D.b:6 | (D.a:0 & A.d:6))) & !A.e:4)";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_013_ok() {
    let user_attrs = vec![
        "B.d:6", "C.b:4", "A.e:1", "D.b:5_00", "D.b:5_01", "D.b:5_02", "D.b:5_03",
    ];
    let policy = "(B.d:6 & (C.b:4 & ((C.d:6 | ((A.e:1 | C.c:0) & !D.b:5)) | B.a:2)))";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_013_fail() {
    let user_attrs = vec!["A.e:1", "B.d:6", "D.b:5_01"];
    let policy = "(B.d:6 & (C.b:4 & ((C.d:6 | ((A.e:1 | C.c:0) & !D.b:5)) | B.a:2)))";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_014_ok() {
    let user_attrs = vec!["D.b:6"];
    let policy = "(D.b:6 | ((((A.b:1 | D.c:6) | B.b:6) | B.a:1) & D.d:2))";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_014_fail() {
    let user_attrs = vec![];
    let policy = "(D.b:6 | ((((A.b:1 | D.c:6) | B.b:6) | B.a:1) & D.d:2))";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_015_ok() {
    let user_attrs = vec!["B.d:5", "A.e:5", "C.c:5", "A.c:5", "D.d:3", "B.d:0"];
    let policy = "((((A.d:0 | (B.d:4 | D.c:6)) | B.d:5) & (A.e:5 & ((C.c:5 & (A.c:5 & D.d:3)) | A.d:3))) & B.d:0)";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_015_fail() {
    let user_attrs = vec!["B.d:5", "C.c:5", "A.c:5", "B.d:0", "A.e:5"];
    let policy = "((((A.d:0 | (B.d:4 | D.c:6)) | B.d:5) & (A.e:5 & ((C.c:5 & (A.c:5 & D.d:3)) | A.d:3))) & B.d:0)";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_016_ok() {
    let user_attrs = vec![
        "C.e:5_00", "C.e:5_01", "C.e:5_02", "A.d:2_00", "A.d:2_01", "A.d:2_02",
    ];
    let policy =
        "(!C.e:5 & (((B.a:4 | ((D.e:4 & ((D.b:0 | A.a:3) | C.c:5)) | B.b:5)) & D.a:6) | !A.d:2))";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_016_fail() {
    let user_attrs = vec!["C.e:5_02", "C.e:5_01"];
    let policy =
        "(!C.e:5 & (((B.a:4 | ((D.e:4 & ((D.b:0 | A.a:3) | C.c:5)) | B.b:5)) & D.a:6) | !A.d:2))";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_017_ok() {
    let user_attrs = vec!["D.e:6"];
    let policy = "(C.b:0 | (D.c:5 | D.e:6))";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_017_fail() {
    let user_attrs = vec![];
    let policy = "(C.b:0 | (D.c:5 | D.e:6))";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_018_ok() {
    let user_attrs = vec!["B.d:3_00", "B.d:3_01", "B.d:3_02", "B.d:3_03"];
    let policy = "!B.d:3";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_018_fail() {
    let user_attrs = vec![];
    let policy = "!B.d:3";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_019_ok() {
    let user_attrs = vec!["A.b:4", "D.c:5", "C.d:5", "B.c:2"];
    let policy = "((((A.b:4 & D.c:5) & C.d:5) & B.c:2) | A.e:0)";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_019_fail() {
    let user_attrs = vec!["A.b:4", "D.c:5", "C.d:5"];
    let policy = "((((A.b:4 & D.c:5) & C.d:5) & B.c:2) | A.e:0)";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_020_ok() {
    let user_attrs = vec!["B.a:0"];
    let policy = "B.a:0";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_020_fail() {
    let user_attrs = vec![];
    let policy = "B.a:0";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_021_ok() {
    let user_attrs = vec!["A.a:0_00"];
    let policy = "((B.b:6 | !A.a:0) | (B.a:0 & B.e:4))";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_021_fail() {
    let user_attrs = vec![];
    let policy = "((B.b:6 | !A.a:0) | (B.a:0 & B.e:4))";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_022_ok() {
    let user_attrs = vec!["C.d:4"];
    let policy = "C.d:4";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_022_fail() {
    let user_attrs = vec![];
    let policy = "C.d:4";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_023_ok() {
    let user_attrs = vec!["B.c:5", "C.b:0"];
    let policy = "((B.c:5 | (D.a:4 & (!B.c:2 | (C.c:0 & (C.d:5 | D.e:1))))) & C.b:0)";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_023_fail() {
    let user_attrs = vec!["B.c:5"];
    let policy = "((B.c:5 | (D.a:4 & (!B.c:2 | (C.c:0 & (C.d:5 | D.e:1))))) & C.b:0)";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_024_ok() {
    let user_attrs = vec!["D.b:0"];
    let policy = "(B.e:6 | D.b:0)";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_024_fail() {
    let user_attrs = vec![];
    let policy = "(B.e:6 | D.b:0)";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_025_ok() {
    let user_attrs = vec!["C.c:1", "B.b:1", "D.a:3", "C.d:0"];
    let policy = "((C.c:1 & (B.b:1 & D.a:3)) & (C.d:0 | A.e:5))";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_025_fail() {
    let user_attrs = vec!["C.c:1", "C.d:0", "B.b:1"];
    let policy = "((C.c:1 & (B.b:1 & D.a:3)) & (C.d:0 | A.e:5))";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_026_ok() {
    let user_attrs = vec![
        "C.e:2", "D.a:5_00", "D.a:5_01", "D.a:1_00", "D.a:1_01", "D.a:1_02", "D.a:1_03",
    ];
    let policy = "((C.e:2 | !D.c:2) & (!D.a:5 & ((!D.a:1 | (C.a:0 | (B.a:0 | (A.e:3 | (D.b:3 & !A.c:5))))) | B.b:5)))";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_026_fail() {
    let user_attrs = vec!["D.a:1_03", "D.a:1_02", "D.a:5_01", "D.a:5_00", "D.a:1_00"];
    let policy = "((C.e:2 | !D.c:2) & (!D.a:5 & ((!D.a:1 | (C.a:0 | (B.a:0 | (A.e:3 | (D.b:3 & !A.c:5))))) | B.b:5)))";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_027_ok() {
    let user_attrs = vec!["C.b:4", "D.e:6"];
    let policy = "(C.b:4 & (D.e:6 | (!B.c:6 | D.d:1)))";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_027_fail() {
    let user_attrs = vec!["C.b:4"];
    let policy = "(C.b:4 & (D.e:6 | (!B.c:6 | D.d:1)))";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_028_ok() {
    let user_attrs = vec!["D.c:5"];
    let policy = "((A.d:1 & (B.e:6 & A.d:5)) | D.c:5)";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_028_fail() {
    let user_attrs = vec![];
    let policy = "((A.d:1 & (B.e:6 & A.d:5)) | D.c:5)";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_029_ok() {
    let user_attrs = vec!["C.e:6"];
    let policy = "C.e:6";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_029_fail() {
    let user_attrs = vec![];
    let policy = "C.e:6";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_030_ok() {
    let user_attrs = vec!["B.b:2", "A.d:2", "A.c:6"];
    let policy = "(((B.e:4 | D.c:3) & !A.a:0) | ((B.b:2 & (A.d:2 | A.d:0)) & A.c:6))";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_030_fail() {
    let user_attrs = vec![];
    let policy = "(((B.e:4 | D.c:3) & !A.a:0) | ((B.b:2 & (A.d:2 | A.d:0)) & A.c:6))";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_031_ok() {
    let user_attrs = vec!["A.a:4"];
    let policy = "A.a:4";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_031_fail() {
    let user_attrs = vec![];
    let policy = "A.a:4";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_032_ok() {
    let user_attrs = vec!["A.c:5"];
    let policy = "(((A.b:4 | (C.c:6 | (C.b:3 | B.c:4))) & B.e:4) | (A.c:5 | !C.e:0))";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_032_fail() {
    let user_attrs = vec![];
    let policy = "(((A.b:4 | (C.c:6 | (C.b:3 | B.c:4))) & B.e:4) | (A.c:5 | !C.e:0))";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_033_ok() {
    let user_attrs = vec!["C.a:2", "A.a:4", "D.a:1"];
    let policy = "((C.a:2 & A.a:4) & D.a:1)";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_033_fail() {
    let user_attrs = vec!["A.a:4", "D.a:1"];
    let policy = "((C.a:2 & A.a:4) & D.a:1)";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_034_ok() {
    let user_attrs = vec!["A.b:6_00", "A.b:6_01", "A.b:6_02", "B.c:0", "A.c:2"];
    let policy = "(((!A.b:6 & (((B.d:6 & B.a:6) & !D.c:0) | B.c:0)) & A.c:2) | (C.b:2 & C.e:3))";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_034_fail() {
    let user_attrs = vec!["A.b:6_00", "B.c:0", "A.b:6_01", "A.b:6_02"];
    let policy = "(((!A.b:6 & (((B.d:6 & B.a:6) & !D.c:0) | B.c:0)) & A.c:2) | (C.b:2 & C.e:3))";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_035_ok() {
    let user_attrs = vec!["A.d:2_00", "A.d:2_01", "A.d:2_02"];
    let policy = "!A.d:2";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_035_fail() {
    let user_attrs = vec![];
    let policy = "!A.d:2";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_036_ok() {
    let user_attrs = vec!["D.d:1", "D.d:6_00", "D.d:6_01"];
    let policy = "((D.d:1 & (!D.d:3 | !D.d:6)) | D.a:4)";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_036_fail() {
    let user_attrs = vec!["D.d:6_01"];
    let policy = "((D.d:1 & (!D.d:3 | !D.d:6)) | D.a:4)";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_037_ok() {
    let user_attrs = vec!["A.e:3"];
    let policy = "((!D.c:1 | D.c:2) | A.e:3)";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_037_fail() {
    let user_attrs = vec![];
    let policy = "((!D.c:1 | D.c:2) | A.e:3)";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_038_ok() {
    let user_attrs = vec!["D.c:4_00", "D.c:4_01", "D.c:4_02"];
    let policy = "!D.c:4";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_038_fail() {
    let user_attrs = vec![];
    let policy = "!D.c:4";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_039_ok() {
    let user_attrs = vec!["D.a:6", "A.b:6"];
    let policy = "(D.a:6 & A.b:6)";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_039_fail() {
    let user_attrs = vec!["A.b:6"];
    let policy = "(D.a:6 & A.b:6)";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_040_ok() {
    let user_attrs = vec!["B.d:6", "A.d:2", "D.c:4"];
    let policy = "((B.d:6 & (A.d:2 & D.c:4)) | ((!A.e:1 | (B.e:1 | B.a:2)) & A.a:6))";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_040_fail() {
    let user_attrs = vec!["D.c:4", "A.d:2"];
    let policy = "((B.d:6 & (A.d:2 & D.c:4)) | ((!A.e:1 | (B.e:1 | B.a:2)) & A.a:6))";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_041_ok() {
    let user_attrs = vec!["D.e:1"];
    let policy = "(((B.b:5 & A.b:5) & ((B.c:0 | B.a:1) | C.a:1)) | D.e:1)";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_041_fail() {
    let user_attrs = vec![];
    let policy = "(((B.b:5 & A.b:5) & ((B.c:0 | B.a:1) | C.a:1)) | D.e:1)";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_042_ok() {
    let user_attrs = vec!["A.b:6"];
    let policy = "(A.b:6 | (A.b:3 & ((((D.e:4 & B.e:4) | A.b:4) & !D.e:5) & C.b:1)))";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_042_fail() {
    let user_attrs = vec![];
    let policy = "(A.b:6 | (A.b:3 & ((((D.e:4 & B.e:4) | A.b:4) & !D.e:5) & C.b:1)))";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_043_ok() {
    let user_attrs = vec!["B.b:1", "A.a:5", "B.a:0"];
    let policy = "(B.b:1 & (A.a:5 & ((!A.a:3 | B.a:0) | D.a:4)))";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_043_fail() {
    let user_attrs = vec!["B.b:1", "B.a:0"];
    let policy = "(B.b:1 & (A.a:5 & ((!A.a:3 | B.a:0) | D.a:4)))";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_044_ok() {
    let user_attrs = vec!["B.d:0", "D.e:0", "A.c:6"];
    let policy = "((!B.d:0 & A.c:2) | ((B.d:0 & D.e:0) & A.c:6))";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_044_fail() {
    let user_attrs = vec!["A.c:6", "D.e:0"];
    let policy = "((!B.d:0 & A.c:2) | ((B.d:0 & D.e:0) & A.c:6))";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_045_ok() {
    let user_attrs = vec!["B.b:4"];
    let policy = "(((!C.e:6 | (!B.e:2 & (B.c:3 & D.e:6))) | (A.b:0 | B.b:4)) | C.c:4)";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_045_fail() {
    let user_attrs = vec![];
    let policy = "(((!C.e:6 | (!B.e:2 & (B.c:3 & D.e:6))) | (A.b:0 | B.b:4)) | C.c:4)";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_046_ok() {
    let user_attrs = vec![
        "D.c:5_00", "B.e:5", "C.a:3", "A.c:0_00", "A.c:0_01", "D.e:1", "D.d:6",
    ];
    let policy =
        "((!D.c:5 & (B.e:5 & (C.a:3 & ((!A.c:0 & D.e:1) | A.b:1)))) & (D.d:6 | (A.a:6 | D.b:5)))";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_046_fail() {
    let user_attrs = vec![
        "D.d:6", "D.c:5_00", "A.c:0_00", "A.c:0_01", "C.a:3", "B.e:5",
    ];
    let policy =
        "((!D.c:5 & (B.e:5 & (C.a:3 & ((!A.c:0 & D.e:1) | A.b:1)))) & (D.d:6 | (A.a:6 | D.b:5)))";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_047_ok() {
    let user_attrs = vec!["C.a:2", "B.b:2"];
    let policy = "(C.a:2 & B.b:2)";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_047_fail() {
    let user_attrs = vec!["B.b:2"];
    let policy = "(C.a:2 & B.b:2)";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_048_ok() {
    let user_attrs = vec!["A.b:5", "A.a:2_00", "A.a:2_01"];
    let policy = "(((((!C.b:0 & ((((B.e:2 | !B.a:4) | C.e:2) & D.b:3) | A.b:0)) | A.b:5) | C.d:2) & (!A.a:2 | D.a:3)) | D.c:1)";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_048_fail() {
    let user_attrs = vec!["A.a:2_00", "A.a:2_01"];
    let policy = "(((((!C.b:0 & ((((B.e:2 | !B.a:4) | C.e:2) & D.b:3) | A.b:0)) | A.b:5) | C.d:2) & (!A.a:2 | D.a:3)) | D.c:1)";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_049_ok() {
    let user_attrs = vec![
        "D.b:0_00", "D.b:0_01", "D.b:0_02", "D.b:0_03", "A.e:6_00", "A.e:6_01",
    ];
    let policy = "((!D.b:0 & (C.b:3 | (!A.e:6 | D.b:5))) | D.e:0)";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_049_fail() {
    let user_attrs = vec![];
    let policy = "((!D.b:0 & (C.b:3 | (!A.e:6 | D.b:5))) | D.e:0)";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_050_ok() {
    let user_attrs = vec!["D.e:0", "C.c:4", "A.c:5", "C.d:5", "B.a:1"];
    let policy = "((D.e:0 & (((((A.c:4 & ((!A.c:5 | (((C.e:6 & !B.a:0) | A.d:4) | A.b:6)) | D.d:1)) | C.c:4) | !D.e:2) & A.c:5) & C.d:5)) & B.a:1)";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_050_fail() {
    let user_attrs = vec!["C.d:5", "B.a:1", "D.e:0", "C.c:4"];
    let policy = "((D.e:0 & (((((A.c:4 & ((!A.c:5 | (((C.e:6 & !B.a:0) | A.d:4) | A.b:6)) | D.d:1)) | C.c:4) | !D.e:2) & A.c:5) & C.d:5)) & B.a:1)";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_051_ok() {
    let user_attrs = vec!["A.b:5", "D.c:6"];
    let policy = "(((A.b:1 | A.b:5) & D.c:6) | ((B.b:6 & !C.e:4) & D.e:0))";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_051_fail() {
    let user_attrs = vec!["A.b:5"];
    let policy = "(((A.b:1 | A.b:5) & D.c:6) | ((B.b:6 & !C.e:4) & D.e:0))";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_052_ok() {
    let user_attrs = vec!["D.b:2"];
    let policy = "D.b:2";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_052_fail() {
    let user_attrs = vec![];
    let policy = "D.b:2";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_053_ok() {
    let user_attrs = vec![
        "D.e:2_00", "B.e:4_00", "B.e:4_01", "B.e:4_02", "D.e:3", "B.e:1",
    ];
    let policy = "(((!D.e:2 & (!B.e:4 | !D.a:0)) & D.e:3) & B.e:1)";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_053_fail() {
    let user_attrs = vec!["D.e:2_00", "B.e:4_02", "B.e:1", "B.e:4_01"];
    let policy = "(((!D.e:2 & (!B.e:4 | !D.a:0)) & D.e:3) & B.e:1)";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_054_ok() {
    let user_attrs = vec!["B.b:3", "D.a:1", "C.b:5_00", "D.a:4", "D.e:3", "C.e:1_00"];
    let policy = "(B.b:3 & (((D.a:1 & ((((B.a:3 | A.d:3) & B.d:6) & !B.b:5) | !C.b:5)) | A.b:1) & ((D.a:4 & D.e:3) & !C.e:1)))";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_054_fail() {
    let user_attrs = vec!["B.b:3", "D.a:1", "C.e:1_00", "D.a:4", "C.b:5_00"];
    let policy = "(B.b:3 & (((D.a:1 & ((((B.a:3 | A.d:3) & B.d:6) & !B.b:5) | !C.b:5)) | A.b:1) & ((D.a:4 & D.e:3) & !C.e:1)))";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_055_ok() {
    let user_attrs = vec!["B.c:0", "C.e:6"];
    let policy = "((B.c:0 & C.e:6) | (B.c:3 | C.a:2))";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_055_fail() {
    let user_attrs = vec!["C.e:6"];
    let policy = "((B.c:0 & C.e:6) | (B.c:3 | C.a:2))";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_056_ok() {
    let user_attrs = vec!["B.e:1", "B.a:6"];
    let policy = "((B.e:1 & (A.e:3 | B.a:6)) | D.c:0)";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_056_fail() {
    let user_attrs = vec!["B.e:1"];
    let policy = "((B.e:1 & (A.e:3 | B.a:6)) | D.c:0)";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_057_ok() {
    let user_attrs = vec!["B.a:0", "D.d:0", "C.b:6", "C.c:2"];
    let policy = "((B.a:0 & ((D.d:0 & C.b:6) & C.c:2)) | B.a:6)";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_057_fail() {
    let user_attrs = vec!["B.a:0", "D.d:0", "C.c:2"];
    let policy = "((B.a:0 & ((D.d:0 & C.b:6) & C.c:2)) | B.a:6)";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_058_ok() {
    let user_attrs = vec!["A.d:3_00", "A.d:3_01", "B.c:1", "D.e:3", "B.e:3", "B.c:4"];
    let policy = "(!A.d:3 & (((B.c:1 & (D.e:3 & (((A.b:3 | B.d:1) & D.c:2) | B.e:3))) & B.c:4) | (C.c:4 | B.e:6)))";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_058_fail() {
    let user_attrs = vec!["D.e:3", "B.c:4", "B.e:3", "A.d:3_01"];
    let policy = "(!A.d:3 & (((B.c:1 & (D.e:3 & (((A.b:3 | B.d:1) & D.c:2) | B.e:3))) & B.c:4) | (C.c:4 | B.e:6)))";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_059_ok() {
    let user_attrs = vec!["A.e:4"];
    let policy = "A.e:4";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_059_fail() {
    let user_attrs = vec![];
    let policy = "A.e:4";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_060_ok() {
    let user_attrs = vec!["B.e:6_00", "B.e:6_01", "B.e:6_02", "A.a:4", "B.e:1"];
    let policy = "(A.b:3 | (!B.e:6 & (A.a:4 & (B.d:3 | B.e:1))))";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_060_fail() {
    let user_attrs = vec!["B.e:6_02", "B.e:1"];
    let policy = "(A.b:3 | (!B.e:6 & (A.a:4 & (B.d:3 | B.e:1))))";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_061_ok() {
    let user_attrs = vec!["D.d:5"];
    let policy = "D.d:5";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_061_fail() {
    let user_attrs = vec![];
    let policy = "D.d:5";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_062_ok() {
    let user_attrs = vec!["D.c:6"];
    let policy = "D.c:6";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_062_fail() {
    let user_attrs = vec![];
    let policy = "D.c:6";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_063_ok() {
    let user_attrs = vec!["A.c:6", "A.c:5", "D.a:2", "D.d:4", "A.c:1", "C.c:3"];
    let policy = "(((A.c:6 & A.c:5) & (D.a:2 & (D.d:4 & A.c:1))) & C.c:3)";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_063_fail() {
    let user_attrs = vec!["D.d:4", "A.c:1", "D.a:2", "A.c:5", "C.c:3"];
    let policy = "(((A.c:6 & A.c:5) & (D.a:2 & (D.d:4 & A.c:1))) & C.c:3)";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_064_ok() {
    let user_attrs = vec!["C.d:1_00", "C.d:1_01", "C.d:1_02", "A.c:0"];
    let policy = "((!C.d:1 | A.c:5) & A.c:0)";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_064_fail() {
    let user_attrs = vec!["A.c:0"];
    let policy = "((!C.d:1 | A.c:5) & A.c:0)";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_065_ok() {
    let user_attrs = vec!["D.a:5", "A.b:4"];
    let policy = "(B.e:6 | ((B.a:5 | (((C.d:0 | A.b:1) | D.a:5) & A.b:4)) | (D.d:0 & !C.d:1)))";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_065_fail() {
    let user_attrs = vec!["D.a:5"];
    let policy = "(B.e:6 | ((B.a:5 | (((C.d:0 | A.b:1) | D.a:5) & A.b:4)) | (D.d:0 & !C.d:1)))";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_066_ok() {
    let user_attrs = vec![
        "C.a:1_00", "C.a:1_01", "C.a:1_02", "A.d:6", "C.c:6", "B.a:4", "A.a:2", "A.c:6_00",
        "A.c:6_01",
    ];
    let policy = "((!C.a:1 & (A.d:6 & (C.c:6 & ((B.a:4 | D.e:2) & A.a:2)))) & !A.c:6)";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_066_fail() {
    let user_attrs = vec![
        "A.c:6_01", "B.a:4", "C.a:1_02", "C.c:6", "C.a:1_01", "A.c:6_00", "A.a:2",
    ];
    let policy = "((!C.a:1 & (A.d:6 & (C.c:6 & ((B.a:4 | D.e:2) & A.a:2)))) & !A.c:6)";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_067_ok() {
    let user_attrs = vec!["D.d:6_00", "D.d:6_01", "D.d:6_02", "D.d:6_03", "C.a:3"];
    let policy = "(!D.d:6 & C.a:3)";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_067_fail() {
    let user_attrs = vec!["D.d:6_00", "D.d:6_03"];
    let policy = "(!D.d:6 & C.a:3)";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_068_ok() {
    let user_attrs = vec!["A.b:4_00"];
    let policy = "(!A.b:4 | C.a:4)";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_068_fail() {
    let user_attrs = vec![];
    let policy = "(!A.b:4 | C.a:4)";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_069_ok() {
    let user_attrs = vec!["B.c:1"];
    let policy = "B.c:1";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_069_fail() {
    let user_attrs = vec![];
    let policy = "B.c:1";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_070_ok() {
    let user_attrs = vec!["B.a:5_00", "B.a:5_01", "B.a:5_02", "A.c:4", "B.e:3_00"];
    let policy = "(!B.a:5 & (A.c:4 & (((D.d:6 | D.b:0) | A.e:4) | !B.e:3)))";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_070_fail() {
    let user_attrs = vec!["B.a:5_01", "B.e:3_00", "B.a:5_00"];
    let policy = "(!B.a:5 & (A.c:4 & (((D.d:6 | D.b:0) | A.e:4) | !B.e:3)))";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_071_ok() {
    let user_attrs = vec![
        "B.e:3_00", "B.e:3_01", "B.e:3_02", "B.e:3_03", "B.c:3", "C.d:1",
    ];
    let policy = "(!B.e:3 & (B.c:3 & (C.a:1 | C.d:1)))";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_071_fail() {
    let user_attrs = vec!["B.e:3_02", "B.e:3_03", "C.d:1"];
    let policy = "(!B.e:3 & (B.c:3 & (C.a:1 | C.d:1)))";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_072_ok() {
    let user_attrs = vec!["A.a:6", "A.a:2"];
    let policy = "((((A.c:6 | A.a:6) | !B.d:5) & A.a:2) | (B.c:0 & B.b:3))";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_072_fail() {
    let user_attrs = vec!["A.a:2"];
    let policy = "((((A.c:6 | A.a:6) | !B.d:5) & A.a:2) | (B.c:0 & B.b:3))";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_073_ok() {
    let user_attrs = vec!["A.c:3"];
    let policy = "A.c:3";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_073_fail() {
    let user_attrs = vec![];
    let policy = "A.c:3";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_074_ok() {
    let user_attrs = vec!["C.c:4"];
    let policy = "(((D.d:6 & ((D.c:1 | B.c:1) | C.d:0)) & C.b:1) | (C.c:4 | A.c:3))";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_074_fail() {
    let user_attrs = vec![];
    let policy = "(((D.d:6 & ((D.c:1 | B.c:1) | C.d:0)) & C.b:1) | (C.c:4 | A.c:3))";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_075_ok() {
    let user_attrs = vec!["B.c:6"];
    let policy = "(B.c:6 | !A.e:0)";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_075_fail() {
    let user_attrs = vec![];
    let policy = "(B.c:6 | !A.e:0)";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_076_ok() {
    let user_attrs = vec!["A.d:4", "B.c:6", "B.e:3", "C.d:4"];
    let policy = "(((((C.d:1 & D.d:1) | B.a:1) | A.d:4) & (B.c:6 & B.e:3)) & C.d:4)";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_076_fail() {
    let user_attrs = vec!["C.d:4", "B.e:3", "A.d:4"];
    let policy = "(((((C.d:1 & D.d:1) | B.a:1) | A.d:4) & (B.c:6 & B.e:3)) & C.d:4)";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_077_ok() {
    let user_attrs = vec!["D.c:0"];
    let policy = "(D.c:0 | (B.a:0 & (C.a:5 & ((!B.d:6 | !A.c:1) | !D.d:2))))";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_077_fail() {
    let user_attrs = vec![];
    let policy = "(D.c:0 | (B.a:0 & (C.a:5 & ((!B.d:6 | !A.c:1) | !D.d:2))))";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_078_ok() {
    let user_attrs = vec!["D.c:4_00", "D.c:4_01", "D.c:4_02", "D.c:4_03"];
    let policy = "((B.a:6 | (!D.c:4 | A.d:6)) | !B.b:6)";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_078_fail() {
    let user_attrs = vec![];
    let policy = "((B.a:6 | (!D.c:4 | A.d:6)) | !B.b:6)";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_079_ok() {
    let user_attrs = vec![
        "A.c:4", "D.d:0_00", "D.d:0_01", "D.d:0_02", "D.d:0_03", "A.a:4",
    ];
    let policy = "((A.c:4 & !D.d:0) & A.a:4)";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_079_fail() {
    let user_attrs = vec!["D.d:0_02", "A.c:4", "D.d:0_01", "D.d:0_00", "D.d:0_03"];
    let policy = "((A.c:4 & !D.d:0) & A.a:4)";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_080_ok() {
    let user_attrs = vec!["C.b:3", "D.a:0_00"];
    let policy = "(C.b:3 & (!D.a:0 | B.b:5))";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_080_fail() {
    let user_attrs = vec!["D.a:0_00"];
    let policy = "(C.b:3 & (!D.a:0 | B.b:5))";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_081_ok() {
    let user_attrs = vec!["A.a:2_00"];
    let policy = "(!A.a:2 | (((!D.d:4 | (C.b:3 | (D.e:1 | B.a:2))) & C.a:4) | D.d:4))";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_081_fail() {
    let user_attrs = vec![];
    let policy = "(!A.a:2 | (((!D.d:4 | (C.b:3 | (D.e:1 | B.a:2))) & C.a:4) | D.d:4))";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_082_ok() {
    let user_attrs = vec!["D.b:1", "C.a:4"];
    let policy = "((D.b:1 & C.a:4) | (B.e:6 & (A.d:3 & !C.d:5)))";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_082_fail() {
    let user_attrs = vec!["D.b:1"];
    let policy = "((D.b:1 & C.a:4) | (B.e:6 & (A.d:3 & !C.d:5)))";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_083_ok() {
    let user_attrs = vec!["D.b:3"];
    let policy = "D.b:3";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_083_fail() {
    let user_attrs = vec![];
    let policy = "D.b:3";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_084_ok() {
    let user_attrs = vec!["A.b:4"];
    let policy = "A.b:4";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_084_fail() {
    let user_attrs = vec![];
    let policy = "A.b:4";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_085_ok() {
    let user_attrs = vec!["D.d:2", "D.d:1"];
    let policy = "((B.d:3 & !B.d:1) | (D.d:2 & D.d:1))";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_085_fail() {
    let user_attrs = vec!["D.d:2"];
    let policy = "((B.d:3 & !B.d:1) | (D.d:2 & D.d:1))";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_086_ok() {
    let user_attrs = vec!["B.e:5_00", "B.e:5_01", "B.e:5_02"];
    let policy = "!B.e:5";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_086_fail() {
    let user_attrs = vec![];
    let policy = "!B.e:5";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_087_ok() {
    let user_attrs = vec!["D.e:5"];
    let policy = "D.e:5";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_087_fail() {
    let user_attrs = vec![];
    let policy = "D.e:5";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_088_ok() {
    let user_attrs = vec!["D.e:1"];
    let policy = "D.e:1";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_088_fail() {
    let user_attrs = vec![];
    let policy = "D.e:1";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_089_ok() {
    let user_attrs = vec!["A.e:0", "B.a:3"];
    let policy = "((A.e:0 & B.a:3) | (C.c:6 & (A.c:0 & (!B.c:0 | B.d:0))))";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_089_fail() {
    let user_attrs = vec!["A.e:0"];
    let policy = "((A.e:0 & B.a:3) | (C.c:6 & (A.c:0 & (!B.c:0 | B.d:0))))";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_090_ok() {
    let user_attrs = vec!["A.c:4"];
    let policy = "A.c:4";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_090_fail() {
    let user_attrs = vec![];
    let policy = "A.c:4";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_091_ok() {
    let user_attrs = vec!["C.a:0", "A.b:1", "C.e:3"];
    let policy = "((C.a:0 | (C.d:5 | A.b:6)) & (A.b:1 & (C.e:3 | ((((C.a:1 & A.b:3) & A.d:5) | C.e:1) | C.a:5))))";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_091_fail() {
    let user_attrs = vec!["C.a:0", "A.b:1"];
    let policy = "((C.a:0 | (C.d:5 | A.b:6)) & (A.b:1 & (C.e:3 | ((((C.a:1 & A.b:3) & A.d:5) | C.e:1) | C.a:5))))";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_092_ok() {
    let user_attrs = vec!["C.a:1"];
    let policy = "((C.b:4 | C.a:1) | C.c:3)";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_092_fail() {
    let user_attrs = vec![];
    let policy = "((C.b:4 | C.a:1) | C.c:3)";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_093_ok() {
    let user_attrs = vec!["A.e:3"];
    let policy = "A.e:3";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_093_fail() {
    let user_attrs = vec![];
    let policy = "A.e:3";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_094_ok() {
    let user_attrs = vec!["A.a:6", "C.b:5", "C.e:5", "B.e:1", "A.a:6", "B.a:1"];
    let policy = "((((A.a:6 & (C.b:5 & C.e:5)) & B.e:1) & A.a:6) & ((B.a:1 | !C.b:2) | D.e:0))";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_094_fail() {
    let user_attrs = vec!["A.a:6", "A.a:6", "C.e:5", "C.b:5"];
    let policy = "((((A.a:6 & (C.b:5 & C.e:5)) & B.e:1) & A.a:6) & ((B.a:1 | !C.b:2) | D.e:0))";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_095_ok() {
    let user_attrs = vec!["A.d:3"];
    let policy = "((!B.e:1 | ((!A.b:2 | (D.b:0 | (A.e:4 & A.c:3))) | D.e:5)) | (A.d:3 | B.d:4))";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_095_fail() {
    let user_attrs = vec![];
    let policy = "((!B.e:1 | ((!A.b:2 | (D.b:0 | (A.e:4 & A.c:3))) | D.e:5)) | (A.d:3 | B.d:4))";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_096_ok() {
    let user_attrs = vec!["D.c:1"];
    let policy = "D.c:1";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_096_fail() {
    let user_attrs = vec![];
    let policy = "D.c:1";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_097_ok() {
    let user_attrs = vec!["C.d:0", "D.e:0", "B.b:5"];
    let policy = "(C.d:0 & ((D.e:0 & B.b:5) | B.b:3))";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_097_fail() {
    let user_attrs = vec!["D.e:0", "C.d:0"];
    let policy = "(C.d:0 & ((D.e:0 & B.b:5) | B.b:3))";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_098_ok() {
    let user_attrs = vec!["B.a:1"];
    let policy = "B.a:1";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_098_fail() {
    let user_attrs = vec![];
    let policy = "B.a:1";
    assert_decryption_fail(user_attrs, policy);
}

#[test]
fn generated_test_case_099_ok() {
    let user_attrs = vec![
        "C.a:0", "B.a:0", "A.c:3", "B.a:4_00", "B.a:4_01", "B.c:5", "A.c:5",
    ];
    let policy = "((C.a:0 & (((B.a:0 & A.c:3) & !B.a:4) & (B.c:5 & A.c:5))) | D.a:6)";
    assert_decryption_ok(user_attrs, policy);
}

#[test]
fn generated_test_case_099_fail() {
    let user_attrs = vec!["B.c:5", "B.a:4_01", "B.a:0", "A.c:5", "A.c:3", "B.a:4_00"];
    let policy = "((C.a:0 & (((B.a:0 & A.c:3) & !B.a:4) & (B.c:5 & A.c:5))) | D.a:6)";
    assert_decryption_fail(user_attrs, policy);
}
