//! The shared nesting calibration shapes.
#![warn(clippy::excessive_nesting)]

/// S1: no control structure.
pub fn flat(x: i32) -> i32 {
    x + 1
}

/// S2: one control structure.
pub fn one_branch(x: i32) -> &'static str {
    if x == 0 { "zero" } else { "other" }
}

/// S3: a control structure inside one.
pub fn branch_in_branch(x: i32, y: i32) -> &'static str {
    if x == 0 {
        if y == 0 { "both" } else { "first_only" }
    } else {
        "neither"
    }
}

/// S4: three control structures deep.
pub fn three_deep(x: i32, y: i32, z: i32) -> &'static str {
    if x == 0 {
        if y == 0 {
            if z == 0 { "all" } else { "two" }
        } else {
            "one"
        }
    } else {
        "none"
    }
}

/// S5: a closure in the function body.
pub fn closure_in_body(xs: &[i32]) -> Vec<i32> {
    xs.iter().map(|x| x + 1).collect()
}

/// S6: a closure inside a branch.
pub fn closure_in_branch(xs: &[i32]) -> Vec<i32> {
    if xs.is_empty() {
        Vec::new()
    } else {
        xs.iter().map(|x| x + 1).collect()
    }
}

/// S7: a control structure inside a closure.
pub fn branch_in_closure(xs: &[i32]) -> Vec<&'static str> {
    xs.iter()
        .map(|x| if *x == 0 { "zero" } else { "other" })
        .collect()
}
