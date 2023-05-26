//! Some utilities to calculate diff and nicify them

use std::collections::VecDeque;

/// Diff two texts line by line
///
/// The function returns a list of lines.
/// The bool marks if the lines are different (`true`) or the same (`false`).
/// The difference to [`diff::lines`] is that each block of changes is padded to the same lengths.
/// If `left` has many deletions, the `right` side will be filled with lines.
///
/// The padding lines are not empty, but contain the indention of the other side.
pub fn diff_lines<'a>(left: &'a str, right: &'a str) -> Vec<(bool, &'a str, &'a str)> {
    // Add a detailed diff between both results
    let mut lines = Vec::new();
    let diff = diff::lines(left, right);
    let mut deletions_buffer = VecDeque::new();
    for diffr in diff {
        match diffr {
            diff::Result::Left(del) => {
                deletions_buffer.push_back(del);
            }
            diff::Result::Right(ins) => {
                // If there is a previous deletion, we combine this `ins`ertion with it
                let del = deletions_buffer
                    .pop_front()
                    .unwrap_or_else(|| &ins[..get_indentation_level(ins)]);
                lines.push((true, del, ins));
            }
            diff::Result::Both(line, _) => {
                // There might be outstanding deletions which we have not mapped yet
                // They need to be printed first
                while let Some(del) = deletions_buffer.pop_front() {
                    lines.push((true, del, &del[..get_indentation_level(del)]));
                }
                lines.push((false, line, line));
            }
        }
    }
    // There might be outstanding deletions which we have not mapped yet
    // They need to be printed first
    while let Some(del) = deletions_buffer.pop_front() {
        lines.push((true, del, &del[..get_indentation_level(del)]));
    }
    lines
}

/// Return the indentation level as the number of ASCII whitespace characters
fn get_indentation_level(s: &str) -> usize {
    s.chars().take_while(|c| c.is_ascii_whitespace()).count()
}

/// Given a diff only keep the changed lines and the context lines
///
/// A diff here means a list of lines, which can either be identical (`false`) or different (`true`) between both sides.
/// The context lines are the lines before and after the changed lines, at each indentation level.
/// This allows to see what exactly the changed lines mean.
pub fn diff_with_context<'a>(diff: &[(bool, &'a str, &'a str)]) -> Vec<(bool, &'a str, &'a str)> {
    /// Same as outer function, but with more control over the behavior
    ///
    /// Each function instance is only responsible for handling one indentation level specified by `level`.
    /// `need_closing_line` indicates if the next line should be included in the output.
    /// It is set if the closing context is necessary.
    /// It needs to be a function argument, since the closing line might have an indentation level smaller than the changed line,
    /// but larger than the opening context.
    /// This leads to another recursive call, so this state needs to be passed on.
    #[allow(clippy::type_complexity)]
    fn inner<'a, 'b>(
        level: usize,
        mut need_closing_line: bool,
        mut diff: &'b [(bool, &'a str, &'a str)],
    ) -> (
        Vec<(bool, &'a str, &'a str)>,
        &'b [(bool, &'a str, &'a str)],
    ) {
        let mut changed_lines = Vec::new();
        let mut last_line = None;

        while let Some(&(changeline, left, right)) = diff.first() {
            match get_indentation_level(left).cmp(&level) {
                std::cmp::Ordering::Equal => {
                    // Consume the line since it is for the current level
                    diff = &diff[1..];
                    if changeline || need_closing_line {
                        changed_lines.push((changeline, left, right));
                        need_closing_line = false;
                        // We already marked the last line as being part of the set
                        // So we need to clear the entry here too, otherwise older last_lines might get emitted
                        last_line = None;
                    } else {
                        // last_line should not be set if the line is already added to the changed line set
                        // Otherwise it might be printed twice
                        last_line = Some((changeline, left, right));
                    }
                }
                std::cmp::Ordering::Greater => {
                    let (changed, newdiff) =
                        inner(get_indentation_level(left), need_closing_line, diff);
                    diff = newdiff;
                    if !changed.is_empty() {
                        if let Some(ll) = last_line.take() {
                            changed_lines.push(ll);
                        }
                        changed_lines.extend(changed);
                        need_closing_line = true;
                    }
                }
                std::cmp::Ordering::Less => break,
            }
        }

        (changed_lines, diff)
    }
    inner(0, false, diff).0
}

#[cfg(test)]
mod test {
    use super::*;

    static LEFT_1: &str = r#"
{
    ((
        a
    ))
    c
    [[[[
        1
        ]]]] // Test a closing line with a different indentation level
    (((((
        b // Test ending without removing all levels
"#;
    static RIGHT_1: &str = r#"
{
    ((
        a
    ))
    [[[
        2 // Test large addition on one side
    ]]]
    c
    [[[[
        22
        ]]]] // Test a closing line with a different indentation level
    (((((
        b // Test ending without removing all levels
"#;

    #[test]
    fn simple_diff() {
        let diff = diff_lines(LEFT_1, RIGHT_1);
        let expected = expect_test::expect![[r#"
            [
                (
                    false,
                    "",
                    "",
                ),
                (
                    false,
                    "{",
                    "{",
                ),
                (
                    false,
                    "    ((",
                    "    ((",
                ),
                (
                    false,
                    "        a",
                    "        a",
                ),
                (
                    false,
                    "    ))",
                    "    ))",
                ),
                (
                    true,
                    "    ",
                    "    [[[",
                ),
                (
                    true,
                    "        ",
                    "        2 // Test large addition on one side",
                ),
                (
                    true,
                    "    ",
                    "    ]]]",
                ),
                (
                    false,
                    "    c",
                    "    c",
                ),
                (
                    false,
                    "    [[[[",
                    "    [[[[",
                ),
                (
                    true,
                    "        1",
                    "        22",
                ),
                (
                    false,
                    "        ]]]] // Test a closing line with a different indentation level",
                    "        ]]]] // Test a closing line with a different indentation level",
                ),
                (
                    false,
                    "    (((((",
                    "    (((((",
                ),
                (
                    false,
                    "        b // Test ending without removing all levels",
                    "        b // Test ending without removing all levels",
                ),
                (
                    false,
                    "",
                    "",
                ),
            ]
        "#]];
        expected.assert_debug_eq(&diff);
    }

    #[test]
    fn simple_diff_with_context() {
        let diff = diff_lines(LEFT_1, RIGHT_1);
        let context_diff = diff_with_context(&diff);
        let expected = expect_test::expect![[r#"
            [
                (
                    false,
                    "{",
                    "{",
                ),
                (
                    true,
                    "    ",
                    "    [[[",
                ),
                (
                    true,
                    "        ",
                    "        2 // Test large addition on one side",
                ),
                (
                    true,
                    "    ",
                    "    ]]]",
                ),
                (
                    false,
                    "    [[[[",
                    "    [[[[",
                ),
                (
                    true,
                    "        1",
                    "        22",
                ),
                (
                    false,
                    "    (((((",
                    "    (((((",
                ),
                (
                    false,
                    "",
                    "",
                ),
            ]
        "#]];
        expected.assert_debug_eq(&context_diff);
    }
}
