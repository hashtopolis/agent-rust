//! A small fluent builder for a process argument list.
//!
//! Provides for a clean way to accept a variety of types without having
//! to do too much cloning ceremony at the call site.

#[derive(Debug, Default)]
pub(crate) struct Args {
    args: Vec<String>,
}

impl Args {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }

    pub(crate) fn args<I>(mut self, args: I) -> Self
    where
        I: IntoIterator,
        I::Item: Into<String>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    /// Append `arg` only when `condition` holds, so optional flags stay in the
    /// chain instead of breaking it with an `if`.
    pub(crate) fn arg_if(self, condition: bool, arg: impl Into<String>) -> Self {
        if condition { self.arg(arg) } else { self }
    }

    pub(crate) fn build(self) -> Vec<String> {
        self.args
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_insertion_order() {
        let args = Args::new().arg("--first").arg("--second").build();

        assert_eq!(args, ["--first", "--second"]);
    }

    #[test]
    fn accepts_borrowed_and_owned_singles() {
        let owned = String::from("--owned");

        let args = Args::new().arg("--borrowed").arg(owned).build();

        assert_eq!(args, ["--borrowed", "--owned"]);
    }

    #[test]
    fn extends_from_iterators_of_str_and_string() {
        let owned = vec![String::from("a"), String::from("b")];

        let args = Args::new()
            .args(["--flag", "value"])
            .args(owned)
            .args("x y".split_whitespace())
            .build();

        assert_eq!(args, ["--flag", "value", "a", "b", "x", "y"]);
    }

    #[test]
    fn arg_if_appends_only_when_true() {
        let with = Args::new().arg("-a").arg_if(true, "-S").arg("-b").build();
        let without = Args::new().arg("-a").arg_if(false, "-S").arg("-b").build();

        assert_eq!(with, ["-a", "-S", "-b"]);
        assert_eq!(without, ["-a", "-b"]);
    }

    #[test]
    fn empty_builder_yields_no_args() {
        assert!(Args::new().build().is_empty());
    }
}
