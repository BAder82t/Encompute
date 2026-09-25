//! Textual `.eir` form.
//!
//! ```text
//! encompute 0.1
//! program score precision 0.001
//! %0 = input "x" [-1.0, 1.0] : secret vector<3>
//! %1 = const [0.5, -0.25, 2.0] : public vector<3>
//! %2 = dot %1, %0 : secret scalar
//! %3 = sigmoid %2 : secret scalar
//! output "score" = %3
//! ```
//!
//! Types are printed for readability; the parser re-derives them and rejects
//! a mismatch. Floats print in Rust's shortest round-trip form, so
//! `parse(&p.to_string()) == p`. `#` starts a comment.

use std::fmt::{self, Write as _};

use crate::error::{Code, Error, Result};
use crate::program::{Builder, CmpOp, LogicOp, Op, Program};
use crate::types::{Elem, Range, Shape, Type, ValueId, Visibility};

const HEADER: &str = "encompute 0.1";
const _: () = assert!(HEADER.len() == "encompute ".len() + crate::IR_VERSION.len());

impl fmt::Display for Program {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{HEADER}")?;
        write!(
            f,
            "program {} precision {:?}",
            self.name(),
            self.precision()
        )?;
        // The default is not written, so receipt-only programs keep the
        // same text and program ID as before verified execution existed.
        if self.verification() != crate::program::Verification::Receipt {
            write!(f, " verification {}", self.verification().name())?;
        }
        writeln!(f)?;
        for (id, node) in self.iter() {
            write!(f, "{id} = {}", node.op.mnemonic())?;
            match &node.op {
                Op::Input { name, range } => {
                    write!(f, " \"{name}\" [{:?}, {:?}]", range.lo, range.hi)?
                }
                Op::Const { data } => write!(f, " {}", floats(data))?,
                Op::Poly { x, coeffs } => write!(f, " {x} {}", floats(coeffs))?,
                Op::Lookup { x, table } => write!(f, " {x} {}", floats(table))?,
                Op::Shift { x, by, .. } => write!(f, " {x} {by}")?,
                op => {
                    let ids: Vec<String> = op.operands().iter().map(ToString::to_string).collect();
                    write!(f, " {}", ids.join(", "))?;
                }
            }
            writeln!(f, " : {}", node.ty)?;
        }
        for o in self.outputs() {
            writeln!(f, "output \"{}\" = {}", o.name, o.value)?;
        }
        Ok(())
    }
}

fn floats(xs: &[f64]) -> String {
    let mut s = String::from("[");
    for (i, x) in xs.iter().enumerate() {
        if i > 0 {
            s.push_str(", ");
        }
        write!(s, "{x:?}").unwrap();
    }
    s.push(']');
    s
}

/// Parse the textual form produced by `Program`'s `Display`.
pub fn parse(src: &str) -> Result<Program> {
    let mut lines = src
        .lines()
        .enumerate()
        .map(|(i, l)| (i + 1, l.split('#').next().unwrap().trim()))
        .filter(|(_, l)| !l.is_empty());

    let (n, header) = lines.next().ok_or_else(|| err(1, "empty input"))?;
    if header != HEADER {
        return Err(err(n, format!("expected {HEADER:?}, got {header:?}")));
    }

    let (n, line) = lines
        .next()
        .ok_or_else(|| err(n, "missing `program` line"))?;
    let mut c = Cursor::new(n, line);
    c.keyword("program")?;
    let name = c.word()?;
    c.keyword("precision")?;
    let precision = c.float()?;
    c.skip_ws();
    let verification = if c.rest.is_empty() {
        crate::program::Verification::Receipt
    } else {
        c.keyword("verification")?;
        match crate::program::Verification::parse(&c.word()?) {
            // Only the non-default mode is written (canonical text).
            Some(v @ crate::program::Verification::Required) => v,
            _ => return c.fail("`required`"),
        }
    };
    c.end()?;
    let mut b = Builder::new(&name, precision).map_err(|e| at(n, e))?;
    b.verification(verification);

    for (n, line) in lines {
        let mut c = Cursor::new(n, line);
        if line.starts_with("output") {
            c.keyword("output")?;
            let name = c.string()?;
            c.punct('=')?;
            let v = c.value()?;
            c.end()?;
            b.output(&name, v).map_err(|e| at(n, e))?;
            continue;
        }
        let id = c.value()?;
        if id.index() != b.len() {
            return Err(err(n, format!("expected %{}, got {id}", b.len())));
        }
        c.punct('=')?;
        let mnemonic = c.word()?;
        let op = match mnemonic.as_str() {
            "input" => {
                let name = c.string()?;
                let r = c.floats()?;
                if r.len() != 2 {
                    return Err(err(n, "input range needs exactly [lo, hi]"));
                }
                Op::Input {
                    name,
                    range: Range::new(r[0], r[1]),
                }
            }
            "const" => Op::Const { data: c.floats()? },
            "poly" => {
                let x = c.value()?;
                Op::Poly {
                    x,
                    coeffs: c.floats()?,
                }
            }
            "neg" => Op::Neg(c.value()?),
            "not" => Op::Not(c.value()?),
            "cast" => Op::Cast(c.value()?),
            "shl" | "shr" => {
                let x = c.value()?;
                let by = c.usize()?;
                Op::Shift {
                    x,
                    left: mnemonic == "shl",
                    by: u32::try_from(by).map_err(|_| err(n, "shift amount too large"))?,
                }
            }
            "lookup" => {
                let x = c.value()?;
                Op::Lookup {
                    x,
                    table: c.floats()?,
                }
            }
            "select" => {
                let cond = c.value()?;
                c.punct(',')?;
                let a = c.value()?;
                c.punct(',')?;
                Op::Select(cond, a, c.value()?)
            }
            "sum" => Op::Sum(c.value()?),
            "sigmoid" => Op::Sigmoid(c.value()?),
            "add" | "sub" | "mul" | "dot" | "matvec" | "eq" | "ne" | "lt" | "le" | "gt" | "ge"
            | "and" | "or" | "xor" | "min" | "max" | "div" | "rem" => {
                let a = c.value()?;
                c.punct(',')?;
                let bv = c.value()?;
                match mnemonic.as_str() {
                    "add" => Op::Add(a, bv),
                    "sub" => Op::Sub(a, bv),
                    "mul" => Op::Mul(a, bv),
                    "dot" => Op::Dot(a, bv),
                    "matvec" => Op::MatVec(a, bv),
                    "eq" => Op::Cmp(CmpOp::Eq, a, bv),
                    "ne" => Op::Cmp(CmpOp::Ne, a, bv),
                    "lt" => Op::Cmp(CmpOp::Lt, a, bv),
                    "le" => Op::Cmp(CmpOp::Le, a, bv),
                    "gt" => Op::Cmp(CmpOp::Gt, a, bv),
                    "ge" => Op::Cmp(CmpOp::Ge, a, bv),
                    "and" => Op::Logic(LogicOp::And, a, bv),
                    "or" => Op::Logic(LogicOp::Or, a, bv),
                    "xor" => Op::Logic(LogicOp::Xor, a, bv),
                    "min" => Op::Min(a, bv),
                    "max" => Op::Max(a, bv),
                    "div" => Op::Div(a, bv),
                    _ => Op::Rem(a, bv),
                }
            }
            other => return Err(err(n, format!("unknown op {other:?}"))),
        };
        c.punct(':')?;
        let ty = c.ty()?;
        c.end()?;
        let id = b.push_op(op, ty).map_err(|e| at(n, e))?;
        let inferred = b.ty(id).map_err(|e| at(n, e))?;
        if inferred != ty {
            return Err(err(
                n,
                format!("{id} is declared `{ty}` but its type is `{inferred}`"),
            ));
        }
    }
    b.finish()
}

fn err(line: usize, msg: impl Into<String>) -> Error {
    Error::new(Code::Parse, format!("line {line}: {}", msg.into()))
}

fn at(line: usize, e: Error) -> Error {
    Error::new(e.code, format!("line {line}: {}", e.message))
}

struct Cursor<'a> {
    line: usize,
    rest: &'a str,
}

impl<'a> Cursor<'a> {
    fn new(line: usize, s: &'a str) -> Self {
        Self { line, rest: s }
    }

    fn skip_ws(&mut self) {
        self.rest = self.rest.trim_start();
    }

    fn fail<T>(&self, what: &str) -> Result<T> {
        let near: String = self.rest.chars().take(20).collect();
        Err(err(self.line, format!("expected {what} near {near:?}")))
    }

    fn take_while(&mut self, f: impl Fn(char) -> bool) -> &'a str {
        self.skip_ws();
        let end = self.rest.find(|c| !f(c)).unwrap_or(self.rest.len());
        let (tok, rest) = self.rest.split_at(end);
        self.rest = rest;
        tok
    }

    fn word(&mut self) -> Result<String> {
        let w = self.take_while(|c| c.is_ascii_alphanumeric() || c == '_');
        if w.is_empty() {
            return self.fail("a word");
        }
        Ok(w.to_owned())
    }

    fn keyword(&mut self, k: &str) -> Result<()> {
        let save = self.rest;
        if self.word().ok().as_deref() == Some(k) {
            Ok(())
        } else {
            self.rest = save;
            self.fail(&format!("`{k}`"))
        }
    }

    fn punct(&mut self, p: char) -> Result<()> {
        self.skip_ws();
        match self.rest.strip_prefix(p) {
            Some(r) => {
                self.rest = r;
                Ok(())
            }
            None => self.fail(&format!("`{p}`")),
        }
    }

    fn string(&mut self) -> Result<String> {
        self.punct('"')?;
        let end = match self.rest.find('"') {
            Some(e) => e,
            None => return self.fail("closing `\"`"),
        };
        let s = self.rest[..end].to_owned();
        self.rest = &self.rest[end + 1..];
        Ok(s)
    }

    fn value(&mut self) -> Result<ValueId> {
        self.punct('%')?;
        let digits = self.take_while(|c| c.is_ascii_digit());
        match digits.parse() {
            Ok(n) => Ok(ValueId(n)),
            Err(_) => self.fail("a value number after `%`"),
        }
    }

    fn float(&mut self) -> Result<f64> {
        let tok = self.take_while(|c| c.is_ascii_digit() || "+-.eE".contains(c));
        match tok.parse::<f64>() {
            Ok(x) if x.is_finite() => Ok(x),
            _ => self.fail("a finite number"),
        }
    }

    fn floats(&mut self) -> Result<Vec<f64>> {
        self.punct('[')?;
        let mut out = vec![];
        self.skip_ws();
        if let Some(r) = self.rest.strip_prefix(']') {
            self.rest = r;
            return Ok(out);
        }
        loop {
            out.push(self.float()?);
            self.skip_ws();
            if let Some(r) = self.rest.strip_prefix(']') {
                self.rest = r;
                return Ok(out);
            }
            self.punct(',')?;
        }
    }

    fn usize(&mut self) -> Result<usize> {
        let digits = self.take_while(|c| c.is_ascii_digit());
        match digits.parse() {
            Ok(n) => Ok(n),
            Err(_) => self.fail("a size"),
        }
    }

    fn ty(&mut self) -> Result<Type> {
        let visibility = match self.word()?.as_str() {
            "secret" => Visibility::Secret,
            "public" => Visibility::Public,
            _ => return self.fail("`secret` or `public`"),
        };
        let shape = match self.word()?.as_str() {
            "scalar" => Shape::Scalar,
            "vector" => {
                self.punct('<')?;
                let n = self.usize()?;
                self.punct('>')?;
                Shape::Vector(n)
            }
            "matrix" => {
                self.punct('<')?;
                let dims = self.take_while(|c| c.is_ascii_alphanumeric());
                let parsed = dims
                    .split_once('x')
                    .and_then(|(r, c)| Some((r.parse().ok()?, c.parse().ok()?)));
                let Some((r, c)) = parsed else {
                    return self.fail("matrix dimensions RxC");
                };
                self.punct('>')?;
                Shape::Matrix(r, c)
            }
            other => match Elem::parse(other) {
                Some(elem) if elem.is_exact() => {
                    return Ok(Type {
                        visibility,
                        shape: Shape::Scalar,
                        elem,
                    })
                }
                _ => return self.fail("a shape or element type"),
            },
        };
        Ok(Type {
            visibility,
            shape,
            elem: Elem::F64,
        })
    }

    fn end(&mut self) -> Result<()> {
        self.skip_ws();
        if self.rest.is_empty() {
            Ok(())
        } else {
            self.fail("end of line")
        }
    }
}
