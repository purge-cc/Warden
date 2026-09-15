use regex_automata::dfa::{dense, Automaton, StartKind};
use regex_automata::nfa::thompson::{self, State, Transition, WhichCaptures, NFA};
use regex_automata::util::look::LookMatcher;
use regex_automata::util::primitives::StateID;
use regex_automata::{Anchored, Input, MatchKind};

use super::{BudgetExceeded, CompileError};
use crate::config::schema::id::Id;

type Dfa = dense::DFA<Vec<u32>>;

/// Fully constructed automata; searches only read tables and use scalar state.
#[derive(Debug)]
pub(super) struct RegexProgram {
    fast: Dfa,
    unicode_boundary: Option<Dfa>,
}

#[derive(Debug)]
pub(super) enum RegexError {
    Syntax(String),
    Budget(&'static str),
    Build(String),
}

impl RegexError {
    pub(super) fn context(self, list: Id, row: u32, limit: usize) -> CompileError {
        match self {
            Self::Syntax(detail) => CompileError::InvalidRegex { list, row, detail },
            Self::Budget(stage) => CompileError::RegexBudgetExceeded {
                list,
                row,
                stage,
                source: BudgetExceeded {
                    limit: "max_regex_program_bytes",
                    actual: None,
                    maximum: limit,
                },
            },
            Self::Build(detail) => CompileError::RegexConstruction { list, row, detail },
        }
    }
}

fn build_dfa(nfa: &NFA, limit: usize, boundary: bool) -> Result<Dfa, RegexError> {
    let config = dense::Config::new()
        .match_kind(MatchKind::All)
        .unicode_word_boundary(!boundary)
        .start_kind(if boundary {
            StartKind::Anchored
        } else {
            StartKind::Both
        })
        .dfa_size_limit(Some(limit))
        .determinize_size_limit(Some(limit));
    let dfa = dense::Builder::new()
        .configure(config)
        .build_from_nfa(nfa)
        .map_err(|error| {
            if error.is_size_limit_exceeded() {
                RegexError::Budget(if boundary {
                    "Unicode boundary DFA"
                } else {
                    "DFA"
                })
            } else {
                RegexError::Build(error.to_string())
            }
        })?;
    if dfa.memory_usage() > limit {
        return Err(RegexError::Budget("DFA representation"));
    }
    // Copy through slices so retained Vec capacities equal their lengths;
    // memory_usage then covers owned tables, not just their initialized prefix.
    Ok(dfa.to_owned())
}

impl RegexProgram {
    pub(super) fn compile(
        source: &str,
        case_insensitive: bool,
        limit: usize,
    ) -> Result<Self, RegexError> {
        let hir = regex_syntax::ParserBuilder::new()
            .case_insensitive(case_insensitive)
            .build()
            .parse(source)
            .map_err(|error| RegexError::Syntax(error.to_string()))?;
        let nfa = thompson::Compiler::new()
            .configure(
                thompson::Config::new()
                    .which_captures(WhichCaptures::None)
                    .nfa_size_limit(Some(limit)),
            )
            .build_from_hir(&hir)
            .map_err(|_| RegexError::Budget("NFA"))?;
        let fast = build_dfa(&nfa, limit, false)?;
        let unicode_boundary = if nfa.look_set_any().contains_word_unicode() {
            let expanded = boundary_nfa(&nfa, limit)
                .map_err(|_| RegexError::Budget("Unicode boundary NFA"))?;
            Some(build_dfa(&expanded, limit, true)?)
        } else {
            None
        };
        Ok(Self {
            fast,
            unicode_boundary,
        })
    }

    #[inline]
    pub(super) fn is_match(&self, text: &str) -> bool {
        if let Some(dfa) = &self.unicode_boundary {
            if !text.is_ascii() {
                return boundary_match(dfa, text);
            }
        }
        self.fast
            .try_search_fwd(&Input::new(text).earliest(true))
            .expect("Unicode quit bytes use the boundary automaton")
            .is_some()
    }
}

// Assertions depend only on absence, ASCII word/nonword, LF, CR, Unicode
// word/nonword, or an interior UTF-8 byte boundary. Encoding that context before
// each input byte turns conditional epsilon edges into ordinary byte edges.
// Dense determinization then supports Unicode assertions without a lazy cache,
// NFA simulation, input copies, or an ASCII-only interpretation of Unicode.
const CONTEXTS: u8 = 50;
const INTERIOR: u8 = 49;
const REPRESENTATIVES: [&str; 7] = ["", "a", "!", "\n", "\r", "é", "☃"];

fn char_class(c: Option<char>) -> u8 {
    match c {
        None => 0,
        Some('\n') => 3,
        Some('\r') => 4,
        Some(c) if c.is_ascii_alphanumeric() || c == '_' => 1,
        Some(c) if c.is_ascii() => 2,
        Some(c) if regex_syntax::is_word_character(c) => 5,
        Some(_) => 6,
    }
}

fn context(text: &str, at: usize) -> u8 {
    if !text.is_char_boundary(at) {
        return INTERIOR;
    }
    char_class(text[..at].chars().next_back()) * 7 + char_class(text[at..].chars().next())
}

fn boundary_match(dfa: &Dfa, text: &str) -> bool {
    let mut state = dfa
        .start_state_forward(&Input::new(b"").anchored(Anchored::Yes))
        .expect("anchored boundary automaton");
    for at in 0..=text.len() {
        state = dfa.next_state(state, context(text, at));
        if dfa.is_match_state(state) {
            return true;
        }
        if dfa.is_dead_state(state) {
            return false;
        }
        if let Some(&byte) = text.as_bytes().get(at) {
            state = dfa.next_state(state, byte);
            if dfa.is_match_state(state) {
                return true;
            }
            if dfa.is_dead_state(state) {
                return false;
            }
        }
    }
    dfa.is_match_state(dfa.next_eoi_state(state))
}

fn boundary_nfa(nfa: &NFA, limit: usize) -> Result<NFA, Box<thompson::BuildError>> {
    let mut builder = thompson::Builder::new();
    builder.set_size_limit(Some(limit))?;
    builder.set_utf8(false);
    builder.start_pattern()?;
    let mut dispatch = Vec::with_capacity(nfa.states().len());
    for _ in nfa.states() {
        dispatch.push(builder.add_empty().map_err(Box::new)?);
    }
    let mut consuming = Vec::with_capacity(dispatch.len());
    for state in nfa.states() {
        let mapped = match state {
            State::ByteRange { trans } => builder.add_range(Transition {
                next: dispatch[trans.next.as_usize()],
                ..*trans
            })?,
            State::Sparse(sparse) => builder.add_sparse(
                sparse
                    .transitions
                    .iter()
                    .map(|trans| Transition {
                        next: dispatch[trans.next.as_usize()],
                        ..*trans
                    })
                    .collect(),
            )?,
            State::Dense(dense) => builder.add_sparse(
                (0..=u8::MAX)
                    .filter_map(|byte| {
                        dense.matches_byte(byte).map(|next| Transition {
                            start: byte,
                            end: byte,
                            next: dispatch[next.as_usize()],
                        })
                    })
                    .collect(),
            )?,
            State::Match { .. } => builder.add_match()?,
            _ => builder.add_fail()?,
        };
        consuming.push(mapped);
    }
    let matcher = LookMatcher::new();
    let mut visited = vec![false; dispatch.len()];
    let mut stack = Vec::with_capacity(dispatch.len());
    let mut terminals = Vec::new();
    for (rank, &entry) in dispatch.iter().enumerate() {
        let mut transitions = Vec::with_capacity(usize::from(CONTEXTS));
        for code in 0..CONTEXTS {
            let mut sample = String::new();
            let at = if code == INTERIOR {
                sample.push('é');
                1
            } else {
                sample.push_str(REPRESENTATIVES[usize::from(code / 7)]);
                let at = sample.len();
                sample.push_str(REPRESENTATIVES[usize::from(code % 7)]);
                at
            };
            visited.fill(false);
            terminals.clear();
            stack.push(StateID::new(rank).expect("rank from existing NFA"));
            while let Some(id) = stack.pop() {
                if std::mem::replace(&mut visited[id.as_usize()], true) {
                    continue;
                }
                match nfa.state(id) {
                    State::Look { look, next } => {
                        if matcher.matches(*look, sample.as_bytes(), at) {
                            stack.push(*next);
                        }
                    }
                    State::Union { alternates } => stack.extend(alternates.iter().copied()),
                    State::BinaryUnion { alt1, alt2 } => {
                        stack.push(*alt1);
                        stack.push(*alt2);
                    }
                    State::Capture { next, .. } => stack.push(*next),
                    State::Fail => {}
                    // String regexes cannot report matches inside a codepoint.
                    State::Match { .. } if code == INTERIOR => {}
                    _ => terminals.push(consuming[id.as_usize()]),
                }
            }
            let next = builder.add_union(terminals.clone())?;
            transitions.push(Transition {
                start: code,
                end: code,
                next,
            });
        }
        let next = builder.add_sparse(transitions)?;
        builder.patch(entry, next)?;
    }
    let start = dispatch[nfa.start_unanchored().as_usize()];
    builder.finish_pattern(start)?;
    Ok(builder.build(start, start)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dfa_size_failure_is_contextual_budget_error() {
        let nfa = NFA::new("a").unwrap();
        let error = build_dfa(&nfa, 1, false)
            .unwrap_err()
            .context(Id::new("rules").unwrap(), 7, 1);
        assert!(matches!(
            error,
            CompileError::RegexBudgetExceeded {
                row: 7,
                stage: "DFA",
                source: BudgetExceeded { maximum: 1, .. },
                ..
            }
        ));
    }

    #[test]
    fn quota_covers_both_dense_automata_and_their_representation() {
        let limit = 1 << 20;
        for source in [r"example", r"\bélan\b"] {
            let program = RegexProgram::compile(source, true, limit).unwrap();
            let owned = program.fast.memory_usage()
                + program
                    .unicode_boundary
                    .as_ref()
                    .map_or(0, Dfa::memory_usage)
                + std::mem::size_of::<RegexProgram>()
                + 2 * std::mem::size_of::<usize>();
            assert!(owned <= super::super::CompiledCostV1::regex_bytes(limit).unwrap());
            assert_eq!(program.unicode_boundary.is_some(), source.contains(r"\b"));
        }
    }

    #[test]
    fn finite_context_preserves_all_assertions_at_every_utf8_offset() {
        use regex_automata::util::look::LookSet;
        let matcher = LookMatcher::new();
        for left in [
            "", "a", "_", "9", "!", "\0", "\n", "\r", "é", "中", "\u{301}", "☃", "😀",
        ] {
            for right in [
                "", "a", "_", "9", "!", "\0", "\n", "\r", "é", "中", "\u{301}", "☃", "😀",
            ] {
                let text = format!("{left}{right}");
                for at in 0..=text.len() {
                    let code = context(&text, at);
                    let sample = if code == INTERIOR {
                        "é".to_owned()
                    } else {
                        format!(
                            "{}{}",
                            REPRESENTATIVES[usize::from(code / 7)],
                            REPRESENTATIVES[usize::from(code % 7)]
                        )
                    };
                    let sample_at = if code == INTERIOR {
                        1
                    } else {
                        REPRESENTATIVES[usize::from(code / 7)].len()
                    };
                    for look in LookSet::full().iter() {
                        assert_eq!(
                            matcher.matches(look, text.as_bytes(), at),
                            matcher.matches(look, sample.as_bytes(), sample_at),
                            "{look:?}: {text:?} at {at}"
                        );
                    }
                }
            }
        }
    }
}
