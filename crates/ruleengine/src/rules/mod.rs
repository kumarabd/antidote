//! Individual rule implementations (R1, R2, ...)

mod r1;
mod r10;
mod r11;
mod r12;
mod r13;
mod r14;
mod r2;
mod r3;
mod r3b;
mod r4;
mod r5;
mod r6;
mod r6b;
mod r7;
mod r8;
mod r9;

use antidote_core::Event;
use crate::state::SessionState;
use crate::RuleEngine;

/// Event-driven rules: take event + session, return new flags (caller updates counts).
pub fn evaluate_event_driven(
    engine: &RuleEngine,
    event: &Event,
    session: &mut SessionState,
) -> Vec<antidote_core::Flag> {
    let mut flags = Vec::new();
    match event.event_type {
        antidote_core::EventType::FileWrite => {
            flags.extend(r1::check(engine, event, session));
            flags.extend(r2::check(engine, event, session));
        }
        antidote_core::EventType::FileDelete => {
            flags.extend(r3b::check(engine, event, session));
        }
        antidote_core::EventType::FileRead => {
            flags.extend(r14::check(engine, event, session));
        }
        antidote_core::EventType::NetHttp => {
            flags.extend(r4::check(engine, event, session));
        }
        antidote_core::EventType::CmdExec => {
            flags.extend(r3::check(engine, event, session));
        }
        antidote_core::EventType::Tick | antidote_core::EventType::Heartbeat => {
            flags.extend(evaluate_aggregate(engine, session));
        }
        _ => {}
    }
    flags
}

/// Aggregate rules (evaluated on Tick/Heartbeat).
pub fn evaluate_aggregate(
    engine: &RuleEngine,
    session: &mut SessionState,
) -> Vec<antidote_core::Flag> {
    let mut flags = Vec::new();
    flags.extend(r5::check(engine, session));
    flags.extend(r6::check(engine, session));
    flags.extend(r6b::check(engine, session));
    flags.extend(r7::check(engine, session));
    flags.extend(r8::check(engine, session));
    flags.extend(r9::check(engine, session));
    flags.extend(r10::check(engine, session));
    flags.extend(r11::check(engine, session));
    flags.extend(r12::check(engine, session));
    r13::check(engine, session); // R13 + BENIGN_INDEXING (labels only, no flags)
    flags
}
