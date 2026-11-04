//! Rendering findings in various formats.

pub mod html;
pub mod json;
pub mod terminal;

#[derive(Clone, Copy)]
pub struct Stats {
    pub rules: usize,
    pub events: usize,
    pub findings: usize,
}
