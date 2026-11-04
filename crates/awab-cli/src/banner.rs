//! The terminal banner and credit lines — the tool's face, in the tradition of
//! hydra / nmap / msfconsole.

use awab_core::util::{format_utc, now_epoch};

const VERSION: &str = env!("CARGO_PKG_VERSION");

const ART: &str = "\
 █████╗ ██╗    ██╗ █████╗ ██████╗ \n\
██╔══██╗██║    ██║██╔══██╗██╔══██╗\n\
███████║██║ █╗ ██║███████║██████╔╝\n\
██╔══██║██║███╗██║██╔══██║██╔══██╗\n\
██║  ██║╚███╔███╔╝██║  ██║██████╔╝\n\
╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═════╝ ";

const AMBER: &str = "\x1b[38;5;208m";
const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";

/// The full banner for `awab` (no args) and `awab -h`.
pub fn big(color: bool) -> String {
    let tag = format!("awab v{VERSION} - hunt threats in Linux logs, straight from the terminal");
    let by = "(c) 2026 Awab Al-shandawi  -  MITRE ATT&CK mapped  -  defensive use only";
    if color {
        format!("\n{AMBER}{ART}{RESET}\n\n  {BOLD}{tag}{RESET}\n  {DIM}{by}{RESET}\n")
    } else {
        format!("\n{ART}\n\n  {tag}\n  {by}\n")
    }
}

/// The two-line credit printed at the start of a scan, hydra-style.
pub fn run_header(color: bool) -> String {
    let l1 = format!(
        "awab v{VERSION} (c) 2026 by Awab Al-shandawi - fast Linux log triage & threat hunting"
    );
    let l2 = format!("awab starting scan at {}", format_utc(now_epoch()));
    if color {
        format!("{BOLD}{l1}{RESET}\n{DIM}{l2}{RESET}\n")
    } else {
        format!("{l1}\n{l2}\n")
    }
}
