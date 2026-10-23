//! Keyleak: find API keys leaked in your home folder.
//!
//! Read-only and offline: it opens files, never writes to them, and makes no
//! network calls. Secrets are masked before they leave the file scanner.

pub mod demo;
pub mod detect;
pub mod html;
pub mod ignore;
pub mod scan;
pub mod term;
