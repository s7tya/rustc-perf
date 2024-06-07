use thiserror::Error;

#[macro_use]
extern crate itertools;

#[derive(Error, Debug)]
#[error("command failed: {command}")]
pub struct CommandFailed {
    command: String,
}

pub mod api;
pub mod db;
pub mod github;
pub mod load;
pub mod server;

pub mod trace {
    include!(concat!(env!("OUT_DIR"), "/perfetto.protos.rs"));
}

mod average;
mod benchmark_metadata;
mod comparison;
mod interpolate;
mod request_handlers;
mod resources;
mod selector;
mod self_profile;
