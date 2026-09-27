//! SO Trace Database — Core Storage Engine
//!
//! This crate provides the core storage engine for SO Trace Database,
//! a specialized database for storing and querying Android SO execution traces.

pub mod db;
pub mod models;
pub mod storage;
pub mod memory_delta;
pub mod index;
pub mod query;
pub mod adapters;
pub mod elf;

pub use db::SoTraceDB;
