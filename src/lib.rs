#![feature(test)]
extern crate test;

pub mod cipher;
pub mod config;
pub mod cursor;
pub mod mac;
pub mod stream;

pub const NONCE_BYTES: usize = 12;
pub const X_NONCE_BYTES: usize = 24;
pub const KEY_BYTES: usize = 32;
