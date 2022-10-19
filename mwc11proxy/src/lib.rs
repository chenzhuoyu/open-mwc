#![feature(pointer_byte_offsets)]

pub mod arp;
pub mod log;
pub mod options;

pub type Unit = Maybe<()>;
pub type Error = Box<dyn std::error::Error + Send + Sync>;
pub type Maybe<T> = Result<T, Error>;

#[inline]
pub fn as_err<T: std::error::Error + Send + Sync + 'static>(e: T) -> Error {
    Box::new(e) as Error
}
