use std::convert::From;

#[derive(Debug)]
pub enum Error {
    KeyNotFound,
    KeyAlreadyExists,
    UnexpectedError,
    KeyOverflowError,
    ValueOverflowError,
    TryFromSliceError(&'static str),
    UTF8Error,
}


// IO ERR转换成 自定义error
impl From<std::io::Error> for Error {
    fn from(_value: std::io::Error) -> Self {
        Error::UnexpectedError
    }
}