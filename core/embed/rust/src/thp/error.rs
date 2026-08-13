use trezor_thp::Error as ThpError;

use crate::micropython::exception::{self, Exception, ExceptionType, RuntimeError};
use crate::micropython::qstr::Qstr;
use crate::micropython::typ::FullType;

#[cfg_attr(test, derive(Debug))]
pub(super) enum Error {
    Protocol(ThpError),
    CannotUnlock,
    ChannelNotFound,
    InterfaceNotFound,
    TooManyInterfaces,
    UnexpectedPacketInResult,
    InvalidKeyLength,
}

static THP_EXCEPTION_TYPE: FullType =
    exception::define_exception(Qstr::MP_QSTR_ThpError, exception::Exception);
#[allow(non_upper_case_globals)]
pub(super) static ThpExceptionType: &ExceptionType =
    unsafe { ExceptionType::wrap_type(THP_EXCEPTION_TYPE.as_type()) };

fn thp_exception(error: ThpError) -> Exception<'static> {
    match error {
        ThpError::UnexpectedInput => ThpExceptionType.create_with_arg(c"Unexpected input"),
        ThpError::NotReady => ThpExceptionType.create_with_arg(c"Not ready"),
        ThpError::MalformedData => ThpExceptionType.create_with_arg(c"Malformed data"),
        ThpError::CryptoError => ThpExceptionType.create_with_arg(c"Crypto error"),
        ThpError::InvalidChecksum => ThpExceptionType.create_with_arg(c"Invalid checksum"),
        ThpError::InsufficientBuffer => ThpExceptionType.create_with_arg(c"Insufficient buffer"),
    }
}

impl Error {
    pub fn into_exception(self) -> Exception<'static> {
        match self {
            Error::Protocol(error) => thp_exception(error),
            Error::CannotUnlock => RuntimeError.create_with_arg(c"THP context is locked"),
            Error::ChannelNotFound => ThpExceptionType.create_with_arg(c"Channel not found"),
            Error::InterfaceNotFound => ThpExceptionType.create_with_arg(c"Interface not found"),
            Error::TooManyInterfaces => ThpExceptionType.create_with_arg(c"Too many interfaces"),
            Error::UnexpectedPacketInResult => {
                ThpExceptionType.create_with_arg(c"Unexpected packet in result")
            }
            Error::InvalidKeyLength => ThpExceptionType.create_with_arg(c"Invalid key length"),
        }
    }
}

impl From<ThpError> for Error {
    fn from(error: ThpError) -> Self {
        Error::Protocol(error)
    }
}

impl From<Error> for crate::micropython::error::Error {
    fn from(error: Error) -> Self {
        crate::micropython::error::Error::CustomException(error.into_exception())
    }
}
