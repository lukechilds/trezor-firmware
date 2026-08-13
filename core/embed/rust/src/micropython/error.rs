use core::convert::{Infallible, TryInto};
use core::ffi::CStr;
use core::num::TryFromIntError;

use super::exception;
use super::obj::Obj;

#[allow(clippy::enum_variant_names)] // We mimic the Python exception classnames here.
#[derive(Clone, Copy, Debug)]
pub enum Error {
    TypeError,
    OutOfRange,
    MissingKwargs,
    AllocationFailed,
    EOFError,
    IndexError,
    CaughtException(Obj),
    KeyError(Obj),
    AttributeError(Obj),
    ValueError(&'static CStr),
    ValueErrorParam(&'static CStr, Obj),
    RuntimeError(&'static CStr),
    NotImplementedError,
    CustomException(exception::Exception<'static>),
}

impl Error {
    /// Create an exception instance matching the error code. The result of this
    /// call should only be used to immediately raise the exception, because the
    /// object is not guaranteed to remain intact. MicroPython might reuse the
    /// same space for creating a different exception.
    pub unsafe fn into_obj(self) -> Obj {
        unsafe {
            match self {
                Error::TypeError => exception::TypeError.create().into_obj(),
                Error::OutOfRange => exception::OverflowError.create().into_obj(),
                Error::MissingKwargs => exception::TypeError.create().into_obj(),
                Error::AllocationFailed => exception::MemoryError.create().into_obj(),
                Error::IndexError => exception::IndexError.create().into_obj(),
                Error::CaughtException(obj) => obj,
                Error::KeyError(key) => exception::KeyError.create_with_arg(key).into_obj(),
                Error::ValueError(msg) => exception::ValueError.create_with_arg(msg).into_obj(),
                Error::ValueErrorParam(msg, param) => {
                    if let Ok(msg) = msg.try_into() {
                        let args = [msg, param];
                        exception::ValueError.create_with_args(&args).into_obj()
                    } else {
                        exception::ValueError.create().into_obj()
                    }
                }
                Error::AttributeError(attr) => {
                    exception::AttributeError.create_with_arg(attr).into_obj()
                }
                Error::EOFError => exception::EOFError.create().into_obj(),
                Error::RuntimeError(msg) => exception::RuntimeError.create_with_arg(msg).into_obj(),
                Error::NotImplementedError => exception::NotImplementedError.create().into_obj(),
                Error::CustomException(exception) => exception.into_obj(),
            }
        }
    }

    /// Raise the error as a micropython exception.
    ///
    /// # Safety
    ///
    /// Delegates directly to [`exception::raise_exception_obj`], see safety
    /// notes there.
    pub(super) unsafe fn raise(self) -> ! {
        // SAFETY: into_obj constructs a valid exception instance (satisfying nlr_jump)
        // and this is immediately raised (satisfying into_obj)
        unsafe { exception::raise_exception_obj(self.into_obj()) };
    }
}

// Implements a conversion from `core::convert::Infallible` to `Error` to so
// that code generic over `TryFrom` can work with values covered by the blanket
// impl for `Into`: `https://doc.rust-lang.org/std/convert/enum.Infallible.html`
impl From<Infallible> for Error {
    fn from(_: Infallible) -> Self {
        unreachable!()
    }
}

impl From<TryFromIntError> for Error {
    fn from(_: TryFromIntError) -> Self {
        Self::OutOfRange
    }
}

// #[cfg(feature = "thp")]
// impl From<trezor_thp::Error> for Error {
//     fn from(error: trezor_thp::Error) -> Self {
//         match error {
//             trezor_thp::Error::UnexpectedInput =>
// Error::ThpError(c"Unexpected input"),             trezor_thp::Error::NotReady
// => Error::ThpError(c"Not ready"),
// trezor_thp::Error::MalformedData => Error::ThpError(c"Malformed data"),
//             trezor_thp::Error::InvalidChecksum => Error::ThpError(c"Invalid
// checksum"),             trezor_thp::Error::InsufficientBuffer =>
// Error::ThpError(c"Insufficient buffer"),
// trezor_thp::Error::CryptoError => Error::ThpError(c"Crypto error"),         }
//     }
// }

// #[cfg(feature = "crypto")]
// impl From<crypto::Error> for crate::error::Error {
//     fn from(e: crypto::Error) -> Self {
//         match e {
//             crypto::Error::SignatureVerificationFailed => {
//                 value_error!(c"Signature verification failed")
//             }
//             crypto::Error::InvalidEncoding => value_error!(c"Invalid key or
// signature encoding"),             crypto::Error::InvalidParams =>
// value_error!(c"Invalid cryptographic parameters"),
// crypto::Error::InvalidContext => value_error!(c"Invalid cryptographic
// context"),             crypto::Error::AuthenticationFailed =>
// value_error!(c"Authentication failed"),
// crypto::Error::InvalidSigmask => value_error!(c"Invalid sigmask"),         }
//     }
// }
