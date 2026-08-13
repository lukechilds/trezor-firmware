#![allow(non_upper_case_globals)]

use super::ffi;
use super::obj::Obj;
use super::qstr::Qstr;
use super::typ::{FullType, Type};

/// Marker for an exception type.
///
/// # Safety
///
/// This is, honestly, kind of wonky. `Type` is not a full type struct, it ends
/// with an incomplete array. So an owning exception type does't make sense,
/// because it can't correctly own the inner type.
///
/// (No constructors are exposed.)
///
/// The role of ExceptionType is in [`wrap_type`], allowing us to convert a
/// _reference_ to a `Type` into a reference to an `ExceptionType`.
#[derive(Debug)]
#[repr(transparent)]
pub struct ExceptionType {
    type_: Type,
}

impl ExceptionType {
    pub const unsafe fn wrap_type(type_: &'static Type) -> &'static Self {
        // SAFETY: ExceptionType is repr(transparent).
        // Assuming Type is actually an exception type,
        // the cast is safe.
        unsafe { core::mem::transmute(type_) }
    }

    pub const fn as_type(&self) -> &Type {
        &self.type_
    }

    pub fn is_type_of(&'static self, other: Obj) -> bool {
        self.as_type().is_type_of(other)
    }

    pub fn create<'a>(&'static self) -> Exception<'a> {
        Exception {
            type_: self,
            args: ExceptionArgs::NoArgs,
        }
    }

    pub fn create_with_arg<'a>(&'static self, arg: impl TryInto<Obj>) -> Exception<'a> {
        let args = match arg.try_into() {
            Ok(obj) => ExceptionArgs::SingleArg(obj),
            _ => ExceptionArgs::NoArgs,
        };
        Exception { type_: self, args }
    }

    pub fn create_with_args<'a>(&'static self, args: &'a [Obj]) -> Exception<'a> {
        Exception {
            type_: self,
            args: ExceptionArgs::MultipleArgs(args),
        }
    }
}

macro_rules! wrap_builtin {
    ($name:ident, $type:expr) => {
        // SAFETY: provided type must be an exception type.
        pub const $name: &ExceptionType = unsafe { ExceptionType::wrap_type($type) };
    };
}

wrap_builtin!(AttributeError, &ffi::mp_type_AttributeError);
wrap_builtin!(EOFError, &ffi::mp_type_EOFError);
wrap_builtin!(Exception, &ffi::mp_type_Exception);
wrap_builtin!(IndexError, &ffi::mp_type_IndexError);
wrap_builtin!(KeyError, &ffi::mp_type_KeyError);
wrap_builtin!(MemoryError, &ffi::mp_type_MemoryError);
wrap_builtin!(NotImplementedError, &ffi::mp_type_NotImplementedError);
wrap_builtin!(OverflowError, &ffi::mp_type_OverflowError);
wrap_builtin!(RuntimeError, &ffi::mp_type_RuntimeError);
wrap_builtin!(TypeError, &ffi::mp_type_TypeError);
wrap_builtin!(ValueError, &ffi::mp_type_ValueError);

pub const fn define_exception(name: Qstr, parent: &ExceptionType) -> FullType {
    obj_type! {
        name: name,
        make_new_fn: ffi::mp_obj_exception_make_new,
        attr_fn: ffi::mp_obj_exception_attr,
        print_fn: ffi::mp_obj_exception_print,
        parent: parent.as_type(),
    }
}

/// Helper enum for exception arguments.
///
/// Enables trivially passing none or a single owned argument, or a reference to
/// a slice of owned arguments.
#[derive(Debug, Copy, Clone)]
pub enum ExceptionArgs<'a> {
    NoArgs,
    SingleArg(Obj),
    MultipleArgs(&'a [Obj]),
}

/// Exception wrapper object.
///
/// Represents an unraised exception on Rust side. When creating FFI exceptions
/// via [`ffi::mp_obj_new_exception_args`], the resulting object may be reused
/// by MicroPython for another exception. By keeping the arguments explicitly
/// without constructing the exception, we avoid the problem.
///
/// The actual exception object is then constructed via [`Exception::into_obj`].
#[derive(Debug, Copy, Clone)]
pub struct Exception<'a> {
    type_: &'static ExceptionType,
    args: ExceptionArgs<'a>,
}

impl Exception<'_> {
    /// Convert a custom exception into a MicroPython exception object.
    ///
    /// # Safety
    ///
    /// The result of this call should only be used to immediately raise the
    /// exception, because the object is not guaranteed to remain intact.
    /// MicroPython might reuse the same space for creating a different
    /// exception. See [`new_exception_args`].
    pub unsafe fn into_obj(self) -> Obj {
        let args: &[Obj] = match self.args {
            ExceptionArgs::NoArgs => {
                // SAFETY: self.type_ is a valid exception type.
                return unsafe { ffi::mp_obj_new_exception(self.type_.as_type()) };
            }
            ExceptionArgs::SingleArg(arg) => &[arg],
            ExceptionArgs::MultipleArgs(args) => args,
        };
        // SAFETY: self.type_ is a valid exception type.
        unsafe { ffi::mp_obj_new_exception_args(self.type_.as_type(), args.len(), args.as_ptr()) }
    }

    /// Raise the exception into MicroPython
    ///
    /// # Safety
    ///
    /// Should only be called at the boundary which would otherwise return to C.
    /// See [`raise_exception_obj`] for more details.
    pub unsafe fn raise(self) -> ! {
        // SAFETY:
        // - into_obj constructs a valid exception instance (satisfying nlr_jump)
        // - this is immediately raised (satisfying into_obj)
        unsafe { raise_exception_obj(self.into_obj()) };
    }
}

/// Raise a micropython object as exception via NLR jump.
///
/// # Safety
///
/// Jumps directly out of the context without running any destructors,
/// finalizers, etc. This is very likely to break a lot of Rust's assumptions:
/// in particular, _any_ jumping over Rust code is currently considered
/// undefined. See full discussion at https://github.com/rust-lang/rfcs/issues/2625
/// Should only be called at the boundary which would otherwise return to C.
pub(super) unsafe fn raise_exception_obj(obj: Obj) -> ! {
    // SAFETY: argument must be an exception instance
    unsafe { ffi::nlr_jump(obj.as_ptr()) };
}
