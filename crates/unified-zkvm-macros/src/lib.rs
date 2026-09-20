//! Procedural macros for unified-zkvm guest entrypoints.
//!
//! # Why only one macro
//!
//! There is exactly one macro here, and it earns its place by removing a real
//! portability problem: each zkVM has a different entrypoint ritual (SP1 wants
//! `sp1_zkvm::entrypoint!`, RISC Zero wants `risc0_zkvm::guest::entry!`, both
//! want `#![no_main]`). Without a macro, every guest would carry a `#[cfg]`
//! ladder for something that has nothing to do with the application.
//!
//! Everything else this crate could plausibly generate — typed I/O wrappers,
//! builder sugar — is better as ordinary functions, which produce better error
//! messages and can be read without understanding proc-macro expansion.
//!
//! # What it generates
//!
//! No magic and no hidden behaviour. The expansion is documented on
//! [`macro@entrypoint`] and is a handful of lines you could have written by
//! hand.

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, ItemFn};

/// Marks a function as the guest entrypoint.
///
/// ```ignore
/// #[unified_zkvm::entrypoint]
/// fn main() {
///     let n: u32 = unified_zkvm::guest::zk_read().unwrap();
///     unified_zkvm::guest::zk_commit(&(n * n)).unwrap();
/// }
/// ```
///
/// # Generated code
///
/// The function body is left untouched. The macro renames it and emits the
/// backend's entrypoint invocation:
///
/// * **SP1** — `sp1_zkvm::entrypoint!(__unified_zkvm_guest_main);`
/// * **RISC Zero** — `risc0_zkvm::guest::entry!(__unified_zkvm_guest_main);`
/// * **no backend** — a plain `fn main()` calling through, so the guest runs as
///   an ordinary binary under `cargo run` and `cargo test`.
///
/// The `#![no_main]` attribute is **not** emitted, because an inner attribute
/// cannot be added from an attribute macro. Guests that target a real backend
/// declare it themselves at the top of the file; the guest guide shows the
/// four-line preamble.
///
/// # Errors
///
/// Compilation fails with a clear message if applied to anything other than a
/// free function taking no arguments.
#[proc_macro_attribute]
pub fn entrypoint(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let func = parse_macro_input!(item as ItemFn);

    if !func.sig.inputs.is_empty() {
        return syn::Error::new_spanned(
            &func.sig.inputs,
            "a unified-zkvm entrypoint takes no arguments; read input inside the \
             body with `zk_read()`",
        )
        .to_compile_error()
        .into();
    }
    if func.sig.asyncness.is_some() {
        return syn::Error::new_spanned(
            func.sig.asyncness,
            "a guest entrypoint cannot be `async`; zkVM guests are single-threaded \
             and have no executor",
        )
        .to_compile_error()
        .into();
    }

    let mut inner = func;
    let original_name = inner.sig.ident.clone();
    let inner_name = syn::Ident::new("__unified_zkvm_guest_main", original_name.span());
    inner.sig.ident = inner_name.clone();

    quote! {
        #inner

        #[cfg(feature = "sp1")]
        ::sp1_zkvm::entrypoint!(#inner_name);

        #[cfg(feature = "risc0")]
        ::risc0_zkvm::guest::entry!(#inner_name);

        // No backend selected: run as a normal binary so guest logic stays
        // testable on the host with no zkVM toolchain installed.
        #[cfg(all(not(feature = "sp1"), not(feature = "risc0")))]
        fn main() {
            #inner_name()
        }
    }
    .into()
}
