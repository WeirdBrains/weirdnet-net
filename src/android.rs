//! Android only: hand `ndk-context` the process's JavaVM and application Context.
//!
//! On Android, hickory-resolver (libp2p's DNS transport inside a [`crate::Node`]) reads the system
//! DNS servers from the ConnectivityManager through `ndk-context`, and panics if that was never
//! initialized, which takes down every node dialing a real network (device linking by QR, relays,
//! `/dnsaddr`). Other crates that reach Android services through `ndk-context` (keystores) need
//! the same. Call [`init_context`] once, before any node starts; the
//! [`android_context_init!`](crate::android_context_init) macro exports the JNI function an app's
//! Kotlin calls for that.

pub use jni_sys;

use std::sync::Once;
use std::sync::atomic::{AtomicBool, Ordering};

use jni_sys::{JNI_OK, JNIEnv, JavaVM, jobject};

static INIT: Once = Once::new();
static SET: AtomicBool = AtomicBool::new(false);

/// Gives `ndk-context` the JavaVM behind `env` and a global reference to `context` (kept for the
/// life of the process, as `ndk-context` expects). Only the first call does anything; it returns
/// whether the context is set (false if the JVM refused the VM or the global reference).
///
/// # Safety
/// `env` must be the calling thread's valid `JNIEnv` and `context` a live reference to the
/// application `Context`, as when called from a JNI native method.
pub unsafe fn init_context(env: *mut JNIEnv, context: jobject) -> bool {
    INIT.call_once(|| {
        // SAFETY: the caller guarantees `env` and `context`; the global reference keeps the
        // Context alive for the life of the process.
        unsafe {
            let fns = &**env;
            let mut vm: *mut JavaVM = std::ptr::null_mut();
            if (fns.v1_2.GetJavaVM)(env, &mut vm) != JNI_OK || vm.is_null() {
                return;
            }
            let global = (fns.v1_2.NewGlobalRef)(env, context);
            if global.is_null() {
                return;
            }
            ndk_context::initialize_android_context(vm.cast(), global.cast());
            SET.store(true, Ordering::Release);
        }
    });
    SET.load(Ordering::Acquire)
}
