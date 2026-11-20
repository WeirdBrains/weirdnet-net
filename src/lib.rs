#![doc = include_str!("../README.md")]
pub mod addr;
#[cfg(target_os = "android")]
pub mod android;
pub mod app;
pub mod content;
mod error;
pub mod events;
pub mod exchange;
pub mod identity;
pub mod ingress;
pub mod invite;
pub mod join;
pub mod locator;
pub mod member;
pub mod names;
pub mod node;
pub mod peers;
pub mod profile;
pub mod sealed;
pub mod shard;
pub mod stream;
pub mod sync;
pub mod user;
pub mod wire;
pub mod wss;

pub use app::{AppError, AppHandler, AppRequest, AppResponse, Body as AppBody};
pub use error::{NetError, Result};
pub use events::{Event, Events, StatusWatch};
pub use exchange::{Answer, DEFAULT_TTL_MS, Derived, Offer, Token, normalize_code};
pub use libp2p::identity::{Keypair, PublicKey};
pub use libp2p::{Multiaddr, PeerId};
pub use node::{Handler, Message, Node, NodeConfig, RelayLimits, Sighting, Status};
pub use peers::{DiscoveryMode, PeerHint, decode_peers, encode_peers};
pub use profile::{Profile, RESERVED_LINK_SCHEME, WEIRDNET};
pub use stream::{Incoming, Limits, Path, Stream};
pub use weirdnet_keys::{Key32, Sealed};
pub use wss::WssTls;

/// Exports the JNI native method an Android app calls once at startup to initialize
/// `ndk-context` (see `weirdnet_net::android`, built on Android only). Without it, a node that
/// resolves DNS panics on Android. Give it the full JNI name of your Kotlin `external fun`:
/// `Java_<package with _ for .>_<Class>_<method>`. On other targets it expands to nothing, so
/// it can be called unconditionally.
///
/// ```ignore
/// // Rust (the app's bridge crate):
/// weirdnet_net::android_context_init!(Java_org_weirdbrains_bragi_RustContext_nativeInit);
/// ```
///
/// ```kotlin
/// // Kotlin, org.weirdbrains.bragi.RustContext, called before anything touches Rust:
/// object RustContext {
///     init { System.loadLibrary("bragi_bridge") }
///     @JvmStatic external fun nativeInit(context: Context)
/// }
/// ```
#[macro_export]
macro_rules! android_context_init {
    ($name:ident) => {
        #[cfg(target_os = "android")]
        /// JNI entry point: initializes `ndk-context` (`weirdnet_net::android::init_context`).
        ///
        /// # Safety
        /// Called by the JVM with a valid `env` and a live application `Context`.
        #[unsafe(no_mangle)]
        pub unsafe extern "system" fn $name(
            env: *mut $crate::android::jni_sys::JNIEnv,
            _class: $crate::android::jni_sys::jclass,
            context: $crate::android::jni_sys::jobject,
        ) {
            // SAFETY: forwarded from the JVM's call, see above.
            unsafe {
                $crate::android::init_context(env, context);
            }
        }
    };
}

/// The last 8 characters of a peer id.
pub fn short_peer_id(p: &PeerId) -> String {
    identity::short_peer(&p.to_string()).to_string()
}

/// Milliseconds since the Unix epoch.
pub fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

#[cfg(test)]
mod app_tests;
#[cfg(test)]
mod content_tests;
#[cfg(test)]
mod discovery_tests;
#[cfg(test)]
mod dnsaddr_tests;
#[cfg(test)]
mod events_tests;
#[cfg(test)]
mod ingress_tests;
#[cfg(test)]
mod member_tests;
#[cfg(test)]
mod names_tests;
#[cfg(test)]
mod relay_tests;
#[cfg(test)]
mod sealed_tests;
#[cfg(test)]
mod stream_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod wire_tests;
#[cfg(test)]
mod wss_tests;
