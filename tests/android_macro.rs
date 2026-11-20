//! The JNI export macro expands on Android and to nothing elsewhere, so apps can call it
//! unconditionally (checked for Android with `cargo clippy --tests --target aarch64-linux-android`).

weirdnet_net::android_context_init!(Java_org_weirdbrains_test_RustContext_nativeInit);

#[test]
fn the_macro_compiles_on_every_target() {
    #[cfg(target_os = "android")]
    {
        let _exported = Java_org_weirdbrains_test_RustContext_nativeInit;
    }
}
