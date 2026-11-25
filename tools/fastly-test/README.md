# Existing Fastly diagnostic service

This restores the official Rust starter used for the existing fastly-test service during an earlier Blossom diagnostic session. The source revision is the last upstream commit before the recorded initialization: https://github.com/fastly/compute-starter-kit-rust-default/tree/c8f2a6248b6d8fb43ef8f245ccfaeb800d5e2606. See source-provenance.json for limits. The original deployed source SHA was not embedded, so this is a provenance-based restoration rather than a bit-for-bit package recovery.

Routing code and landing HTML are unchanged from that upstream source. The build pins Fastly SDK0.13.3 with url2.5.9 for RUSTSEC-2026-0592, the toolchain is pinned, and the manifest identifies the existing service. This standalone Cargo workspace does not alter the Blossom application.

From this directory, use `cargo build --locked --release --target wasm32-wasip1`, then `python3 tests/smoke.py --wasm target/wasm32-wasip1/release/fastly-compute-project.wasm --viceroy /path/to/viceroy`. Viceroy0.22 or newer is required. The tests use only a local runtime and check the recorded live landing fingerprint, routing and method behavior.

Deployment is separate and requires approval for this diagnostic target. Preserve its existing service configuration; do not initialize a replacement service. The upstream license is retained in LICENSE.
