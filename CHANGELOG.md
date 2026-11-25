# Changelog

## 1.0.0
- Initial Android local VPN DNS-filtering prototype.
- Added a system-wide DNS interception route for Android's configured VPN resolver.
- Added conservative domain suffix filtering and a Cloudflare/Google UDP DNS upstream.
- Added basic blocked/allowed query counters.
- Added CI build workflow for a debug APK.
- CI compilation fix: removed an unreachable checked-exception catch from the packet loop.
