# DiTz AdShield

Android local DNS filtering VPN. This is an experimental, no-root DNS blocker for all apps on the device.

## Build

GitHub Actions builds a debug APK on every push to `main` and supports manual runs.

1. Open **Actions → Android APK**.
2. Select **Run workflow** for a manual build, or wait for the push build.
3. Download the `DiTz-AdShield-debug-apk` artifact from a successful run.
4. Install the APK on Android and approve the Android VPN permission.

The APK is a debug build, not a Play Store release.

## Current scope and limitations

- Uses Android `VpnService` as a local DNS filter; it is not a remote VPN tunnel.
- Intercepts standard IPv4 UDP DNS sent through Android's configured VPN DNS server.
- Does not inspect HTTPS or decrypt application traffic.
- Does not reliably block hard-coded IPs, ads served from the same domain as app content, or app-controlled DoH/DoT.
- This initial engine does not yet implement TCP DNS or IPv6 DNS interception.
- Android permits only one active VPN at a time. Other VPN apps conflict.
- Public DNS resolvers receive the domain names for allowed lookups.
- False positives can break application features. Stop protection if an app loses connectivity.

**No 100% ad-blocking guarantee is made.** Test the apps and networks you use before relying on this software.
