# Releasing Veiltrium

## One-time signing-key setup

The release workflow is fail-closed: it will not publish an installer until the private/public key pair is configured and the same public key is embedded in `veiltrium.sh` as `UPDATE_PUBLIC_KEY_PEM`.

Generate the pair on your own trusted machine, not in CI and not in the repository:

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out vt-release-private.pem
openssl pkey -in vt-release-private.pem -pubout -out vt-release-public.pem
chmod 600 vt-release-private.pem
```

1. Put the contents of `vt-release-public.pem` into `UPDATE_PUBLIC_KEY_PEM` in `veiltrium.sh` as one double-quoted, multiline value. The public key is not secret.
2. In GitHub, open **Settings → Secrets and variables → Actions**:
   - create secret `VT_RELEASE_PRIVATE_KEY` with the complete `vt-release-private.pem`;
   - create variable `VT_RELEASE_PUBLIC_KEY` with the complete `vt-release-public.pem`.
3. Verify the pair locally:

   ```bash
   openssl pkey -in vt-release-private.pem -pubout -outform PEM | cmp - vt-release-public.pem
   printf test > release-test
   openssl dgst -sha256 -sign vt-release-private.pem -out release-test.sig release-test
   openssl dgst -sha256 -verify vt-release-public.pem -signature release-test.sig release-test
   rm -f release-test release-test.sig
   ```

4. Remove the local private-key file after GitHub accepts the secret. Do not commit it, paste it into an issue or send it through chat.

Until these steps are complete, `veiltrium --update` refuses to run a new script rather than trusting an unsigned one, and `installer-release.yml` stops at preflight.

## Installer release

1. Merge the intended changes with green FAST and the required integration checks. Update `SCRIPT_VERSION`, both changelogs and any pinned panel version/SHA-256 values.
2. Ensure `PANEL_VERSION` refers to an already published `panel-v*` release whose non-test source matches `main`.
3. Create an installer tag `vYYYY.MM.DD` or `vYYYY.MM.DD.N` and push it.
4. `installer-release.yml` verifies the key pair and the public key embedded in the script, runs FULL on Ubuntu 24.04 and 26.04 with the published panel, runs FAST again, then publishes:
   - `veiltrium.sh`;
   - `veiltrium.sh.sig`, the detached OpenSSL signature;
   - `SHA256SUMS`.
5. Verify the published asset independently:

   ```bash
   TAG=vYYYY.MM.DD.N
   curl -fsSLO "https://github.com/Vanilla-SilQ-HD/Veiltrium/releases/download/${TAG}/veiltrium.sh"
   curl -fsSLO "https://github.com/Vanilla-SilQ-HD/Veiltrium/releases/download/${TAG}/veiltrium.sh.sig"
   openssl dgst -sha256 -verify vt-release-public.pem -signature veiltrium.sh.sig veiltrium.sh
   ```

Do not edit release assets after publication. Make a new tag for any change.

## Panel release

A `panel-vX.Y.Z` tag runs `panel-release.yml`, which tests and publishes static amd64/arm64 binaries and `SHA256SUMS`. Update `PANEL_VERSION` and both panel hashes in the installer before the installer FULL release check.
