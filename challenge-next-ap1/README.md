# AP-01 runtime

This directory contains the isolated AP-01 Next.js runtime used by the local
challenge environment. It intentionally preserves the documented middleware
behavior for the exercise; it is not a general-purpose web service.

## Runtime contract

- Next.js is locked to `13.2.4` in both the manifest and lockfile.
- The Dockerfile uses the Debian/glibc Node image family and fails the build
  when the Next.js executable is absent after `npm ci`.
- The base-image digest remains intentionally unpinned until the Product Owner
  records successful native armv7 dependency installation, production build,
  and runtime startup for the same revision.

## Desktop verification

Build the image from this directory, start it without a challenge-flag mount,
then run the runtime check with `AP1_BASE_URL` set to its local HTTP address.
The check verifies production startup, ordinary protected-route rejection,
the documented special-header handler path, and the fixed non-secret 503
response when no flag is available.

Desktop verification is an alternative-environment check only. It does not
prove native armv7 compatibility and does not replace Product Owner native
armv7 validation.
