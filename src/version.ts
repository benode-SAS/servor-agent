// Single source of truth for the compiled agent version. The build writes it
// into dist/manifest.json (see scripts/write-manifest.ts) so the API only ever
// advertises a version for which a real binary exists.
export const BUILD_VERSION = '1.0.6';
