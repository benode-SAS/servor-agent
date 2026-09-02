/**
 * Version of the source this binary was compiled from.
 *
 * @remarks
 * Reported with every metrics push and compared against the version the control
 * plane advertises to decide whether to self-update. It lives in source rather
 * than in `package.json` because a compiled executable carries no package
 * metadata. `scripts/write-manifest.ts` copies it into `dist/manifest.json`
 * only after the binaries exist, so the API can never advertise a version for
 * which no binary was built.
 */
export const BUILD_VERSION = '1.1.3';
