// `join.js` instructs esbuild to join all ed25519 tool js files into one
// file. Use one of the following commands for either human readable or
// minified.  From ESBuild's docs concerning for multiple files:
//
// > Note that bundling is different than file concatenation. Passing esbuild
// multiple input files with bundling enabled will create multiple separate
// bundles instead of joining the input files together. To join a set of files
// together with esbuild, import them all into a single entry point file and
// bundle just that one file with esbuild.
//
// For single page, or non modules, use `iife` format. This app was
// created with:
//
// ```
// esbuild join.js --bundle --format=iife --minify --sourcemap --platform=browser  --outfile=app.min.js
// ```
//
// Also useful for development.  The only point of the `*.join.js` file is
// human readable debugging. 
//```
// esbuild join.js --bundle --format=esm                                           --outfile=app.join.js
// ```
//
//For modules, use `esm` format.
// ```
// esbuild join.js --bundle --format=esm  --minify --sourcemap                     --outfile=app.min.js
// ```
//
export * from './app.js';
export * from './noble-ed25519.js';