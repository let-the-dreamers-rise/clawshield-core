/**
 * Injected at the top of every module in the browser bundle (esbuild `inject`), so code that
 * uses the Node global `Buffer` gets the `buffer` package's implementation instead.
 */
export { Buffer } from "buffer";
