import { readFileSync, writeFileSync } from "node:fs";

const inputPath = process.argv[2];
const outputPath = process.argv[3];

if (!inputPath || !outputPath) {
  console.error("Usage: node node_convert.mjs <input-file> <output-json>");
  process.exit(2);
}

let input;

try {
  input = readFileSync(inputPath, "utf8");
} catch (error) {
  console.error(`Cannot read input file: ${error.message}`);
  process.exit(2);
}

let mod;

try {
  mod = await import("singbox-converter");
} catch (error) {
  console.error("singbox-converter is not installed");
  process.exit(3);
}

const fn =
  mod.convertToOutbounds ||
  mod.default?.convertToOutbounds ||
  (typeof mod.default === "function" ? mod.default : undefined);

if (typeof fn !== "function") {
  console.error("convertToOutbounds function not found in singbox-converter");
  process.exit(4);
}

let result = fn(input);

if (result && typeof result.then === "function") {
  result = await result;
}

let outbounds = [];

if (Array.isArray(result)) {
  outbounds = result;
} else if (result && Array.isArray(result.outbounds)) {
  outbounds = result.outbounds;
} else if (result && typeof result === "object") {
  outbounds = [result];
}

writeFileSync(outputPath, JSON.stringify(outbounds, null, 2));

console.log(
  JSON.stringify({
    outbounds: outbounds.length,
  })
);
