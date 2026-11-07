#!/usr/bin/env node
import { readdir, readFile } from "node:fs/promises";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const testName = /(?:^|[_.-])(?:tests?|spec)(?:[_.-]|$)/;
const moduleToken = /((?:^[\t ]*#\[[^\]]*\]\s*)*)(?:pub(?:\([^)]*\))?\s+)?mod\s+(\w+)\s*([;{])|[{}]/gm;
const violations = [];

function isTestConfiguration(attributes) {
  return /\bcfg\s*\([^\]]*\btest\b/.test(attributes.replace(/\bnot\s*\(\s*test\s*\)/g, ""));
}

function rustCode(source) {
  const trivia = /\/\/[^\n]*|\/\*|(?:b|c)?r(#{0,})"[\s\S]*?"\1|(?:b|c)?"(?:\\[\s\S]|[^"\\])*"|'(?:\\(?:u\{[^}]*\}|x[\da-fA-F]{2}|.)|[^'\\\n])'/g;
  let code = "";
  let offset = 0;
  for (let match; (match = trivia.exec(source)) !== null;) {
    let end = trivia.lastIndex;
    if (match[0] === "/*") {
      let depth = 1;
      while (depth > 0 && end < source.length) {
        if (source.startsWith("/*", end)) {
          depth++;
          end += 2;
        } else if (source.startsWith("*/", end)) {
          depth--;
          end += 2;
        } else {
          end++;
        }
      }
      trivia.lastIndex = end;
    }
    code += source.slice(offset, match.index) + source.slice(match.index, end).replace(/[^\n]/g, " ");
    offset = end;
  }
  return code + source.slice(offset);
}

async function check(directory) {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) {
      if (testName.test(entry.name)) {
        violations.push(`${relative(root, path)}: standalone test directories are not allowed in source directories`);
      }
      await check(path);
    } else if (entry.isFile() && /\.(?:rs|[cm]?[jt]sx?)$/.test(entry.name)) {
      const name = relative(root, path);
      if (testName.test(entry.name)) {
        violations.push(`${name}: standalone test files are not allowed in source directories`);
      }
      if (entry.name.endsWith(".rs")) {
        const source = rustCode(await readFile(path, "utf8"));
        if ([...source.matchAll(/^\s*#!\[[^\]]*\]/gm)].some(([attribute]) => isTestConfiguration(attribute))) {
          violations.push(`${name}: test-only source files must be inline modules`);
        }
        const scopes = [false];
        for (const match of source.matchAll(moduleToken)) {
          if (match[2]) {
            const testModule = scopes.at(-1) || testName.test(match[2]) || isTestConfiguration(match[1]);
            if (match[3] === "{") {
              scopes.push(testModule);
            } else if (testModule) {
              const line = source.slice(0, match.index).split("\n").length;
              violations.push(`${name}:${line}: test module ${match[2]} must be inline`);
            }
          } else if (match[0] === "{") {
            scopes.push(scopes.at(-1));
          } else {
            scopes.pop();
          }
        }
      }
    }
  }
}

await check(join(root, "src"));
for (const entry of await readdir(join(root, "crates"), { withFileTypes: true })) {
  if (entry.isDirectory()) {
    await check(join(root, "crates", entry.name, "src"));
  }
}

if (violations.length > 0) {
  console.error(violations.join("\n"));
  console.error("Keep unit tests in inline #[cfg(test)] modules and integration tests under tests/.");
  process.exitCode = 1;
}
