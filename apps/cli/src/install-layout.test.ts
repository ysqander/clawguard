import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";
import { pathToFileURL } from "node:url";

import {
  resolveCurrentEntrypointPath,
  resolveDefaultDaemonEntrypointPath,
  resolveDefaultServiceWorkingDirectory,
} from "./install-layout.js";

test("resolveDefaultDaemonEntrypointPath prefers the packaged daemon when present", () => {
  const entrypointPath = resolveCurrentEntrypointPath();
  const moduleUrl = pathToFileURL(entrypointPath).href;

  const resolved = resolveDefaultDaemonEntrypointPath({
    moduleUrl,
    pathExists: (filePath) => filePath.endsWith(`${path.sep}daemon.js`),
  });

  assert.equal(resolved, path.resolve(path.dirname(entrypointPath), "daemon.js"));
});

test("resolveDefaultDaemonEntrypointPath falls back to the repo daemon during local development", () => {
  const entrypointPath = resolveCurrentEntrypointPath();
  const moduleUrl = pathToFileURL(entrypointPath).href;

  const resolved = resolveDefaultDaemonEntrypointPath({
    moduleUrl,
    pathExists: (filePath) => filePath.includes(`${path.sep}apps${path.sep}daemon${path.sep}dist`),
  });

  assert.match(resolved, /apps\/daemon\/dist\/index\.js$/u);
});

test("resolveDefaultServiceWorkingDirectory prefers HOME when set", () => {
  assert.equal(resolveDefaultServiceWorkingDirectory("/Users/tester"), "/Users/tester");
});
