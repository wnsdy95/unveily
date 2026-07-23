import { spawnSync } from "node:child_process";

const thresholds = Object.freeze({ lines: 39, branches: 38, functions: 44 });
const runtimeSuites = [
  "test/backgroundRuntime.test.js",
  "test/backgroundCookieRuntime.test.js",
  "test/backgroundInitializationRuntime.test.js"
];
const expectedRuntimeEvidence = [
  "background isolates same-route navigations",
  "background cookie batching preserves attribution",
  "initialization queue preserves another tab's main-frame boundary"
];
const args = [
  "--test",
  "--test-concurrency=1",
  "--experimental-test-coverage",
  "--test-coverage-include=src/background.js",
  `--test-coverage-lines=${thresholds.lines}`,
  `--test-coverage-branches=${thresholds.branches}`,
  `--test-coverage-functions=${thresholds.functions}`,
  ...runtimeSuites
];

const result = spawnSync(process.execPath, args, {
  cwd: process.cwd(),
  encoding: "utf8",
  env: {
    ...process.env,
    FORCE_COLOR: "0",
    NO_COLOR: "1",
    NODE_DISABLE_COLORS: "1"
  },
  maxBuffer: 16 * 1024 * 1024
});

if (result.stdout) process.stdout.write(result.stdout);
if (result.stderr) process.stderr.write(result.stderr);
if (result.error) {
  process.stderr.write(`Background coverage runner failed: ${result.error.message}\n`);
  process.exitCode = 1;
} else if (result.status !== 0) {
  process.exitCode = Number.isInteger(result.status) ? result.status : 1;
} else {
  const output = `${result.stdout || ""}\n${result.stderr || ""}`.replace(
    /\u001b\[[0-9;]*m/g,
    ""
  );
  const backgroundRow = output.match(
    /\bbackground\.js\s*\|\s*([\d.]+)\s*\|\s*([\d.]+)\s*\|\s*([\d.]+)\s*\|/
  );
  const coverage = output.match(
    /\ball files\s*\|\s*([\d.]+)\s*\|\s*([\d.]+)\s*\|\s*([\d.]+)\s*\|/
  );
  const missingEvidence = expectedRuntimeEvidence.filter((label) => !output.includes(label));

  if (!backgroundRow || !coverage || missingEvidence.length > 0) {
    const details = [
      !backgroundRow ? "no background.js coverage row" : "",
      !coverage ? "no include-filtered aggregate coverage row" : "",
      missingEvidence.length > 0 ? `missing runtime suites: ${missingEvidence.join(", ")}` : ""
    ]
      .filter(Boolean)
      .join("; ");
    process.stderr.write(`Background coverage evidence check failed: ${details}\n`);
    process.exitCode = 1;
  } else {
    const [lines, branches, functions] = coverage.slice(1).map(Number);
    if (
      lines < thresholds.lines ||
      branches < thresholds.branches ||
      functions < thresholds.functions
    ) {
      process.stderr.write(
        `Background aggregate coverage is below the configured floor: ${lines}/${branches}/${functions}\n`
      );
      process.exitCode = 1;
    } else {
      process.stdout.write(
        `Background coverage gate verified background.js aggregate: lines ${lines}%, branches ${branches}%, functions ${functions}%.\n`
      );
    }
  }
}
