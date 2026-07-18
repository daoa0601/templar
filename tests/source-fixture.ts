import type { SourceSnapshot } from "../src/source.js";

export function sourceSnapshot(): SourceSnapshot {
  return {
    schema_version: "1",
    repository: { name: "sample-service", revision: "0123456789abcdef" },
    files: [
      {
        path: "src/app.ts",
        content: `import { readFile } from "node:fs/promises";

app.get("/files", async (req, res) => {
  const name = req.query.name;
  const data = await readFile(\`/srv/files/\${name}\`, "utf8");
  res.send(data);
});
`,
      },
      {
        path: "src/worker.ts",
        content: `export async function handler(event: { command: string }) {
  return event.command;
}
`,
      },
      {
        path: "tests/app.test.ts",
        content: `test("reads a fixture", async () => readFile("fixture.txt", "utf8"));\n`,
      },
      { path: "README.md", content: "# Sample service\n" },
    ],
  };
}
