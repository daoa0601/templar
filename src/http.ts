import { timingSafeEqual } from "node:crypto";
import { readFile } from "node:fs/promises";
import http from "node:http";
import type { AddressInfo } from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { WORKFLOW_CATALOG } from "./catalog.js";
import type { TemplarConfig } from "./config.js";
import { decodeIncidentInput } from "./contracts.js";
import { redactedError, TemplarError } from "./errors.js";
import type { TemplarService } from "./service.js";

const DASHBOARD = fileURLToPath(new URL("../assets/dashboard/", import.meta.url));

function sendJson(response: http.ServerResponse, status: number, value: unknown): void {
  const body = `${JSON.stringify(value)}\n`;
  response.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(body),
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
  });
  response.end(body);
}

function authenticate(request: http.IncomingMessage, config: TemplarConfig): boolean {
  if (config.bearerToken === undefined) return true;
  const expected = Buffer.from(`Bearer ${config.bearerToken}`);
  const observedHeader = request.headers.authorization;
  if (observedHeader === undefined) return false;
  const observed = Buffer.from(observedHeader);
  return observed.length === expected.length && timingSafeEqual(observed, expected);
}

async function body(request: http.IncomingMessage, limit: number): Promise<Buffer> {
  const declared = Number(request.headers["content-length"] ?? 0);
  if (Number.isFinite(declared) && declared > limit) {
    throw new TemplarError({
      code: "BODY_TOO_LARGE",
      message: `Request body exceeds the ${limit}-byte limit.`,
      status: 413,
    });
  }
  const chunks: Array<Buffer> = [];
  let total = 0;
  for await (const raw of request) {
    const chunk = Buffer.isBuffer(raw) ? raw : Buffer.from(raw);
    total += chunk.length;
    if (total > limit) {
      throw new TemplarError({
        code: "BODY_TOO_LARGE",
        message: `Request body exceeds the ${limit}-byte limit.`,
        status: 413,
      });
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks, total);
}

function numericCursor(value: string | null): number {
  if (value === null || value === "") return 0;
  if (!/^[0-9]+$/u.test(value))
    throw new TemplarError({
      code: "INVALID_INPUT",
      message: "after must be a non-negative integer.",
      status: 400,
    });
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed))
    throw new TemplarError({
      code: "INVALID_INPUT",
      message: "after is out of range.",
      status: 400,
    });
  return parsed;
}

async function staticAsset(
  response: http.ServerResponse,
  name: "index.html" | "app.js" | "styles.css",
): Promise<void> {
  const data = await readFile(path.join(DASHBOARD, name));
  const contentType = name.endsWith(".html")
    ? "text/html; charset=utf-8"
    : name.endsWith(".js")
      ? "text/javascript; charset=utf-8"
      : "text/css; charset=utf-8";
  response.writeHead(200, {
    "Content-Type": contentType,
    "Content-Length": data.byteLength,
    "Cache-Control": "no-cache",
    "Content-Security-Policy":
      "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
  });
  response.end(data);
}

async function handle(
  request: http.IncomingMessage,
  response: http.ServerResponse,
  service: TemplarService,
): Promise<void> {
  const method = request.method ?? "GET";
  const url = new URL(request.url ?? "/", `http://${request.headers.host ?? "localhost"}`);
  if (method === "GET" && url.pathname === "/health/live")
    return sendJson(response, 200, { status: "ok" });
  if (method === "GET" && url.pathname === "/health/ready") {
    await service.initialize();
    return sendJson(response, 200, { status: "ready" });
  }
  if (method === "GET" && url.pathname === "/") return staticAsset(response, "index.html");
  if (method === "GET" && url.pathname === "/app.js") return staticAsset(response, "app.js");
  if (method === "GET" && url.pathname === "/styles.css")
    return staticAsset(response, "styles.css");

  if (!url.pathname.startsWith("/api/")) {
    throw new TemplarError({ code: "NOT_FOUND", message: "Route was not found.", status: 404 });
  }
  if (!authenticate(request, service.config)) {
    throw new TemplarError({
      code: "AUTH_REQUIRED",
      message: "A valid bearer token is required.",
      status: 401,
    });
  }

  if (method === "GET" && url.pathname === "/api/workflows") {
    return sendJson(response, 200, WORKFLOW_CATALOG);
  }
  if (method === "POST" && url.pathname === "/api/artifacts/pcap") {
    const contentType = request.headers["content-type"]?.split(";", 1)[0]?.trim().toLowerCase();
    if (
      contentType !== "application/vnd.tcpdump.pcap" &&
      contentType !== "application/octet-stream"
    ) {
      throw new TemplarError({
        code: "INVALID_INPUT",
        message: "PCAP upload content type is unsupported.",
        status: 415,
      });
    }
    return sendJson(
      response,
      201,
      await service.stagePcap(await body(request, service.config.maxPcapBytes)),
    );
  }
  if (method === "POST" && url.pathname === "/api/incidents") {
    const contentType = request.headers["content-type"]?.split(";", 1)[0]?.trim().toLowerCase();
    if (contentType !== "application/json")
      throw new TemplarError({
        code: "INVALID_INPUT",
        message: "Incident body must be JSON.",
        status: 415,
      });
    const encoded = await body(request, service.config.maxJsonBytes);
    let parsed: unknown;
    try {
      parsed = JSON.parse(encoded.toString("utf8"));
    } catch (cause) {
      throw new TemplarError({
        code: "INVALID_INPUT",
        message: "Incident body is not valid JSON.",
        status: 400,
        cause,
      });
    }
    return sendJson(
      response,
      202,
      await service.submitTelecomIncident(decodeIncidentInput(parsed)),
    );
  }
  if (method === "GET" && url.pathname === "/api/runs")
    return sendJson(response, 200, await service.listRuns());

  const match =
    /^\/api\/runs\/([A-Za-z0-9][A-Za-z0-9_-]{0,127})(?:\/(events|result|cancel|acknowledge))?$/u.exec(
      url.pathname,
    );
  if (match !== null) {
    const runId = match[1]!;
    const action = match[2];
    if (method === "GET" && action === undefined)
      return sendJson(response, 200, await service.inspectRun(runId));
    if (method === "GET" && action === "events")
      return sendJson(
        response,
        200,
        await service.events(runId, numericCursor(url.searchParams.get("after"))),
      );
    if (method === "GET" && action === "result")
      return sendJson(response, 200, await service.result(runId));
    if (method === "POST" && action === "cancel")
      return sendJson(response, 200, await service.cancel(runId));
    if (method === "POST" && action === "acknowledge") {
      const encoded = await body(request, service.config.maxJsonBytes);
      let parsed: unknown;
      try {
        parsed = JSON.parse(encoded.toString("utf8"));
      } catch (cause) {
        throw new TemplarError({
          code: "INVALID_INPUT",
          message: "Acknowledgment body is not valid JSON.",
          status: 400,
          cause,
        });
      }
      if (
        typeof parsed !== "object" ||
        parsed === null ||
        Array.isArray(parsed) ||
        Object.keys(parsed).length !== 1 ||
        !("rationale" in parsed) ||
        typeof parsed.rationale !== "string"
      ) {
        throw new TemplarError({
          code: "INVALID_INPUT",
          message: "Acknowledgment requires only a rationale string.",
          status: 400,
        });
      }
      return sendJson(response, 200, await service.acknowledgePromotion(runId, parsed.rationale));
    }
  }
  throw new TemplarError({ code: "NOT_FOUND", message: "Route was not found.", status: 404 });
}

export interface TemplarHttpServer {
  readonly server: http.Server;
  readonly origin: string;
  readonly close: () => Promise<void>;
}

export async function startHttpServer(
  service: TemplarService,
  options: { readonly port?: number; readonly host?: string } = {},
): Promise<TemplarHttpServer> {
  await service.initialize();
  const server = http.createServer((request, response) => {
    void handle(request, response, service).catch((error) => {
      const projected = redactedError(error);
      sendJson(response, projected.status, projected.body);
    });
  });
  const host = options.host ?? service.config.host;
  const port = options.port ?? service.config.port;
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => {
      server.off("error", reject);
      resolve();
    });
  });
  const address = server.address() as AddressInfo;
  return {
    server,
    origin: `http://${address.family === "IPv6" ? `[${address.address}]` : address.address}:${address.port}`,
    close: () =>
      new Promise<void>((resolve, reject) =>
        server.close((error) => (error === undefined ? resolve() : reject(error))),
      ),
  };
}
