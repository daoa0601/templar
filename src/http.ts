import { readFile } from "node:fs/promises";
import http from "node:http";
import type { AddressInfo } from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  HttpGuardrailError,
  matchesBearerToken,
  readBoundedBody,
  readBoundedJson,
  requestMediaType,
  sendJson as sendHardenedJson,
} from "@agentic-orch/node-guardrails/http";

import { WORKFLOW_CATALOG } from "./catalog.js";
import { isLoopbackHost, type TemplarConfig } from "./config.js";
import {
  decodeExerciseSolveInput,
  decodeIncidentInput,
  decodePcapSecurityTriageInput,
  decodeSourceSecurityAuditInput,
  decodeSourceSecurityFixInput,
  decodeSourceFixValidationInput,
} from "./contracts.js";
import { redactedError, TemplarError } from "./errors.js";
import type { TemplarService } from "./service.js";

const DASHBOARD = fileURLToPath(new URL("../assets/dashboard/", import.meta.url));
const REJECTED_BODY_CLEANUP_MS = 1_000;

function sendJson(response: http.ServerResponse, status: number, value: unknown): void {
  sendHardenedJson(response, status, value, { newline: true });
}

function singleHeader(request: http.IncomingMessage, name: string): string | undefined {
  const values = request.headersDistinct[name];
  return values?.length === 1 ? values[0] : undefined;
}

function loopbackRequestOrigin(request: http.IncomingMessage): string | undefined {
  const host = singleHeader(request, "host");
  if (host === undefined) return undefined;
  try {
    const origin = new URL(`http://${host}`);
    if (
      origin.username !== "" ||
      origin.password !== "" ||
      origin.pathname !== "/" ||
      origin.search !== "" ||
      origin.hash !== ""
    ) {
      return undefined;
    }
    const hostname = origin.hostname.toLowerCase();
    return hostname === "127.0.0.1" || hostname === "localhost" || hostname === "[::1]"
      ? origin.origin
      : undefined;
  } catch {
    return undefined;
  }
}

function allowTokenlessLoopbackRequest(request: http.IncomingMessage): boolean {
  const requestOrigin = loopbackRequestOrigin(request);
  if (requestOrigin === undefined) return false;

  const fetchSite = singleHeader(request, "sec-fetch-site");
  if (request.headers["sec-fetch-site"] !== undefined && fetchSite === undefined) return false;
  if (fetchSite !== undefined && fetchSite !== "same-origin" && fetchSite !== "none") return false;

  const header = singleHeader(request, "origin");
  if (request.headers.origin !== undefined && header === undefined) return false;
  if (header === undefined) return true;
  if (header === "null") return false;
  try {
    const origin = new URL(header);
    return (
      origin.origin !== "null" &&
      origin.username === "" &&
      origin.password === "" &&
      origin.pathname === "/" &&
      origin.search === "" &&
      origin.hash === "" &&
      origin.origin === requestOrigin
    );
  } catch {
    return false;
  }
}

function authenticate(request: http.IncomingMessage, config: TemplarConfig): boolean {
  if (config.bearerToken === undefined) return allowTokenlessLoopbackRequest(request);
  return matchesBearerToken(request.headers.authorization, config.bearerToken);
}

function bodyError(cause: HttpGuardrailError, limit: number): TemplarError {
  if (cause.kind === "body_too_large") {
    return new TemplarError({
      code: "BODY_TOO_LARGE",
      message: `Request body exceeds the ${limit}-byte limit.`,
      status: 413,
      cause,
    });
  }
  if (cause.kind === "media_type_unsupported") {
    return new TemplarError({
      code: "INVALID_INPUT",
      message: "Request body must be JSON.",
      status: 415,
      cause,
    });
  }
  if (cause.kind === "json_invalid") {
    return new TemplarError({
      code: "INVALID_INPUT",
      message: "Request body is not valid JSON.",
      status: 400,
      cause,
    });
  }
  return new TemplarError({
    code: "INVALID_INPUT",
    message:
      cause.kind === "content_encoding_unsupported"
        ? "Compressed request bodies are not accepted."
        : cause.kind === "content_length_invalid"
          ? "Content-Length is invalid."
          : cause.message,
    status: cause.status,
    cause,
  });
}

async function body(
  request: http.IncomingMessage,
  response: http.ServerResponse,
  limit: number,
): Promise<Buffer> {
  try {
    return await readBoundedBody(request, {
      limitBytes: limit,
      rejection: {
        action: "respond-and-close",
        response,
        timeoutMs: REJECTED_BODY_CLEANUP_MS,
      },
    });
  } catch (cause) {
    if (cause instanceof HttpGuardrailError) throw bodyError(cause, limit);
    throw cause;
  }
}

async function jsonBody(
  request: http.IncomingMessage,
  response: http.ServerResponse,
  limit: number,
): Promise<unknown> {
  try {
    return await readBoundedJson(request, {
      limitBytes: limit,
      rejection: {
        action: "respond-and-close",
        response,
        timeoutMs: REJECTED_BODY_CLEANUP_MS,
      },
    });
  } catch (cause) {
    if (cause instanceof HttpGuardrailError) throw bodyError(cause, limit);
    throw cause;
  }
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
  if (method === "GET" && url.pathname === "/api/labs") {
    return sendJson(response, 200, await service.labProviders());
  }
  if (method === "POST" && url.pathname === "/api/artifacts/pcap") {
    const contentType = requestMediaType(request);
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
      await service.stagePcap(await body(request, response, service.config.maxPcapBytes)),
    );
  }
  if (method === "POST" && url.pathname === "/api/artifacts/exercise-snapshot") {
    return sendJson(
      response,
      201,
      await service.stageExerciseSnapshot(
        await jsonBody(request, response, service.config.maxExerciseSnapshotBytes),
      ),
    );
  }
  if (method === "POST" && url.pathname === "/api/artifacts/source-snapshot") {
    return sendJson(
      response,
      201,
      await service.stageSourceSnapshot(
        await jsonBody(request, response, service.config.maxSourceSnapshotBytes),
      ),
    );
  }
  if (
    method === "POST" &&
    (url.pathname === "/api/incidents" || url.pathname === "/api/workflows/telecom_incident/runs")
  ) {
    return sendJson(
      response,
      202,
      await service.submitTelecomIncident(
        decodeIncidentInput(await jsonBody(request, response, service.config.maxJsonBytes)),
      ),
    );
  }
  if (method === "POST" && url.pathname === "/api/workflows/pcap_security_triage/runs") {
    return sendJson(
      response,
      202,
      await service.submitPcapSecurityTriage(
        decodePcapSecurityTriageInput(
          await jsonBody(request, response, service.config.maxJsonBytes),
        ),
      ),
    );
  }
  if (method === "POST" && url.pathname === "/api/workflows/exercise_solve/runs") {
    return sendJson(
      response,
      202,
      await service.submitExerciseSolve(
        decodeExerciseSolveInput(await jsonBody(request, response, service.config.maxJsonBytes)),
      ),
    );
  }
  if (method === "POST" && url.pathname === "/api/workflows/source_security_audit/runs") {
    return sendJson(
      response,
      202,
      await service.submitSourceSecurityAudit(
        decodeSourceSecurityAuditInput(
          await jsonBody(request, response, service.config.maxJsonBytes),
        ),
      ),
    );
  }
  if (method === "POST" && url.pathname === "/api/workflows/source_security_fix/runs") {
    return sendJson(
      response,
      202,
      await service.submitSourceSecurityFix(
        decodeSourceSecurityFixInput(
          await jsonBody(request, response, service.config.maxJsonBytes),
        ),
      ),
    );
  }
  if (method === "GET" && url.pathname === "/api/runs")
    return sendJson(response, 200, await service.listRuns());

  const match =
    /^\/api\/runs\/([A-Za-z0-9][A-Za-z0-9_-]{0,127})(?:\/(events|result|cancel|acknowledge|verify|verification))?$/u.exec(
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
      const parsed = await jsonBody(request, response, service.config.maxJsonBytes);
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
    if (method === "POST" && action === "verify") {
      const parsed = decodeSourceFixValidationInput(
        await jsonBody(request, response, service.config.maxJsonBytes),
      );
      return sendJson(
        response,
        202,
        await service.submitSourceFixValidation(runId, parsed.rationale),
      );
    }
    if (method === "GET" && action === "verification") {
      return sendJson(response, 200, await service.sourceFixValidation(runId));
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
  const host = options.host ?? service.config.host;
  const port = options.port ?? service.config.port;
  if (service.config.bearerToken === undefined && !isLoopbackHost(host)) {
    throw new TemplarError({
      code: "INVALID_INPUT",
      message: "A bearer token is required for a non-loopback HTTP listener.",
      status: 400,
    });
  }
  await service.initialize();
  const server = http.createServer((request, response) => {
    void handle(request, response, service).catch((error) => {
      const projected = redactedError(error);
      sendJson(response, projected.status, projected.body);
    });
  });
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
