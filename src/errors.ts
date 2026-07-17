export type TemplarErrorCode =
  | "AUTH_REQUIRED"
  | "BODY_TOO_LARGE"
  | "CONFLICT"
  | "INVALID_INPUT"
  | "NOT_FOUND"
  | "PCAP_INVALID"
  | "PCAP_LIMIT_EXCEEDED"
  | "RUN_NOT_ACTIVE"
  | "SERVICE_UNAVAILABLE"
  | "INTERNAL_ERROR";

export class TemplarError extends Error {
  readonly code: TemplarErrorCode;
  readonly status: number;
  readonly expose: boolean;

  constructor(options: {
    readonly code: TemplarErrorCode;
    readonly message: string;
    readonly status: number;
    readonly expose?: boolean;
    readonly cause?: unknown;
  }) {
    super(options.message, { cause: options.cause });
    this.name = "TemplarError";
    this.code = options.code;
    this.status = options.status;
    this.expose = options.expose ?? options.status < 500;
  }
}

export function invalidInput(message: string, cause?: unknown): TemplarError {
  return new TemplarError({ code: "INVALID_INPUT", message, status: 400, cause });
}

export function redactedError(error: unknown): {
  readonly status: number;
  readonly body: { readonly error: { readonly code: TemplarErrorCode; readonly message: string } };
} {
  const known = error instanceof TemplarError ? error : undefined;
  return {
    status: known?.status ?? 500,
    body: {
      error: {
        code: known?.code ?? "INTERNAL_ERROR",
        message: known?.expose === true ? known.message : "The request could not be completed.",
      },
    },
  };
}
