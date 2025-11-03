import { randomUUIDv5, type Server } from "bun";

// Simple HTTP status codes and response helpers for Bun (Fetch API compatible)

export enum StatusCodes {
    // 2xx
    OK = 200,
    CREATED = 201,
    NO_CONTENT = 204,

    // 3xx
    MOVED_PERMANENTLY = 301,
    FOUND = 302,

    // 4xx
    BAD_REQUEST = 400,
    UNAUTHORIZED = 401,
    FORBIDDEN = 403,
    NOT_FOUND = 404,
    METHOD_NOT_ALLOWED = 405,
    CONFLICT = 409,
    UNPROCESSABLE_ENTITY = 422,

    // 5xx
    INTERNAL_SERVER_ERROR = 500,
    NOT_IMPLEMENTED = 501,
    SERVICE_UNAVAILABLE = 503,
}

export type HeadersInitRecord = Record<string, string>;

/**
 * Create a JSON Response (works in Bun, uses the Fetch Response API)
 */
export function jsonResponse(
    data: unknown,
    status: StatusCodes = StatusCodes.OK,
    headers?: HeadersInitRecord
): Response {
    if (status === StatusCodes.NO_CONTENT) {
        return new Response(null, { status, headers });
    }
    const finalHeaders: HeadersInitRecord = {
        'Content-Type': 'application/json; charset=utf-8',
        ...headers,
    };
    return new Response(JSON.stringify(data), { status, headers: finalHeaders });
}

/**
 * Create a plain text Response
 */
export function textResponse(
    text: string,
    status: StatusCodes = StatusCodes.OK,
    headers?: HeadersInitRecord
): Response {
    const finalHeaders: HeadersInitRecord = {
        'Content-Type': 'text/plain; charset=utf-8',
        ...headers,
    };
    return new Response(text, { status, headers: finalHeaders });
}

/**
 * Create a redirect Response with Location header
 */
export function redirectResponse(
    location: string,
    status: StatusCodes = StatusCodes.FOUND
): Response {
    return new Response(null, { status, headers: { Location: location } });
}



/**
 * Create a problem response for a specific issue
 */
export function problemResponse(
    title: string,
    detail: string,
    status: StatusCodes,
    instance?: string,
    type?: string,
    additionalProps?: Record<string, unknown>
): Response {
    const defaultType = `about:blank`; // https://datatracker.ietf.org/doc/html/rfc9457#section-3.1.1
    const problemDetails = {
        title,
        detail,
        status,
        type: type || defaultType,
        ...(instance && { instance }),
        ...additionalProps,
    };

    const headers: HeadersInitRecord = {
        'Content-Type': 'application/problem+json',
    };

    return jsonResponse(problemDetails, status, headers);
}

/**
 * Create a bad request 400 problem response
 */
export function badRequestResponse(detail: string, instance?: string, type?: string, additionalProps?: Record<string, unknown>): Response {
    return problemResponse("Bad Request", detail, StatusCodes.BAD_REQUEST, instance, type, additionalProps);
}

/**
 * Create an unauthorized 401 problem response
 */
export function unauthorizedResponse(detail: string, instance?: string, type?: string, additionalProps?: Record<string, unknown>): Response {
    return problemResponse("Unauthorized", detail, StatusCodes.UNAUTHORIZED, instance, type, additionalProps);
}

/**
 * Create a forbidden 403 problem response
 */
export function forbiddenResponse(detail: string, instance?: string, type?: string, additionalProps?: Record<string, unknown>): Response {
    return problemResponse("Forbidden", detail, StatusCodes.FORBIDDEN, instance, type, additionalProps);
}

/**
 * Create a not found 404 problem response
 */
export function notFoundResponse(detail: string, instance?: string, type?: string, additionalProps?: Record<string, unknown>): Response {
    return problemResponse("Not Found", detail, StatusCodes.NOT_FOUND, instance, type, additionalProps);
}

/**
 * Create a conflict 409 problem response
 */
export function conflictResponse(detail: string, instance?: string, type?: string, additionalProps?: Record<string, unknown>): Response {
    return problemResponse("Conflict", detail, StatusCodes.CONFLICT, instance, type, additionalProps);
}

/**
 * Create an unprocessable entity 422 problem response
 */
export function unprocessableEntityResponse(detail: string, instance?: string, type?: string, additionalProps?: Record<string, unknown>): Response {
    return problemResponse("Unprocessable Entity", detail, StatusCodes.UNPROCESSABLE_ENTITY, instance, type, additionalProps);
}

/**
 * Create an internal server error 500 problem response
 */
export function internalServerErrorResponse(detail: string, instance?: string, type?: string, additionalProps?: Record<string, unknown>): Response {
    return problemResponse("Internal Server Error", detail, StatusCodes.INTERNAL_SERVER_ERROR, instance, type, additionalProps);
}

/**
 * Create a method not allowed 405 problem response with required Allow header
 * @param allowedMethods - Array of allowed HTTP methods (e.g., ['GET', 'POST'])
 */
export function methodNotAllowedResponse(
    allowedMethods: string[],
    detail: string,
    instance?: string,
    type?: string,
    additionalProps?: Record<string, unknown>
): Response {
    const headers: HeadersInitRecord = {
        'Allow': allowedMethods.join(', ')
    };
    return problemResponse(
        "Method Not Allowed",
        detail,
        StatusCodes.METHOD_NOT_ALLOWED,
        instance,
        type,
        { ...additionalProps, headers }
    );
}

////////////////////////////
// Utility Functions
////////////////////////////

/**
 * Attempts to parse a string into a URL object.
 * 
 * @param url - The string URL to parse
 * @returns A URL object if parsing is successful, null otherwise
 * 
 * @example
 * ```typescript
 * const validUrl = tryParseURL('https://example.com'); // Returns URL object
 * const invalidUrl = tryParseURL('not-a-url'); // Returns null
 * ```
 */
export function tryParseURL(url: string): URL | null {
  try {
    return new URL(url);
  } catch {
    return null;
  }
}


/**
 * Retrieves the request ID from the incoming request.
 * If the request ID is not present in the headers, a new one is generated
 * using the client's IP address and a predefined namespace.
 *
 * @param req - The incoming request object.
 * @param server - The server instance used to retrieve the client's IP address.
 * @returns The request ID as a string. If the request ID is not found, 
 *          a new request ID is generated in the format 'ruuid:<UUID>'.
 */
export function getRequestId(req: Request, server: Server<any>): string {
    const addressIP = server.requestIP(req)?.address;
    const ip = addressIP ? String(addressIP) : 'unknown';
    const requestID = req.headers.get('X-Request-ID') || 'ruuid:' + randomUUIDv5(String(ip), 'mystika-webserver-request');
    return requestID;
}