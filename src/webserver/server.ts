import '../utility/validate_config';
import SwaggerHTML from './swagger';
const now = performance.now();
import log from "../modules/logger";
import path from "path";
import fs from "fs";
import docs_html from "./www/public/docs.html";
import editor_html from "./www/public/editor.html";
import benchmark_html from "./www/public/benchmark.html";
import connectiontest_html from "./www/public/connection-test.html";
import login_html from "./www/public/index.html";
import register_html from "./www/public/register.html";
import game_html from "./www/public/game.html";
import forgotpassword_html from "./www/public/forgot-password.html";
import changepassword_html from "./www/public/change-password.html";
import { type Server } from "bun";
import { badRequestResponse, forbiddenResponse, getRequestId, jsonResponse, methodNotAllowedResponse, notFoundResponse, StatusCodes, tryParseURL } from './ResponseHelper';

// Load whitelisted and blacklisted IPs and functions
import { w_ips, b_ips, blacklistAdd } from "../systems/security";

// Load security rules from security.cfg
const security = fs.existsSync(path.join(import.meta.dir, "../../config/security.cfg"))
  ? fs.readFileSync(path.join(import.meta.dir, "../../config/security.cfg"), "utf8").split("\n").filter(line => line.trim() !== "" && !line.startsWith("#"))
  : [];

if (security.length > 0) {
  log.success(`Loaded ${security.length} security rules`);
} else {
  log.warn("No security rules found");
}

// Load assets
import "../modules/assetloader";

import assetCache from "../services/assetCache";
import { authenticate } from './controllers/authenticate';
import { createGuestAccount, login, register, resetPassword, updatePassword } from './controllers/account';
const _cert = path.join(import.meta.dir, "../certs/cert.pem");
const _key = path.join(import.meta.dir, "../certs/key.pem");
const _https = process.env.WEBSRV_USESSL === "true" && fs.existsSync(_cert) && fs.existsSync(_key);
const _srvport = _https ? (process.env.WEBSRV_PORTSSL || 443) : (process.env.WEBSRV_PORT || 80)

const routes = {
  "/swaggerui": {
    GET: async () => {
      return new Response(SwaggerHTML, {
        headers: {
          "Content-Type": "text/html",
        },
      });
    }
  },
  "/api.json": {
    GET: async () => {
      const apiSpecPath = path.join(import.meta.dir, "./www/public/api.json");
      if (!fs.existsSync(apiSpecPath)) {
        return notFoundResponse("API specification not found");
        // return new Response(JSON.stringify({ message: "API specification not found" }), { status: 404 });
      }
      const apiSpec = fs.readFileSync(apiSpecPath, "utf8");
      return new Response(apiSpec, {
        headers: {
          "Content-Type": "application/json",
        },
      });
    }
  },
  "/docs": docs_html,
  "/benchmark": benchmark_html,
  "/connection-test": connectiontest_html,
  "/": login_html,
  "/registration": register_html,
  "/game": game_html,
  "/editor": editor_html,
  "/login": (req: Request, server: any) => login(req, server),
  "/verify": (req: Request, server: any) => authenticate(req, server),
  "/register": (req: Request, server: any) => register(req, server),
  "/guest-login": async (req: Request, server: any) => createGuestAccount(req, server),
  "/forgot-password": forgotpassword_html,
  "/change-password": changepassword_html,
  "/reset-password": async (req: Request, server: any) => {
    if (req.method !== "POST") {
      const url = tryParseURL(req.url);
      return methodNotAllowedResponse(["POST"], "Method not allowed.", url?.pathname);
    }
    return await resetPassword(req, server);
  },
  "/update-password": async (req: Request, server: any) => {
    if (req.method !== "POST") {
      const url = tryParseURL(req.url);
      return methodNotAllowedResponse(["POST"], "Method not allowed.", url?.pathname);
    }
    return await updatePassword(req, server);
  },
  "/tileset": async (req: Request) => {
    const url = tryParseURL(req.url);
    const tilesets = await assetCache.get("tilesets");
    if (req.method !== "GET") {
      return methodNotAllowedResponse(["GET"], "Method not allowed.", url?.pathname);
    }
    if (!url) {
      return badRequestResponse("Invalid URL provided.");
    }
    const tilesetName = url.searchParams.get("name");
    if (!tilesetName) {
      return badRequestResponse("Tileset name parameter is required.");
    }

    for (const key of Object.keys(tilesets)) {
      if (tilesets[key].name === tilesetName) {
        return jsonResponse({ tileset: tilesets[key] });
      }
    }
    return notFoundResponse(`Tileset does not exist in the asset cache`, url.pathname, "#name-not-found", { "name": tilesetName } );
  },
} as Record<string, any>;

const websrv = Bun.serve({
  port: _srvport,
  routes: {
    "/swaggerui": routes["/swaggerui"],
    "/docs": routes["/docs"],
    "/benchmark": routes["/benchmark"],
    "/connection-test": routes["/connection-test"],
    "/": routes["/"],
    "/registration": routes["/registration"],
    "/register": routes["/register"],
    "/guest-login": routes["/guest-login"],
    "/forgot-password": routes["/forgot-password"],
    "/change-password": routes["/change-password"],
    "/reset-password": routes["/reset-password"],
    "/update-password": routes["/update-password"],
    "/game": routes["/game"],
    "/editor": routes["/editor"],
    "/login": routes["/login"],
    "/verify": routes["/verify"],
    "/tileset": routes["/tileset"],
  },
  async fetch(req: Request, server: Server<any>) {
    const isDevEnv = server.development;
    const url = tryParseURL(req.url);
    const address = server.requestIP(req);
    const ip = address?.address || 'unknown';
    const requestID = getRequestId(req, server);
    log.debug(`Received Request[${requestID}]: ${req.method} ${url} from ${ip} on ${JSON.stringify(address)}`);

    if (!url) {
      return badRequestResponse("Invalid URL provided.");
    }
    if (!address) {
      return badRequestResponse("Unable to determine client IP address.");
    }
    
    // Check if the ip is blacklisted
    if (b_ips.includes(ip)) {
      log.debug(`Request[${requestID}]: ${ip} is blacklisted, returning responseCode 403 forbidden.`);
      return forbiddenResponse(`Access restricted.`, url.pathname);
    }
    
    // Check if the ip is whitelisted
    if (!w_ips.includes(ip)) {
      const path = url.pathname.split("/")[1];
      if (security.includes(path)) {
        // Ban the IP
        log.debug(`Request[${requestID}]: ${ip} is not whitelisted, and path ${path} is forbidden, blacklisting ip & returning 403 forbidden.`);
        await blacklistAdd(ip);
        return forbiddenResponse(`Access denied.`, url.pathname);
      }
    }

    // Restrict direct ip access to the webserver (unless development mode)
    if (process.env.DOMAIN?.replace(/https?:\/\//, "") !== url.host && !isDevEnv) {
      log.debug(`Request[${requestID}]: Direct access using host (${url.host}) from ${ip} is not allowed, returning 403 forbidden.`);
      return forbiddenResponse(`Accessing the server directly via IP address is prohibited. Please use the configured domain name.`, url.pathname);
    }

    const route = routes[url.pathname as keyof typeof routes];
    if (!route) {
      return Response.redirect("/", StatusCodes.MOVED_PERMANENTLY);
    }
    return route[req.method as keyof typeof route]?.(req);
  },
  ...(_https ? {
    cert: fs.readFileSync(_cert),
    key: fs.readFileSync(_key),
  }
    : {}),
});


// If HTTPS is enabled, also start an HTTP server that redirects to HTTPS
if (_https) {
  Bun.serve({
    port: process.env.WEBSRV_PORT || 80,
    fetch(req: Request) {
      const url = tryParseURL(req.url);
      if (!url) {
        return badRequestResponse("Invalid URL provided.");
      }
      // Always redirect to https with same host/path/query
      // If the port is 443, don't include it in the redirect
      const port = process.env.WEBSRV_PORTSSL === "443" ? "" : `:${process.env.WEBSRV_PORTSSL || 443}`;
      return Response.redirect(`https://${url.hostname}${port}${url.pathname}${url.search}`, StatusCodes.MOVED_PERMANENTLY);
    }
  });
}



const readyTimeMs = performance.now() - now;
// log.success(`Webserver started on port ${_srvport + (_https ? " (HTTPS)" : " (HTTP)")} - Ready in ${(readyTimeMs / 1000).toFixed(3)}s (${readyTimeMs.toFixed(0)}ms)`);
log.success(`Webserver started on ${websrv.url} - Ready in ${(readyTimeMs / 1000).toFixed(3)}s (${readyTimeMs.toFixed(0)}ms)`);
await import('../socket/server');