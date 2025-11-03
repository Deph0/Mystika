import { type Server } from "bun";
import query from "../../controllers/sqldatabase";
import { b_ips, w_ips } from "../../systems/security";
import { badRequestResponse, forbiddenResponse, StatusCodes, tryParseURL, unauthorizedResponse } from "../ResponseHelper";

export async function authenticate(req: Request, server: Server<any>) {
    // const isDevEnv = server.development;
    // const requestID = getRequestId(req, server);
    const url = tryParseURL(req.url);

    if (!url) {
        return badRequestResponse("Invalid URL provided.");
    }

    // Check if ip banned
    const ip = server.requestIP(req)?.address;
    if (ip && b_ips.includes(ip) && !w_ips.includes(ip)) {
        return unauthorizedResponse("Unauthorized access.", url.pathname);
    }

    const email = url.searchParams.get("email");
    const token = url.searchParams.get("token");
    const code = url.searchParams.get("code");

    if (!token || !code || !email) {
        return badRequestResponse("Missing required parameters.", url.pathname, "#missing-parameters", { token, code, email });
    }

    const result = await query("SELECT * FROM accounts WHERE token = ? AND email = ? AND verification_code = ? LIMIT 1", [token, email.toLowerCase(), code]) as any;
    if (result.length === 0) {        
        return new Response(JSON.stringify({ message: "Invalid request" }), { status: 403 });
    }

    await query("UPDATE accounts SET verified = 1 WHERE token = ?", [token]);
    await query("UPDATE accounts SET verification_code = NULL WHERE token = ?", [token]);

    // Send to /game
    return Response.redirect(`${server.hostname}/game`, StatusCodes.MOVED_PERMANENTLY);
}