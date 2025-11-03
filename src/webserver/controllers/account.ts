import sendEmail from "../../services/email";
import player from "../../systems/player";
import verify from "../../services/verification";
import { hash, randomBytes } from "../../modules/hash";
import query from "../../controllers/sqldatabase";
import * as settings from "../../config/settings.json";
import log from "../../modules/logger";

// Load whitelisted and blacklisted IPs and functions
import { w_ips, b_ips } from "../../systems/security";


export async function createGuestAccount(req: Request, server: any) {
    try {
        if (!settings.guest_mode?.enabled) {
            return new Response(JSON.stringify({ message: "Guest mode is disabled" }), { status: 403 });
        }
        const ip = server.requestIP(req)?.address;
        if (b_ips.includes(ip) && !w_ips.includes(ip)) {
            return new Response(JSON.stringify({ message: "Invalid request" }), { status: 403 });
        }

        const guest_username = `guest_${randomBytes(12)}`;
        const domain = process.env.DOMAIN?.replace(/^https?:\/\//, "");
        const guest_email = `${guest_username}@${domain}`;
        const guest_password = `guest_${randomBytes(12)}`;
        const guest_password_hash = await hash(guest_password);

        const user = await player.register(guest_username.toLowerCase(), guest_password_hash, guest_email, req, true) as any;
        if (!user) {
            return new Response(JSON.stringify({ message: "Failed to create guest account" }), { status: 500 });
        }

        if (user.error) {
            return new Response(JSON.stringify({ message: user.error }), { status: 400 });
        }

        const token = await player.login(guest_username.toLowerCase(), guest_password);
        if (!token) {
            log.debug(`Failed to login guest user after registration: ${guest_username} (${ip})`);
            return new Response(JSON.stringify({ message: "Failed to create guest account" }), { status: 500 });
        }

        log.debug(`Guest account created: ${guest_username} (${ip})`);

        return new Response(JSON.stringify({ message: "Logged in successfully" }), { status: 301, headers: { "Set-Cookie": `token=${token}; Path=/;` } });

    } catch (error) {
        log.error(`Failed to create guest account: ${error}`);
        return new Response(JSON.stringify({ message: "Failed to create guest account" }), { status: 500 });
    }
}

export async function register(req: Request, server: any) {
    try {
        // Check if ip banned
        const ip = server.requestIP(req)?.address;
        if (b_ips.includes(ip) && !w_ips.includes(ip)) {
            return new Response(JSON.stringify({ message: "Invalid request" }), { status: 403 });
        }
        const body = await req.json();
        const { username, email, password, password2 } = body;
        if (!username || !password || !email || !password2) {
            return new Response(JSON.stringify({ message: "All fields are required" }), { status: 400 });
        }

        if (password !== password2) {
            return new Response(JSON.stringify({ message: "Passwords do not match" }), { status: 400 });
        }

        if (!validateUsername(username)) {
            return new Response(JSON.stringify({ message: "Invalid username" }), { status: 400 });
        }

        if (validatePasswordComplexity(password) === false) {
            return new Response(JSON.stringify({ message: "Password must be between 8 and 20 characters long, contain at least one uppercase letter, one lowercase letter, one number, and one special character." }), { status: 400 });
        }

        if (!validateEmail(email)) {
            return new Response(JSON.stringify({ message: "Invalid email format" }), { status: 400 });
        }

        const password_hash = await hash(password);

        const user = await player.register(username.toLowerCase(), password_hash, email.toLowerCase(), req, false) as any;
        if (!user) {
            return new Response(JSON.stringify({ message: "Failed to register" }), { status: 400 });
        }

        if (user.error) {
            return new Response(JSON.stringify({ message: user.error }), { status: 400 });
        }

        const token = await player.login(username.toLowerCase(), password);
        if (!token) {
            return new Response(JSON.stringify({ message: "Invalid credentials" }), { status: 400 });
        }

        if (settings['2fa'].enabled) {
            const result = await verify(token, email.toLowerCase(), username.toLowerCase()) as any;

            if (result instanceof Error) {
                return new Response(JSON.stringify({ message: "Failed to send verification email" }), { status: 500 });
            }
            return new Response(JSON.stringify({ message: "Verification email sent" }), { status: 200 });
        } else {
            return new Response(JSON.stringify({ message: "Logged in successfully" }), { status: 301, headers: { "Set-Cookie": `token=${token}; Path=/;` } });
        }
    } catch (error) {
        return new Response(JSON.stringify({ message: "Failed to register", error: error instanceof Error ? error.message : "Unknown error" }), { status: 500 });
    }
}

export async function login(req: Request, server: any) {
    try {
        // Check if ip banned
        const ip = server.requestIP(req)?.address;
        if (b_ips.includes(ip) && !w_ips.includes(ip)) {
            return new Response(JSON.stringify({ message: "Invalid request" }), { status: 403 });
        }
        const body = await req.json();
        const { username, password } = body;
        if (!username || !password) {
            return new Response(JSON.stringify({ message: "Invalid credentials" }), { status: 400 });
        }

        if (!validateUsername(username)) {
            return new Response(JSON.stringify({ message: "Invalid username" }), { status: 400 });
        }

        if (password.length < 8 || password.length > 20) {
            return new Response(JSON.stringify({ message: "Password must be between 8 and 20 characters long" }), { status: 400 });
        }

        const token = await player.login(username.toLowerCase(), password);
        if (!token) {
            return new Response(JSON.stringify({ message: "Invalid credentials" }), { status: 400 });
        }

        const useremail = await player.getEmail(username.toLowerCase()) as string;
        if (!useremail) {
            return new Response(JSON.stringify({ message: "Invalid credentials" }), { status: 400 });
        }

        if (!settings["2fa"].enabled) {
            // Update the account to verified
            await query("UPDATE accounts SET verified = 1 WHERE token = ?", [token]);

            // Remove any verification code that may exist
            await query("UPDATE accounts SET verification_code = NULL WHERE token = ?", [token]);
            // 2FA is not enabled, so we can just return the token
            return new Response(JSON.stringify({ message: "Logged in successfully" }), { status: 301, headers: { "Set-Cookie": `token=${token}; Path=/;` } });
        } else {
            // 2FA is enabled, so we need to send a verification email
            const result = await verify(token, useremail.toLowerCase(), username.toLowerCase()) as any;
            if (result instanceof Error) {
                return new Response(JSON.stringify({ message: "Failed to send verification email" }), { status: 500 });
            }
            // Return a 200
            return new Response(JSON.stringify({ message: "Verification email sent" }), { status: 200, headers: { "Set-Cookie": `token=${token}; Path=/;` } });
        }
    } catch (error) {
        log.error(`Failed to authenticate: ${error}`);
        return new Response(JSON.stringify({ message: "Failed to authenticate" }), { status: 500 });
    }
}

export async function resetPassword(req: Request, server: any) {
    if (req.method !== "POST") {
        return new Response(JSON.stringify({ message: "Invalid request" }), { status: 400 });
    }
    const responseMessage = `If the email you provided is registered, you will receive an email with instructions to reset your password.`;
    // Check if ip banned
    const ip = server.requestIP(req)?.address;
    if (b_ips.includes(ip) && !w_ips.includes(ip)) {
        return new Response(JSON.stringify({ message: "Invalid request" }), { status: 403 });
    }
    const body = await req.json();

    if (!body.email) {
        return new Response(JSON.stringify({ message: "Email is required" }), { status: 400 });
    }

    const email = body.email.toLowerCase();

    if (!validateEmail(email)) {
        return new Response(JSON.stringify({ message: "Invalid email" }), { status: 400 });
    }

    // Check if the email exists in the database
    const result = await query("SELECT email FROM accounts WHERE email = ? LIMIT 1", [email]) as any;
    // Don't tip off the user if the email does not exist
    if (result.length === 0) {
        return new Response(JSON.stringify({ message: responseMessage }), { status: 200 });
    }

    // Generate a random code to use for password reset verification
    const code = randomBytes(8);

    // Send the email with the reset link
    const gameName = process.env.GAME_NAME || process.env.DOMAIN || "Game";
    const subject = `${gameName} - Reset your password`;
    const url = `${process.env.DOMAIN}/change-password?email=${email}&code=${code}`;
    const message = `<p style="font-size: 20px;"><a href="${url}">Reset password</a></p><br><p style="font-size:12px;">If you did not request this, please ignore this email.</p>`;
    const emailResponse = await sendEmail(email, subject, gameName, message);
    if (emailResponse !== "Email sent successfully") {
        log.error(`Failed to send reset password email: ${emailResponse}`);
        // We can return a 500 error here because the email doesn't exist in general or the email service failed
        return new Response(JSON.stringify({ message: "Failed to send reset password email" }), { status: 500 });
    }

    await query("UPDATE accounts SET reset_password_code = ? WHERE email = ?", [code, email]);

    return new Response(JSON.stringify({ message: responseMessage }), { status: 200 });
}

export async function updatePassword(req: Request, server: any) {
    if (req.method !== "POST") {
        return new Response(JSON.stringify({ message: "Invalid request" }), { status: 400 });
    }
    // Check if ip banned
    const ip = server.requestIP(req)?.address;
    if (b_ips.includes(ip) && !w_ips.includes(ip)) {
        return new Response(JSON.stringify({ message: "Invalid request" }), { status: 403 });
    }
    const body = await req.json();

    if (!body.email || !body.password || !body.password2 || !body.code) {
        return new Response(JSON.stringify({ message: "All fields are required" }), { status: 400 });
    }

    if (!validateEmail(body.email)) {
        return new Response(JSON.stringify({ message: "Invalid email" }), { status: 400 });
    }

    if (body.password !== body.password2) {
        return new Response(JSON.stringify({ message: "Passwords do not match" }), { status: 400 });
    }

    if (!validatePasswordComplexity(body.password)) {
        return new Response(JSON.stringify({ message: "Password must be between 8 and 20 characters long, contain at least one uppercase letter, one lowercase letter, one number, and one special character." }), { status: 400 });
    }

    // Check if the account exists
    const account = await query("SELECT * FROM accounts WHERE email = ? LIMIT 1", [body.email.toLowerCase()]) as any;
    if (account.length === 0) {
        log.warn(`Attempt to update password for non-existent email: ${body.email.toLowerCase()}`);
        return new Response(JSON.stringify({ message: "Failed to update password" }), { status: 500 });
    }

    // Check if the reset password code matches
    const codeResult = await query("SELECT reset_password_code FROM accounts WHERE email = ? AND reset_password_code = ? LIMIT 1", [body.email.toLowerCase(), body.code]) as any;
    if (codeResult.length === 0) {
        log.warn(`Invalid reset password code for email: ${body.email.toLowerCase()}`);
        return new Response(JSON.stringify({ message: "Invalid reset password code" }), { status: 403 });
    }

    // Update the password
    const hashedPassword = await hash(body.password);
    const updateResult = await query("UPDATE accounts SET password_hash = ?, reset_password_code = NULL, verified = 0, verification_code = NULL WHERE email = ?", [hashedPassword, body.email.toLowerCase()]);
    if (!updateResult) {
        log.error(`Failed to update password for email: ${body.email.toLowerCase()}`);
        return new Response(JSON.stringify({ message: "Failed to update password" }), { status: 500 });
    }

    log.debug(`Password updated successfully for email: ${body.email.toLowerCase()}`);

    if (account.session_id) {
        // If the user is logged in, we need to logout the user
        player.logout(account.session_id);
    }

    return new Response(JSON.stringify({ message: "Password updated successfully" }), { status: 200 });
}

function validatePasswordComplexity(password: string): boolean {
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumbers = /\d/.test(password);
    const hasSpecialCharacter = /[!@#$%^&*(),.?":{}|<>]/.test(password);
    const isValidLength = password.length >= 8 && password.length <= 20;
    return hasUpperCase && hasLowerCase && hasNumbers && hasSpecialCharacter && isValidLength;
}

function validateUsername(username: string): boolean {
    const regex = /^[a-zA-Z0-9_]{3,15}$/; // Alphanumeric and underscores, 3-15 characters
    return regex.test(username);
}

function validateEmail(email: string): boolean {
    const regex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,100}$/;
    return regex.test(email);
}

