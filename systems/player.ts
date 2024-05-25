import query from "../controllers/sqldatabase";
import { hash, randomBytes } from "../modules/hash";
import log from "../modules/logger";

const player = {
    register: async (username: string, password: string, email: string, req: any) => {
        if (!username || !password || !email) return;
        // Validate field lengths
        if (username.length < 5 || password.length < 5 || email.length < 5) return;

        // Validate email format
        if (!email.includes("@") || !email.includes(".")) return;

        // Check if the user exists by username
        const usernameExists = await player.findByUsername(username) as string[];
        if (usernameExists && usernameExists.length != 0) return;

        // Check if the user exists by email
        const emailExists = await player.findByEmail(email) as string[];
        if (emailExists && emailExists.length != 0) return;

        const response = await query(
            "INSERT INTO accounts (email, username, token, password_hash, ip_address, geo_location) VALUES (?, ?, ?, ?, ?, ?)",
            [
              email,
              username,
              "", // empty token
              hash(password),
              req.ip,
              req.headers["cf-ipcountry"],
            ]
          ).catch((err) => {
            log.error(err);
            return;
          });
          if (!response) return;
          return username;
    },
    findByUsername: async (username: string) => {
        if (!username) return;
        const response = await query("SELECT username FROM accounts WHERE username = ?", [username]);
        return response;
    },
    findByEmail: async (email: string) => {
        if (!email) return;
        const response = await query("SELECT email FROM accounts WHERE email = ?", [email]);
        return response;
    },
    getLocation: async (player: Player) => {
        if (!player?.name) return;
        const response = await query("SELECT map, position FROM accounts WHERE username = ?", [player.name]) as LocationData[];
        const map = response[0]?.map as string;
        const position = {
            x: Number(response[0]?.position?.split(",")[0]),
            y: Number(response[0]?.position?.split(",")[1]),
        } as PositionData;

        if (!map || (!position.x && position.x.toString() != '0') || (!position.y && position.y.toString() != '0')) {
            return null;
        }

        return { map, position };
    },
    setLocation: async (player: Player, map: string, position: PositionData) => {
        if (!player?.name || !map || !position) return;
        const response = await query("UPDATE accounts SET map = ?, position = ? WHERE username = ?", [map, `${position.x},${position.y}`, player.name]);
        return response;
    },
    setSessionId: async (token: string, sessionId: string) => {
        if (!token || !sessionId) return;
        const getUsername = await player.getUsernameByToken(token) as any[];
        const username = await getUsername[0]?.username as string;
        const isBanned = await player.isBanned(username) as any[];
        const response = await query("UPDATE accounts SET session_id = ?, online = ? WHERE token = ?", [sessionId, 1, token]);
        if (isBanned[0]?.banned === 1) {
            log.debug(`User ${username} is banned`);
            await player.logout(sessionId);
            return;
        }
        return response;
    },
    getSessionId: async (token: string) => {
        if (!token) return;
        const response = await query("SELECT session_id FROM accounts WHERE token = ?", [token]);
        return response;
    },
    logout: async (session_id: string) => {
        if (!session_id) return;
        const response = await query("UPDATE accounts SET token = NULL, online = ?, session_id = NULL WHERE session_id = ?", [0, session_id]);
        return response;
    },
    clearSessionId: async (session_id: string) => {
        if (!session_id) return;
        const response = await query("UPDATE accounts SET session_id = NULL, online = ? WHERE session_id = ?", [0, session_id]);
        return response;
    },
    login: async (username: string, password: string) => {
        if (!username || !password) return;
        // Validate credentials
        const response = await query("SELECT username FROM accounts WHERE username = ? AND password_hash = ?", [username, hash(password)]) as string[];
        if (response.length === 0) {
            log.debug(`User ${username} failed to login`);
            return;
        }

        // Assign a token to the user
        const token = await player.setToken(username);
        log.debug(`User ${username} logged in`);
        // Update last_login
        await query("UPDATE accounts SET last_login = CURRENT_TIMESTAMP WHERE username = ?", [username]);
        return token;
    },
    getUsernameBySession: async (session_id: string) => {
        if (!session_id) return;
        const response = await query("SELECT username FROM accounts WHERE session_id = ?", [session_id]);
        return response;
    },
    getUsernameByToken: async (token: string) => {
        if (!token) return;
        const response = await query("SELECT username FROM accounts WHERE token = ?", [token]);
        return response;
    },
    getEmail: async (session_id: string) => {
        if (!session_id) return;
        const response = await query("SELECT email FROM accounts WHERE session_id = ?", [session_id]);
        return response;
    },
    returnHome: async (session_id: string) => {
        if (!session_id) return;
        const response = await query("UPDATE accounts SET map = 'main', position = '0,0' WHERE session_id = ?", [session_id]);
        return response;
    },
    setToken: async (username: string) => {
        const token = randomBytes(32);
        if (!username || !token) return;
        const response = await query("UPDATE accounts SET token = ? WHERE username = ?", [token, username]);
        if (!response) return;
        return token;
    },
    isOnline: async (username: string) => {
        if (!username) return;
        const response = await query("SELECT online FROM accounts WHERE username = ?", [username]);
        return response;
    },
    isBanned: async (username: string) => {
        if (!username) return;
        const response = await query("SELECT banned FROM accounts WHERE username = ?", [username]);
        return response;
    },
};

export default player;