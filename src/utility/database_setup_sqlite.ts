// This file is used to create the database and tables if they don't exist
import query from "../controllers/sqldatabase";
import log from "../modules/logger";

// Create accounts table if it doesn't exist
const createAccountsTable = async () => {
  log.info("Creating accounts table...");
  const sql = `
    CREATE TABLE IF NOT EXISTS accounts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL UNIQUE,
        username TEXT NOT NULL UNIQUE,
        token TEXT UNIQUE DEFAULT NULL,
        password_hash TEXT NOT NULL,
        last_login DATETIME DEFAULT NULL,
        online INTEGER DEFAULT 0 NOT NULL,
        role INTEGER DEFAULT 0 NOT NULL,
        banned INTEGER DEFAULT 0 NOT NULL,
        ip_address TEXT DEFAULT NULL,
        geo_location TEXT DEFAULT NULL,
        verification_code TEXT DEFAULT NULL,
        reset_password_code TEXT DEFAULT NULL,
        map TEXT DEFAULT 'main' NOT NULL,
        position TEXT DEFAULT '0,0' NOT NULL,
        session_id TEXT UNIQUE DEFAULT NULL,
        stealth INTEGER DEFAULT 0 NOT NULL,
        direction TEXT DEFAULT 'down' NOT NULL,
        verified INTEGER DEFAULT 0 NOT NULL,
        noclip INTEGER DEFAULT 0 NOT NULL,
        party_id INTEGER DEFAULT NULL,
        guest_mode INTEGER DEFAULT 0 NOT NULL
      );
  `;
  await query(sql);
};

// Create allowed_ips table if it doesn't exist
const createAllowedIpsTable = async () => {
  log.info("Creating allowed_ips table...");
  const sql = `
    CREATE TABLE IF NOT EXISTS allowed_ips (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT NOT NULL UNIQUE
    );
  `;
  await query(sql);
};

// Create blocked_ips table if it doesn't exist
const createBlockedIpsTable = async () => {
  log.info("Creating blocked_ips table...");
  const sql = `
    CREATE TABLE IF NOT EXISTS blocked_ips (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT NOT NULL UNIQUE
    );
  `;
  await query(sql);
};

// Insert 127.0.0.1 and ::1 as allowed IPs if they doesn't exist
const insertLocalhost = async () => {
  log.info("Inserting localhost and ::1 as allowed IPs...");
  const sql = `
    INSERT OR IGNORE INTO allowed_ips (ip) VALUES ('127.0.0.1'), ('::1');
    `;
  await query(sql);
};

// Insert demo account if doesn't exist
const insertDemoAccount = async () => {
  log.info("Inserting demo account...");
  const sql = `
    INSERT OR IGNORE INTO accounts (
      email,
      username,
      password_hash,
      online,
      role,
      banned
    ) VALUES (
      'demo@example.com',
      'demo_user',
      '$argon2id$v=19$m=65536,t=2,p=1$t10G4CvyWPSnL53oJjhAeUwxVn3npXudy6CN41Z8JZE$/Rz8vPge3ECpIeYqJ2XbmBsrXipWuVPLmEGFyQfliWM',
      0,
      1,
      0
    );
    `;
  await query(sql);
};

const insertDemoStats = async () => {
  log.info("Inserting demo stats...");
  const sql = `
    INSERT OR IGNORE INTO stats (
      username,
      health,
      max_health,
      stamina,
      max_stamina,
      xp,
      max_xp,
      level
    ) VALUES (
      'demo_user',
      100,
      100,
      100,
      100,
      0,
      0,
      1
    );
    `;
  await query(sql);
}

const insertDemoClientConfig = async () => {
  log.info("Inserting demo client config...");
  const sql = `
    INSERT OR IGNORE INTO clientconfig (
      username,
      fps,
      music_volume,
      effects_volume,
      muted
    ) VALUES (
      'demo_user',
      60,
      100,
      100,
      0
    );
    `;
  await query(sql);
}

const insertDemoQuestLog = async () => {
  log.info("Inserting demo quest log...");
  const sql = `
    INSERT OR IGNORE INTO quest_log (username) VALUES ('demo_user');
  `;
  await query(sql);
}

const getAllowedIPs = async () => {
  const sql = `
    select * from allowed_ips;
    `;
  return await query(sql);
};

// Create inventory table if it doesn't exist
const createInventoryTable = async () => {
  log.info("Creating inventory table...");
  const sql = `
    CREATE TABLE IF NOT EXISTS inventory (
        username TEXT NOT NULL,
        item TEXT NOT NULL,
        quantity INTEGER NOT NULL
    );
  `;
  await query(sql);
};

// Create items table if it doesn't exist
const createItemsTable = async () => {
  log.info("Creating items table...");
  const sql = `
    CREATE TABLE IF NOT EXISTS items (
        id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE NOT NULL,
        name TEXT NOT NULL UNIQUE,
        quality TEXT NOT NULL,
        description TEXT DEFAULT NULL,
        icon TEXT DEFAULT NULL
    );
  `;
  await query(sql);
};

const createStatsTable = async () => {
  log.info("Creating stats table...");
  const sql = `
    CREATE TABLE IF NOT EXISTS stats (
        id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE NOT NULL,
        username TEXT NOT NULL UNIQUE,
        health INTEGER NOT NULL DEFAULT 100,
        max_health INTEGER NOT NULL DEFAULT 100,
        stamina INTEGER NOT NULL DEFAULT 100,
        max_stamina INTEGER NOT NULL DEFAULT 100,
        xp INTEGER NOT NULL DEFAULT 0,
        max_xp INTEGER NOT NULL DEFAULT 0,
        level INTEGER NOT NULL DEFAULT 1
    );
  `;
  await query(sql);
}

const createClientConfig = async () => {
  log.info("Creating clientconfig table...");
  const sql = `
    CREATE TABLE IF NOT EXISTS clientconfig (
        id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE NOT NULL,
        username TEXT NOT NULL UNIQUE,
        fps INTEGER NOT NULL DEFAULT 240,
        music_volume INTEGER NOT NULL DEFAULT 100,
        effects_volume INTEGER NOT NULL DEFAULT 100,
        muted INTEGER NOT NULL DEFAULT 0
    );
  `;
  await query(sql);
}

const createWeaponsTable = async () => {
  log.info("Creating weapons table...");
  const sql = `
    CREATE TABLE IF NOT EXISTS weapons (
        id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE NOT NULL,
        name TEXT NOT NULL UNIQUE,
        damage INTEGER NOT NULL,
        mana INTEGER NOT NULL,
        \`range\` INTEGER NOT NULL,
        type TEXT NOT NULL,
        description TEXT DEFAULT NULL,
        quality TEXT NOT NULL DEFAULT 'common'
    );
  `;
  await query(sql);
}

const createSpellsTable = async () => {
  log.info("Creating spells table...");
  const sql = `
    CREATE TABLE IF NOT EXISTS spells (
        id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE NOT NULL,
        name TEXT NOT NULL UNIQUE,
        damage INTEGER NOT NULL,
        mana INTEGER NOT NULL,
        \`range\` INTEGER NOT NULL,
        type TEXT NOT NULL,
        cast_time INTEGER NOT NULL,
        description TEXT DEFAULT NULL
    );
  `;
  await query(sql);
}

const createPermissionsTable = async () => {
  log.info("Creating permissions table...");
  const sql = `
    CREATE TABLE IF NOT EXISTS permissions (
        username TEXT NOT NULL UNIQUE PRIMARY KEY,
        permissions TEXT NOT NULL
    );
  `;
  await query(sql);
}

const createPermissionTypesTable = async () => {
  log.info("Creating permission_types table...");
  const sql = `
    CREATE TABLE IF NOT EXISTS permission_types (
        name TEXT NOT NULL UNIQUE PRIMARY KEY
    );
    INSERT OR IGNORE INTO permission_types (name) VALUES
      ('admin.ban'),
      ('admin.disconnect'),
      ('admin.permission'),
      ('admin.respawn'),
      ('admin.unban'),
      ('permission.add'),
      ('permission.list'),
      ('permission.remove'),
      ('server.admin'),
      ('server.notify'),
      ('server.restart'),
      ('server.shutdown')
  `;
  await query(sql);
}

const addPermissionsToDemoAccount = async () => {
  log.info("Adding permissions to demo account...");
  const sql = `
    INSERT OR IGNORE INTO permissions (username, permissions) VALUES ('demo_user', 'admin.*,server.*,permission.*');
  `;
  await query(sql);
}

const createNpcTable = async () => {
  log.info("Creating npcs table...");
  const sql = `
    CREATE TABLE IF NOT EXISTS npcs (
        id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE NOT NULL,
        name TEXT NOT NULL UNIQUE,
        position TEXT NOT NULL,
        hidden INTEGER NOT NULL DEFAULT 0,
        script TEXT DEFAULT NULL,
        dialog TEXT DEFAULT NULL,
        particles TEXT DEFAULT NULL,
        quest INTEGER DEFAULT NULL
    );
  `;
  await query(sql);
}

const createParticleTable = async () => {
  log.info("Creating particles table...");
  const sql = `
    CREATE TABLE IF NOT EXISTS particles (
        id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE NOT NULL,
        name TEXT NOT NULL UNIQUE,
        size INTEGER NOT NULL DEFAULT 1,
        color TEXT NOT NULL DEFAULT 'transparent',
        velocity TEXT NOT NULL DEFAULT '0,0',
        lifetime INTEGER NOT NULL DEFAULT 100,
        opacity FLOAT NOT NULL DEFAULT 1,
        visible INTEGER NOT NULL DEFAULT 1,
        gravity TEXT NOT NULL DEFAULT '0,0',
        localposition TEXT NOT NULL DEFAULT '0,0',
        amount INTEGER NOT NULL DEFAULT 1,
        interval INTEGER NOT NULL DEFAULT 1,
        staggertime FLOAT NOT NULL DEFAULT 0,
        spread TEXT NOT NULL DEFAULT '0,0',
        affected_by_weather INTEGER NOT NULL DEFAULT 0
    );
  `;
  await query(sql);
}

const createWeatherTable = async () => {
  log.info("Creating weather table...");
  const sql = `
    CREATE TABLE IF NOT EXISTS weather (
      name TEXT NOT NULL UNIQUE PRIMARY KEY,
      ambience FLOAT NOT NULL DEFAULT 0,
      wind_direction TEXT NOT NULL DEFAULT 'none',
      wind_speed FLOAT NOT NULL DEFAULT 0,
      humidity FLOAT NOT NULL DEFAULT 30,
      temperature FLOAT NOT NULL DEFAULT 68,
      precipitation FLOAT NOT NULL DEFAULT 0
    );
  `;
  await query(sql);
}

const createDefaultWeather = async () => {
  log.info("Creating default weather...");
  const sql = `
    INSERT OR IGNORE INTO weather (name, ambience, wind_direction, wind_speed, humidity, temperature, precipitation) VALUES ('clear', 0, 'none', 0, 30, 68, 0);
  `;
  await query(sql);
}

const createWorldTable = async () => {
  log.info("Creating world table...");
  const sql = `
    CREATE TABLE IF NOT EXISTS worlds (
      name TEXT NOT NULL UNIQUE PRIMARY KEY,
      weather TEXT NOT NULL DEFAULT 'none',
      max_players INTEGER NOT NULL DEFAULT 100,
      default_map TEXT NOT NULL DEFAULT 'main'
    );
  `;
  await query(sql);
}

const createDefaultWorld = async () => {
  log.info("Creating default world...");
  const sql = `
    INSERT OR IGNORE INTO worlds (name, weather, max_players, default_map) VALUES ('default', 'clear', 100, 'main');
  `;
  await query(sql);
}

const createQuestsTable = async () => {
  log.info("Creating quests table...");
  const sql = `
    CREATE TABLE IF NOT EXISTS quests (
      id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE NOT NULL,
      name VARCHAR(255) NOT NULL,
      description VARCHAR(5000) NOT NULL,
      reward INT NOT NULL,
      xp_gain INT NOT NULL,
      required_quest INT NOT NULL,
      required_level INT NOT NULL
    );
  `;
  await query(sql);
}



const createQuestLogTable = async () => {
  log.info("Creating quest log table...");
  const sql = `
    CREATE TABLE IF NOT EXISTS quest_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE NOT NULL,
      username TEXT NOT NULL UNIQUE,
      completed_quests TEXT NOT NULL DEFAULT '0',
      incomplete_quests TEXT NOT NULL DEFAULT '0'
    );
  `;  
  await query(sql);
}

const createFriendsListTable = async () => {
  log.info("Creating friends list table...");
  const sql = `
    CREATE TABLE IF NOT EXISTS friendslist (
      username TEXT NOT NULL UNIQUE PRIMARY KEY,
      friends TEXT NOT NULL DEFAULT ''
    );
  `;
  await query(sql);
}

const createPartiesTable = async () => {
  log.info("Creating parties table...");
  const sql = `
    CREATE TABLE IF NOT EXISTS parties (
      id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE NOT NULL,
      leader TEXT NOT NULL,
      members TEXT DEFAULT NULL
    );
  `;
  await query(sql);
}

const createCurrencyTable = async () => {
  log.info("Creating currency table...");
  const sql = `
    CREATE TABLE IF NOT EXISTS currency (
      username TEXT NOT NULL UNIQUE PRIMARY KEY,
      copper INTEGER NOT NULL DEFAULT 0,
      silver INTEGER NOT NULL DEFAULT 0,
      gold INTEGER NOT NULL DEFAULT 0
    );
  `;
  await query(sql);
}

// Run the database setup
const setupDatabase = async () => {
  await createAccountsTable();
  await createAllowedIpsTable();
  await createBlockedIpsTable();
  await insertLocalhost();
  await createInventoryTable();
  await createItemsTable();
  await createStatsTable();
  await createClientConfig();
  await createWeaponsTable();
  await createSpellsTable();
  await createPermissionsTable();
  await createPermissionTypesTable();
  await addPermissionsToDemoAccount();
  await createNpcTable();
  await createParticleTable();
  await createWeatherTable();
  await createDefaultWeather();
  await createWorldTable();
  await createDefaultWorld();
  await createQuestsTable();
  await createQuestLogTable();
  await createFriendsListTable();
  await createPartiesTable();
  await createCurrencyTable();
};

try {
  log.info("Setting up database...");
  await setupDatabase();
  const ips = await getAllowedIPs();
  log.trace(`Created allowed ips: ${JSON.stringify(ips)}`);
  await insertDemoAccount();
  await insertDemoStats();
  await insertDemoClientConfig();
  await insertDemoQuestLog();
  log.success("Database setup complete!");
  process.exit(0);
} catch (error) {
  log.error(`Error setting up database: ${error}`);
  process.exit(1);
}
