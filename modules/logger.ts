import path from "path";
import fs from "fs";

const config = {
  debug: false,
  trace: false,
};

const types = {
  info: "\x1b[97m",
  error: "\x1b[31m",
  warn: "\x1b[33m",
  success: "\x1b[32m",
  debug: "\x1b[34m",
  trace: "\x1b[95m",
  clear: "\x1b[0m",
};

const log = {
  type: (_type: string) => types[_type.toLowerCase() as keyof typeof types],
  date: () => new Date().toLocaleDateString().split("/").join("-"),
  timestamp: () => new Date().toLocaleTimeString(),
  createLogFile: async (message: string, type: string) => {
    const timestamp = log.timestamp();

    const _folder = path.join(import.meta.dir, "..", "logs");
    if (!fs.existsSync(_folder)) {
      fs.mkdirSync(_folder);
    }

    const _file = path.join(import.meta.dir, "..", "logs", `${log.date()}.log`);

    if (!fs.existsSync(_file)) {
      fs.writeFileSync(_file, "");
    }

    fs.appendFileSync(_file, `${timestamp} ${message}\n`);

    const _message = `${log.type(type)}${timestamp} ${message} ${log.type(
      "clear"
    )}`;
    console.log(_message);
  },
  info: (msg: string) => {
    log.createLogFile(`[INFO] ${msg}`, "info");
  },
  error: (msg: string) => {
    log.createLogFile(`[ERROR] ${msg}`, "error");
  },
  warn: (msg: string) => {
    log.createLogFile(`[WARN] ${msg}`, "warn");
  },
  success: (msg: string) => {
    log.createLogFile(`[SUCCESS] ${msg}`, "success");
  },
  debug: (msg: string) => {
    if (!config.debug) return;
    log.createLogFile(`[DEBUG] ${msg}`, "debug");
  },
  trace: (msg: string) => {
    if (!config.trace) return;
    log.createLogFile(`[TRACE] ${msg}`, "trace");
  },
  object: (obj: any) => {
    log.createLogFile(`[OBJECT] ${JSON.stringify(obj, null, 2)}`, "info");
  },
};

export default log;
