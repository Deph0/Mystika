import express from "express";
export const router = express.Router();
import assetCache from "../services/assetCache";
const maps = assetCache.get("maps");

// Get map hash
router.get("/map/hash", (req, res) => {
  Object.keys(maps).forEach((key) => {
    res.json({ hash: maps[key].hash });
  });
});

export default router;