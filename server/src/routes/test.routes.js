import express from "express";
import User from "../models/user.model.js";

const router = express.Router();

router.get("/", async (req, res) => {
  const count = await User.countDocuments();

  res.json({
    success: true,
    users: count,
  });
});

export default router;