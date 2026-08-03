import express from "express";
import { register } from "../controllers/auth.controller.js";
import { login } from "../controllers/auth.controller.js";
import { validate } from "../middleware/validate.middleware.js";
import { registerSchema,loginSchema } from "../validators/auth.validator.js";
import { authenticate } from "../middleware/auth.middleware.js";

const router = express.Router();

router.post("/register",
    validate(registerSchema),
    register
);

router.post("/login",
  validate(loginSchema),
  login
);

router.get(
    "/me",
    authenticate,
    (req, res) => {
        res.json({
            success: true,
            user: req.user
        });
    }
);

export default router;
