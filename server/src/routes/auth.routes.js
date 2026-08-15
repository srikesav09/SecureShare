import express from "express";
import { register,login ,profile} from "../controllers/auth.controller.js";
import { validate } from "../middleware/validate.middleware.js";
import { registerSchema,loginSchema } from "../validators/auth.validator.js";
import { authenticate } from "../middleware/auth.middleware.js";
import { loginLimiter, registerLimiter } from "../middleware/rateLimiter.middleware.js";


const router = express.Router();

router.post("/register",
    registerLimiter,
    validate(registerSchema),
    register
);

router.post("/login",
    loginLimiter,
    validate(loginSchema),
    login
);

router.get(
    "/profile",
    authenticate,
    profile
);

export default router;
