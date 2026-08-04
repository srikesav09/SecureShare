import express from "express";
import { register,login ,profile} from "../controllers/auth.controller.js";
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
    "/profile",
    authenticate,
    profile
);

export default router;
