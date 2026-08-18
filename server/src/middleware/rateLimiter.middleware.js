import rateLimit from "express-rate-limit";

const defaultValidateConfig = {
  trustProxy: false,
};

const windowMs = Number(process.env.RATE_LIMIT_WINDOW_MINUTES) || 15 * 60 * 1000;

export const loginLimiter = rateLimit({
    windowMs,
    max: Number(process.env.LOGIN_RATE_LIMIT),
    message: {
        success: false,
        message:
            "Too many login attempts. Please try again later."
    },
    standardHeaders: true,
    legacyHeaders: false,
    validate: defaultValidateConfig

});

export const registerLimiter = rateLimit({
    windowMs,
    max: Number(process.env.REGISTER_RATE_LIMIT),
    message: {
        success: false,
        message:
            "Too many registrations. Please try again later."
    },
    standardHeaders: true,
    legacyHeaders: false,
    validate: defaultValidateConfig
});

export const uploadLimiter = rateLimit({
    windowMs,
    max: Number(process.env.UPLOAD_RATE_LIMIT),
    message: {
        success: false,
        message:
            "Upload limit exceeded."
    },
    standardHeaders: true,
    legacyHeaders: false,
    validate: defaultValidateConfig
});

export const shareLimiter = rateLimit({
    windowMs,
    max: Number(process.env.SHARE_RATE_LIMIT),
    message: {
        success: false,
        message:
            "Too many download attempts."
    },
    standardHeaders: true,
    legacyHeaders: false,
    validate: defaultValidateConfig
});

export const createShareLimiter = rateLimit({
    windowMs,
    max: Number(process.env.CREATE_SHARE_RATE_LIMIT),
    message: {
        success: false,
        message:
            "Share creation limit exceeded."
    },
    standardHeaders: true,
    legacyHeaders: false,
    validate: defaultValidateConfig
});