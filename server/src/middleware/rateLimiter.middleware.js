import rateLimit from "express-rate-limit";

// =====================================================
// Global configuration
// =====================================================

const windowMinutes =
    Number(process.env.RATE_LIMIT_WINDOW_MINUTES) || 15;

const windowMs = windowMinutes * 60 * 1000;

// =====================================================
// Helper
// =====================================================

const getLimit = (envName, fallback) => {
    const value = Number(process.env[envName]);

    if (!Number.isFinite(value) || value <= 0) {
        return fallback;
    }

    return value;
};

// =====================================================
// LOGIN RATE LIMITER
// Protects against brute-force login attempts
// =====================================================

export const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes

    max: 10,

    standardHeaders: true,
    legacyHeaders: false,

    message: {
        success: false,
        message: "Too many login attempts. Please try again later."
    },

    handler: (req, res, next, options) => {
        return res.status(429).json(options.message);
    }
});

// =====================================================
// REGISTER RATE LIMITER
// Prevents account creation abuse
// =====================================================

export const registerLimiter = rateLimit({
    windowMs,

    max: getLimit("REGISTER_RATE_LIMIT", 5),

    standardHeaders: true,
    legacyHeaders: false,

    message: {
        success: false,
        message:
            "Too many registrations. Please try again later.",
    },

    validate: {
        trustProxy: false,
    },
});

// =====================================================
// UPLOAD RATE LIMITER
// Prevents upload endpoint abuse
// =====================================================

export const uploadLimiter = rateLimit({
    windowMs,

    max: getLimit("UPLOAD_RATE_LIMIT", 20),

    standardHeaders: true,
    legacyHeaders: false,

    message: {
        success: false,
        message:
            "Upload limit exceeded. Please try again later.",
    },

    validate: {
        trustProxy: false,
    },
});

// =====================================================
// SHARE / DOWNLOAD RATE LIMITER
// Protects public/shared file access
// =====================================================

export const shareLimiter = rateLimit({
    windowMs,

    max: getLimit("SHARE_RATE_LIMIT", 30),

    standardHeaders: true,
    legacyHeaders: false,

    message: {
        success: false,
        message:
            "Too many download attempts. Please try again later.",
    },

    validate: {
        trustProxy: false,
    },
});

// =====================================================
// CREATE SHARE RATE LIMITER
// Prevents excessive share creation
// =====================================================

export const createShareLimiter = rateLimit({
    windowMs,

    max: getLimit("CREATE_SHARE_RATE_LIMIT", 20),

    standardHeaders: true,
    legacyHeaders: false,

    message: {
        success: false,
        message:
            "Share creation limit exceeded. Please try again later.",
    },

    validate: {
        trustProxy: false,
    },
});