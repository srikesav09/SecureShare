process.env.NODE_ENV = "test";
process.env.TEST_RATE_LIMIT = "false";

process.env.JWT_SECRET =
    "77c1f3b7d0a6e9f2c8a1d5e7b9c3f4a8d6e1b5c9777";

process.env.JWT_EXPIRES_IN = "30m";

process.env.ENCRYPTION_KEY =
    "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";

process.env.RATE_LIMIT_WINDOW_MINUTES = "15";

process.env.LOGIN_RATE_LIMIT = "500";
process.env.REGISTER_RATE_LIMIT = "500";
process.env.UPLOAD_RATE_LIMIT = "500";
process.env.SHARE_RATE_LIMIT = "30";
process.env.CREATE_SHARE_RATE_LIMIT = "20";