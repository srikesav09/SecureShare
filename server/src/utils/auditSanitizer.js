const SENSITIVE_KEYS = new Set([
  "password",
  "passwordHash",
  "token",
  "accessToken",
  "refreshToken",
  "authorization",
  "cookie",
  "secret",
  "apiKey"
]);

const sanitizeValue = (value) => {
  if (Array.isArray(value)) {
    return value.map(sanitizeValue);
  }

  if (
    value !== null &&
    typeof value === "object"
  ) {
    const sanitized = {};

    for (const [key, val] of Object.entries(value)) {
      if (SENSITIVE_KEYS.has(key)) {
        sanitized[key] = "[REDACTED]";
      } else {
        sanitized[key] = sanitizeValue(val);
      }
    }

    return sanitized;
  }

  return value;
};

export const sanitizeAuditLog = (log) => {
  const sanitized = {
    ...log
  };

  if (sanitized.details) {
    sanitized.details =
      sanitizeValue(sanitized.details);
  }

  return sanitized;
};