import Audit from "../models/audit.model.js";

export const createAuditLog = async ({
    req = null,
    user = null,
    action,
    resourceType = null,
    resourceId = null,
    status,
    details = {}
}) => {

    try {
        const requestId = req?.requestId || null;

        const ipAddress =
          req?.headers["x-forwarded-for"] ||
          req?.ip ||
          req?.socket?.remoteAddress ||
          "";

        const userAgent =
            req?.headers["user-agent"] ||
            "";


        const audit =await Audit.create({
            user,
            action,
            resourceType,
            resourceId,
            status,
            requestId,
            ipAddress,
            userAgent,
            details
        });

    } catch (error) {

        console.error(
            "Audit logging failed:",
            error.message
        );

    }

};