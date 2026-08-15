import Audit from "../models/audit.model.js";

export const createAuditLog = async ({
    user = null,
    action,
    resourceType = null,
    resourceId = null,
    status,
    ipAddress = "",
    userAgent = "",
    details = {}
}) => {

    try {

        await Audit.create({
            user,
            action,
            resourceType,
            resourceId,
            status,
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