import crypto from "crypto";

export const requestId = (req, res, next) => {

    const id = crypto.randomUUID();
    req.requestId = id;
    res.setHeader("X-Request-Id", id);
    next();

};