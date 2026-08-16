import mongoose from "mongoose";

import { AUDIT_ACTIONS, AUDIT_STATUS } from "../utils/constants.js";
import AppError from "../utils/AppError.js";

export const requireAdmin = (req, res, next) => {
  if (!req.user) {
    return next(
      new AppError("Authentication required", 401)
    );
  }

  if (req.user.role !== "ADMIN") {
    return next(
      new AppError("Admin access required", 403)
    );
  }

  next();
};