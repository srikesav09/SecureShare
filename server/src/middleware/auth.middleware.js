import AppError from "../utils/AppError.js";
import { verifyToken } from "../utils/jwt.js";
import User from "../models/user.model.js";

export const authenticate = async (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return next(new AppError("Access token required", 401));
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = verifyToken(token);

    const user = await User.findById(decoded.id).select("-password");

    if (!user) {
      return next(new AppError("User no longer exists", 401));
    }

    req.user = {
      id: user.id,
      role: user.role,
      email: user.email,
    };

    next();
    
  } catch (error) {
    if (error instanceof AppError) {
      return next(error);
    }

    return next(new AppError(`Authentication failed: ${error.message}`, 401));
  }
};