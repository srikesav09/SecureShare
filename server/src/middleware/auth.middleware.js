import AppError from "../utils/AppError.js";
import { verifyToken } from "../utils/jwt.js";

export const authenticate = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (
    !authHeader ||
    !authHeader.startsWith("Bearer ")
  ) {
    throw new AppError(
        "Access token required",
        401
    );
  }
  const token = authHeader.split(" ")[1];
  try {
    const decoded = verifyToken(token);

    const user = await User.findById(decoded.id)
    .select("-password");

    if (!user) {
      throw new AppError(
        "User no longer exists",
        401
      );
    }

    req.user = user;
    next();
  } catch {
    throw new AppError("Invalid or expired token", 401);
  }
};