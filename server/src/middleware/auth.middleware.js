import AppError from '../utils/AppError.js';
import { verifyToken } from '../utils/jwt.js';
import User from '../models/user.model.js';
import Session from '../models/session.model.js';

export const authenticate = async (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return next(new AppError('Access token required', 401));
  }

  const token = authHeader.split(' ')[1];

  try {
    const decoded = verifyToken(token);

    const user = await User.findById(decoded.id).select('-password');

    if (!user) {
      return next(new AppError('User no longer exists', 401));
    }

    // Tokens issued after session management was enabled carry a session ID.
    // Legacy tokens remain valid only until their normal JWT expiry so existing
    // users can migrate without being locked out.
    const session = decoded.sid
      ? await Session.findOne({
          tokenId: decoded.sid,
          user: user._id,
          revokedAt: null,
          expiresAt: { $gt: new Date() },
        })
      : null;

    if (decoded.sid && !session) {
      return next(new AppError('Session expired or revoked', 401));
    }

    if (session) {
      session.lastSeenAt = new Date();
      await session.save();
    }

    req.user = {
      id: user.id,
      role: user.role,
      email: user.email,
      sessionId: session?.id || null,
      tokenId: session?.tokenId || null,
    };

    next();
  } catch (error) {
    if (error instanceof AppError) {
      return next(error);
    }

    return next(new AppError(`Authentication failed: ${error.message}`, 401));
  }
};
