import dotenv from 'dotenv';
dotenv.config();

import jwt from 'jsonwebtoken';
import crypto from 'crypto';

export const generateToken = (payload, options = {}) => {
  const tokenId = options.tokenId || crypto.randomUUID();
  return jwt.sign({ ...payload, sid: tokenId }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN,
  });
};

export const verifyToken = (token) => {
  return jwt.verify(token, process.env.JWT_SECRET);
};
