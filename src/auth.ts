import jwt from 'jsonwebtoken';
import { Request, Response, NextFunction } from 'express';
import dotenv from 'dotenv';

dotenv.config();

export const user = {
  id: 1,
  username: process.env.USERNAME!,
  password: process.env.PASSWORD!,
};

// Generate a JWT token
export function generateToken(userId: number): string {
  return jwt.sign({ userId }, process.env.JWT_SECRET_KEY!, { expiresIn: '1h' });
}

// Middleware to verify the JWT token
export function verifyToken(req: Request, res: Response, next: NextFunction) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  jwt.verify(token, process.env.JWT_SECRET_KEY!, (err, decoded) => {
    if (err) {
      return res.status(403).json({ error: 'Failed to authenticate token' });
    }
    req.body.userId = (decoded as { userId: number }).userId;
    next();
  });
}
