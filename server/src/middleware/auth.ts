import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

interface JwtPayload {
  username: string;
}

export const authenticateToken = (req: Request, res: Response, next: NextFunction) => {
  // TODO: verify the token exists and add the user data to the request object
  const authHeader = req.headers.authorization;

  if (authHeader) {
    const token = authHeader.split(' ')[1];
    const secretKey = process.env.JWT_SECRET_KEY || '';

    jwt.verify(token, secretKey, (err, user) => {
      if (err) {
        return res.sendStatus(403);
      }
      req.user = user as JwtPayload;
      return next();
    });
  } else {
    res.sendStatus(401);
  } 
};

export const generateToken = (user_name: string) => {
  const secretKey = process.env.JWT_SECRET_KEY || '';

  return jwt.sign({ user_name }, secretKey, { expiresIn: '1h' });
};
