import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { jwtSecret } from '../config.js';

let adminPassword = '';

export function setPassword(p) {
  adminPassword = p;
}

export function generateJwt(password) {
  if (typeof password !== 'string') return;
  if (password !== adminPassword) return;
  return jwt.sign({ username: 'admin' }, jwtSecret, { expiresIn: '4h' });
}

export function verifyJwt(token) {
  if (typeof token !== 'string') return;
  try {
    return jwt.verify(token, jwtSecret);
  } catch (ex) {
    return null;
  }
}

export function middleware(req, res, next) {
  if (!req.headers.authorization || typeof req.headers.authorization !== 'string')
    return res.status(403).send({
      error: 'Missing authorization header'
    });
  let token = req.headers.authorization.split(' ')[1];
  let decoded = verifyJwt(token);
  if (!decoded)
    return res.status(403).send({
      error: 'Invalid token'
    });
  req.user = decoded;
  next();
}
