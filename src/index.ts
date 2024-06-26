import express, { Express, Request, Response } from 'express';
import { body, validationResult } from 'express-validator';
import bcrypt from 'bcrypt';
import { user, generateToken, verifyToken } from './auth';

const app: Express = express();
const port = 3000;

// Brute force endpoint
app.get(
  '/brute_force',
  [
    body('username').notEmpty(),
    body('password').notEmpty(),
    verifyToken,
  ],
  async (req: Request, res: Response) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { username, password } = req.body;
    if (username !== user.username || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    const token = generateToken(user.id);
    res.json({ token });
  }
);

app.listen(port, () => {
  console.log(`Server started on port ${port}`);
});
