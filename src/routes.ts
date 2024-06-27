import express, { Request, Response } from 'express';
import { body, validationResult } from 'express-validator';
import bcrypt from 'bcrypt';
import { user, generateToken, verifyToken } from './auth';
import logger from './logger';

const router = express.Router();
// User login
router.post(
    '/login',
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

// Root GET endpoint
router.get('/', async (req: Request, res: Response) => {
    res.json({ message: 'Welcome to my challenging api' });
});

router.get('/sql-injection', verifyToken, (req: Request, res: Response) => {
    const { startDate, endDate } = req.query;

    if (!startDate || !endDate) {
        return res.status(400).json({ message: 'Both start and end dates are required' });
    }

    try {
        const start = new Date(startDate as string);
        const end = new Date(endDate as string);
        const diffInDays = Math.ceil((end.getTime() - start.getTime()) / (1000 * 60 * 60 * 24));

        logger.info(`Calculated the number of days between ${startDate} and ${endDate} as ${diffInDays}`);
        res.status(200).json({ daysBetween: diffInDays });
    } catch (err) {
        logger.error(`Error calculating days between dates: ${err}`);
        res.status(400).json({ message: 'Invalid date format' });
    }
});

router.get('/xss', verifyToken, (req: Request, res: Response) => {
    const { startDate, endDate } = req.query;

    if (!startDate || !endDate) {
        return res.status(400).json({ message: 'Both start and end dates are required' });
    }

    try {
        const start = new Date(startDate as string);
        const end = new Date(endDate as string);
        const diffInDays = Math.ceil((end.getTime() - start.getTime()) / (1000 * 60 * 60 * 24));

        logger.info(`Calculated the number of days between ${startDate} and ${endDate} as ${diffInDays}`);
        res.status(200).json({ daysBetween: diffInDays });
    } catch (err) {
        logger.error(`Error calculating days between dates: ${err}`);
        res.status(400).json({ message: 'Invalid date format' });
    }
});


router.get('/brute-force', verifyToken, (req: Request, res: Response) => {
    const { startDate, endDate } = req.query;

    if (!startDate || !endDate) {
        return res.status(400).json({ message: 'Both start and end dates are required' });
    }

    try {
        const start = new Date(startDate as string);
        const end = new Date(endDate as string);
        const diffInDays = Math.ceil((end.getTime() - start.getTime()) / (1000 * 60 * 60 * 24));

        logger.info(`Calculated the number of days between ${startDate} and ${endDate} as ${diffInDays}`);
        res.status(200).json({ daysBetween: diffInDays });
    } catch (err) {
        logger.error(`Error calculating days between dates: ${err}`);
        res.status(400).json({ message: 'Invalid date format' });
    }
});


router.get('/ddos', verifyToken, (req: Request, res: Response) => {
    const { startDate, endDate } = req.query;

    if (!startDate || !endDate) {
        return res.status(400).json({ message: 'Both start and end dates are required' });
    }

    try {
        const start = new Date(startDate as string);
        const end = new Date(endDate as string);
        const diffInDays = Math.ceil((end.getTime() - start.getTime()) / (1000 * 60 * 60 * 24));

        logger.info(`Calculated the number of days between ${startDate} and ${endDate} as ${diffInDays}`);
        res.status(200).json({ daysBetween: diffInDays });
    } catch (err) {
        logger.error(`Error calculating days between dates: ${err}`);
        res.status(400).json({ message: 'Invalid date format' });
    }
});
export default router;
