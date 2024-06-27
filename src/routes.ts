import express, { Request, Response } from 'express';
import { body, validationResult } from 'express-validator';
import bcrypt from 'bcrypt';
import { exec } from 'child_process';
import { user, generateToken, verifyToken } from './auth';
import { parseLogLine, LogData } from './utilities';
import logger from './logger';

const router = express.Router();

// Root GET endpoint
router.get('/', async (req: Request, res: Response) => {
    res.json({ message: 'Welcome to my challenging api' });
    const logLine: string = '127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326';
    const parsedLog: LogData = parseLogLine(logLine);
    console.log(parsedLog);
});

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


router.get('/sql-injection', (req: Request, res: Response) => {
    const { startDate, endDate } = req.query;

    // if (!startDate || !endDate) {
    //     return res.status(400).json({ message: 'Both start and end dates are required' });
    // }

    try {
        const start = new Date(startDate as string);
        const end = new Date(endDate as string);
        const diffInDays = Math.ceil((end.getTime() - start.getTime()) / (1000 * 60 * 60 * 24));

        logger.info(`Calculated the number of days between ${startDate} and ${endDate} as ${diffInDays}`);
        //query all different URI
        //order by num
        //show number of accesses from a same IP in a given time
        //if matches criteria it should be an sql-injection attack
        //Recomend implementing input sanitazion in and verify DB user permission for the matching URI
        exec(`grep -Ei '(\\bselect\\b|\\bfrom\\b|\\bwhere\\b|\\bunion\\b|\\bjoin\\b|\\binsert\\b|\\bupdate\\b|\\bdelete\\b|\\bdrop\\b|\\bcreate\\b|\\balter\\b|\\bexec+\\b|\\bexecute\\b|\\bxp_cmdshell\\b)' /app/data/access.log`, (error, stdout) => {
            if (error) {
                logger.error(`Error executing OS command: ${error}`);
                return res.status(500).json({ message: 'Error executing OS command' });
            }

            logger.info(`OS command output: ${stdout}`);
            const logLines = stdout.trim().split('\n');
            const parsedLogs: LogData[] = logLines.map(parseLogLine);
            const vulnerableEndPoints: string[] = [...new Set(parsedLogs
                .filter(log => log.status === '200' || log.status === '204')
                .map(log => log.request.split('?')[0]))];
            res.status(200).json({ message: "Please check validations in input fields for this vulnerableEndPoints", vulnerableEndPoints: vulnerableEndPoints, matchingRequests: parsedLogs });
        });
    } catch (err) {
        logger.error(`Error calculating days between dates: ${err}`);
        res.status(400).json({ message: 'Invalid date format' });
    }
});

router.get('/xss', (req: Request, res: Response) => {
    const { startDate, endDate } = req.query;

    // if (!startDate || !endDate) {
    //     return res.status(400).json({ message: 'Both start and end dates are required' });
    // }

    try {
        const start = new Date(startDate as string);
        const end = new Date(endDate as string);
        const diffInDays = Math.ceil((end.getTime() - start.getTime()) / (1000 * 60 * 60 * 24));

        logger.info(`Calculated the number of days between ${startDate} and ${endDate} as ${diffInDays}`);
        exec(`grep -Ei '(%3Cscript\\b|%3Chtml\\b|%3Ciframe\\b|%3Cembed\\b|%3Cobject\\b|%3Clink\\b|%3Cstyle\\b|\\bjavascript:\\b|\\bonload=\\b|\\bonclick=\\b|\\bonerror=\\b|\\bonmouseover=\\b)' /app/data/access.log`, (error, stdout) => {
            if (error) {
                logger.error(`Error executing OS command: ${error}`);
                return res.status(500).json({ message: 'Error executing OS command' });
            }

            logger.info(`OS command output: ${stdout}`);
            const logLines = stdout.trim().split('\n');
            const parsedLogs: LogData[] = logLines.map(parseLogLine);
            res.status(200).json({ daysBetween: diffInDays, commandOutput: parsedLogs });
        });
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
        //query all different URI
        //order by num
        //show number of accesses from a same IP in a given time
        //if matches criteria it is a posible brute-force attack
        //Recomend implementing some king of temporal block by number of attempts

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
