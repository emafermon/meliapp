
import { exec } from 'child_process';
import { promisify } from 'util';
import logger from './logger';

export interface LogData {
    ip: string;
    identity: string;
    username: string;
    timestamp: string;
    request: string;
    status: string;
    size: string;
    referrer: string;
    userAgent: string;
}

const regex: RegExp = /^(\S+) (\S+) (\S+) \[(.*?)\] "(.*?)" (\d{3}) (\d+) "(.*?)" "(.*?)"/;
const fields: (keyof LogData)[] = [
    'ip',
    'identity',
    'username',
    'timestamp',
    'request',
    'status',
    'size',
    'referrer',
    'userAgent'
];

export function parseLogLine(line: string): LogData {
    const match = line.match(regex);
    if (!match) {
        throw new Error(`Invalid log line: ${line}`);
    }
    const logData: LogData = {} as LogData;
    for (let i = 1; i <= fields.length; i++) {
        logData[fields[i - 1]] = match[i];
    }
    return logData;
}

const execPromise = promisify(exec);

export async function executeCommand(regexQuery: string) {
    const { stdout, stderr } = await execPromise(`${regexQuery} /app/data/access.log`);
    if (stderr) {
        logger.error(`Error executing OS command: ${stderr}`);
        return { message: 'Error retrieving data' };
    }
    logger.info(`OS command output: ${stdout}`);
    const logLines = stdout.trim().split('\n');
    const parsedLogs: LogData[] = logLines.map(parseLogLine);
    const vulnerableEndPoints: string[] = [...new Set(parsedLogs
        .filter(log => log.status === '200' || log.status === '204')
        .map(log => log.request.split('?')[0]))];
    return { message: "Please check validations in input fields for this vulnerableEndPoints", vulnerableEndPoints: vulnerableEndPoints, matchingRequests: parsedLogs };
}

export function getCurrentDateTime(): string {
    const currentDate = new Date();
    return currentDate.toISOString();
}