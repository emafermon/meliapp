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

export function getCurrentDateTime(): string {
    const currentDate = new Date();
    return currentDate.toISOString();
}