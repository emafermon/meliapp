import express, { Express, Request, Response } from 'express';
import routes from './routes';
import logger from './logger';

const app: Express = express();
app.use(routes);
const port = 3000;

app.listen(port, () => {
  logger.info(`Server started on port ${port}`);
});
