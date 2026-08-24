import { createAgent } from './agent';
import { loadConfig } from './config';

createAgent(loadConfig()).start();
