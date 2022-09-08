import * as example from './config.example.js';
import * as config from './config.js';

export function checkConfig() {
  if (!process.env.FLAG || !process.env.ADMIN_PASSWORD) {
    console.log('No flag and/or admin password');
    process.exit(1);
  }
  if (config.jwtSecret === example.jwtSecret) {
    console.log('jwtSecret is the same as in config.example.js');
    process.exit(1);
  }
}
