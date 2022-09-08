import * as crypto from 'crypto';
import { redisURL } from '../config.js';
import { createClient } from 'redis';

const client = createClient({
  url: redisURL
});

client.on('error', (err) => console.error('Redis Client Error', err));

await client.connect();
console.log('Connected to database');
async function sha256(message) {
  const msgBuffer = new TextEncoder().encode(message);
  const hashBuffer = await crypto.webcrypto.subtle.digest('SHA-256', msgBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
  return hashHex.toString();
}

export function init(redis) {
  client = redis;
}

export async function get(scope, key, ttl) {
  if (!scope || !key) return;
  if (typeof scope !== 'string' || typeof key !== 'string' || (ttl && typeof ttl !== 'number'))
    return;
  let dbKey = `${scope}#${await sha256(key)}`;
  let data = await client.get(dbKey);
  if (!data) return;
  if (ttl && (await client.ttl(dbKey)) === -1) client.expire(dbKey, ttl);
  return JSON.parse(data);
}

export async function set(scope, key, data, ttl) {
  if (!scope || !key) return;
  if (typeof scope !== 'string' || typeof key !== 'string' || (ttl && typeof ttl !== 'number'))
    return;
  let dbKey = `${scope}#${await sha256(key)}`;
  await client.set(dbKey, JSON.stringify(data));
  if (ttl && (await client.ttl(dbKey)) === -1) client.expire(dbKey, ttl);
}

export async function del(scope, key) {
  if (!scope || !key) return;
  if (typeof scope !== 'string' || typeof key !== 'string') return;
  let dbKey = `${scope}#${await sha256(key)}`;
  await client.del(dbKey);
}

export async function incr(scope, key) {
  if (!scope || !key) return;
  if (typeof scope !== 'string' || typeof key !== 'string') return;
  let dbKey = `${scope}#${await sha256(key)}`;
  return await client.incr(dbKey);
}

export async function decr(scope, key) {
  if (!scope || !key) return;
  if (typeof scope !== 'string' || typeof key !== 'string') return;
  let dbKey = `${scope}#${await sha256(key)}`;
  return await client.decr(dbKey);
}
