#!/usr/bin/env bash
[ ! -f ./.env ] && echo "Please copy .env.example to .env and edit it" && exit 1
source ./.env
[ "$FLAG" == "" ] && echo "FLAG is empty, trying to read it from ../flag.txt" && FLAG=$(cat ../flag.txt)
[ "$FLAG" != "" ] && echo "Successfully read ${FLAG}"
[ "$FLAG" == "" ] && echo "FLAG is empty, please set it in .env or in ../flag.txt" && exit 1

[ "$COIN_MARKET_CAP_API_KEY" == "" ] && echo "COIN_MARKET_CAP_API_KEY is empty, test mode will be used" && 
[ "$PORT" == "" ] && echo "PORT is empty" && exit 1
[ "$JWT_SECRET" == "" ] && echo "JWT_SECRET is empty" && exit 1

sed -i '/FLAG/d' ./.env && echo "FLAG=$FLAG" >> ./.env


> ./backend.config.js
{
    echo "export const port = 8080;"
    echo "export const redisURL = \"redis://schei-redis:6379\";"
    echo "export const serviceURL = \"http://schei-pricescache\";"
    echo "export const jwtSecret = \"${JWT_SECRET}\";"
} >> ./backend.config.js

> ./prices-cache.config.js
{
    echo "export const port = 80;"
    echo "export const CoinMarketCapApiKey = \"${COIN_MARKET_CAP_API_KEY}\";"
    echo "export const coinID = 3476;"
    echo "export const convTo = \"EUR\";"
    echo "export const coinName = \"Italian Lira Token (ITL)\";"
    echo "export const pollingInterval = 5 * 60 * 1000;"
} >> ./prices-cache.config.js

echo "Successfully generated config files, start with docker-compose up"