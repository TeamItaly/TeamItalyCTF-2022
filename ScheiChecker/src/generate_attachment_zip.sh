#!/usr/bin/env bash
rm -rf zip_build
rm -rf ../attachments/source.zip
mkdir zip_build

file="./redis.conf"
terminator="# This part of configuration should be stripped from the final .zip for players."
while IFS= read line
do
    if [ "$line" = "$terminator" ]; then
        break
    elif [ "$line" = "" ]; then
        continue
    else
        echo "$line"
    fi
done < "$file" > ./zip_build/redis.conf

cp .example.env ./zip_build/.example.env
cp generate_config_files.sh ./zip_build/generate_config_files.sh
cp docker-compose.yml ./zip_build/docker-compose.yml
cp README.md ./zip_build/README.md

mkdir ./zip_build/backend
mkdir ./zip_build/prices-cache

RSYNC_OPTS=(
    --exclude='node_modules'
    --exclude='config.js'
    --recursive
    --progress
)

rsync "${RSYNC_OPTS[@]}" "./backend" "./zip_build/"
rsync "${RSYNC_OPTS[@]}" "./prices-cache" "./zip_build/"

cd zip_build && zip -r ../../attachments/schei-checker.zip . && cd -

#rm -rf zip_build
echo "Successfully generated attachment zip"