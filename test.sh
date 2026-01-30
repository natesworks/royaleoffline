#!/usr/bin/bash
npm run build -- "--gmv=$1" --device=android
ts-node main.ts
