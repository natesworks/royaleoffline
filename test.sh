#!/usr/bin/bash
npm run build -- "--arch=$1" --device=android
ts-node main.ts
