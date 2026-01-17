#!/usr/bin/bash
adb forward tcp:27042 tcp:27042
npm run build -- "--gmv=$1" --device=android
ts-node main.ts
