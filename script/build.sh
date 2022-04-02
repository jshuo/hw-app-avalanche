#!/bin/bash

set -e

cd ../..
PATH=$(yarn bin):$PATH
cd -
babel --source-maps -d lib src
flow-copy-source -v src lib
cp -r lib /home/jshuo/workspace/avax-secux-txsign/node_modules/@secux/hw-app-avalanche
cp -r src /home/jshuo/workspace/avax-secux-txsign/node_modules/@secux/hw-app-avalanche
