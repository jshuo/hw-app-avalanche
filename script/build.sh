#!/bin/bash

set -e

cd ../..
PATH=$(yarn bin):$PATH
cd -
babel --source-maps -d lib src
flow-copy-source -v src lib
# cp -r lib /home/secux/workspace/avalanche-wallet/node_modules/@secux/hw-app-avalanche
# cp -r src /home/secux/workspace/avalanche-wallet/node_modules/@secux/hw-app-avalanche
