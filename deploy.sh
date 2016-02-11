#!/bin/bash

TILERA_TARGET=${TILERA_TARGET:=$1}

rsync -rav -e ssh --exclude="stats-collector/*" --include ".git/" --exclude=".*" --exclude="tilera-phishing/bin/*" $(pwd) $TILERA_TARGET:/home/tilera/code/
