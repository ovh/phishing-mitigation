#!/bin/sh

LOCK_FILE="/var/lock/tilera-phishing-ip-conf.lock"

if [ -z "$1" ]
then
  echo "reload using default value"
else
  if [ $1 == "clean" ]
  then
    echo "Removing lock file $LOCK_FILE"
    rm -f $LOCK_FILE
    exit 0
  fi
fi

if [ -f $LOCK_FILE ]
then
  echo "Can't reload now, lock file $LOCK_FILE is present"
  exit 1
else

  if [ -z "$(pidof tilera-phishing)" ]; then
    echo "tilera-phishing isn't running"
    exit 1
  fi

  touch $LOCK_FILE

  killall -s USR1 tilera-phishing
  while [ -f $LOCK_FILE ]
  do
    sleep 1
  done

  echo "Config reloaded"
fi
