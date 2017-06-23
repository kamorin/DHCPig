#!/bin/sh -e
##
## test-help.sh
##
## Made by phil
##
##
## Started on  Fri 23 Jun 2017 09:05:14 AM CEST pret
## Last update Fri 23 Jun 2017 09:13:50 AM CEST pret
##

# test that the help (--h, --help) message is no more "None"
helpsize=$(dhcpig --help 2>/dev/null|wc -l)

if test "$helpsize" != "42"
then
  exit 1
fi
