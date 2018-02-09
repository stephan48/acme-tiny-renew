#!/bin/bash
cd /root/acme-tiny-renew/
/usr/bin/python renew.py 1>/dev/null 2>&1
/usr/sbin/service nginx reload
