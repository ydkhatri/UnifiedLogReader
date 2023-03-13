#!/bin/sh
BASE=/tmp/decode_log
rm -rf $BASE
mkdir -p $BASE
unzip -d $BASE $1 /private/var/db\* 
UnifiedLogReader.py -f SQLITE -l DEBUG  ${BASE}/private/var/db/uuidtext ${BASE}/private/var/db/diagnostics/timesync ${BASE}/private/var/db/diagnostics/ ${BASE}/output
