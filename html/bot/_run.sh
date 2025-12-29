#!/bin/bash
# action func 
act() {
    [ $# -lt 1 ] && { echo "1 param is needed."; return 1; }
    cat $1 | ./bot
}

act stand.bot
act walk-first.bot
for n in {1..5}; do
    act walk.bot
done
act walk-end.bot
