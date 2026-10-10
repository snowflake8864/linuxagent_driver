#!/bin/bash
uptime_seconds=$(cat /proc/uptime | cut -d. -f1)
current_time=$(date +%s)

if [ $(($current_time - $uptime_seconds)) -lt 300 ]; then
    echo "System is booting, sleeping for a while based on CPU count..."

    cpu_count=$(nproc)

    if [ "$cpu_count" -eq 1 ]; then
        echo "System has 1 CPU, sleeping for 5 minutes..."
        sleep 300  # 5分钟
    elif [ "$cpu_count" -eq 2 ]; then
        echo "System has 2 CPUs, sleeping for 2 minutes..."
        sleep 120  # 2分钟
    elif [ "$cpu_count" -eq 3 ]; then
        echo "System has 3 CPUs, sleeping for 1 minute..."
        sleep 60   # 1分钟
    else
        echo "System has more than 3 CPUs, no sleep required."
    fi
fi

exit 0

