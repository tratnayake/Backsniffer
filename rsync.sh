#! /bin/bash
while true; do
  change=$(inotifywait -e close_write,moved_to,create .)
  change=${change#./ * }
  if [ "$change" = "*.py" ]; then echo "uest1onQ?" | rsync ./*.py 192.168.0.1:/root/Documents/Backsniffer3; fi
done
