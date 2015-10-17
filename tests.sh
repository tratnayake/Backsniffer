#! /bin/bash

echo "1A Test Process Name"
ps aux | grep "client.py" >> Test1A.txt


echo "1B Test Process Name"
ps aux | grep "Non-suspicious-program" >> Test1B.txt
