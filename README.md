run with::
    sudo ./wscan.py | tee logs/home-$(date '+%s').log | ./wscan.py load
or tracking a specific AP
    sudo ./wscan.py 00:00:00:00:00:00 | tee logs/home-$(date '+%s').log | ./wscan.py load
