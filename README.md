# ProcPuppy
Multi-threaded Yara-based process memory scanner for *nix systems.

> By default it scans the exe and fd/* symlinks, you can add your own list too.

### How to setup
```
cd ~
sudo apt-get update && sudo apt-get upgrade
sudo apt-get install virtualenv
virtualenv ProcPuppyEnv
source ProcPuppyEnv/bin/activate
pip install -r requirements.txt
deactivate
```

### Run
```
source ProcPuppyEnv/bin/activate
python procpuppy.py
```

### Global Variables
```
YARARULEFILE = "<YOUR VALID YARA FILE HERE>"
NUMBEROFTHREADS = <NUMBER OF THREADS YOU WANT, must be integer>
```

Tested on:

 - [x] Ubuntu 20.4
 - [x]  WSL 2.0 on Windows 10 Pro for Workstations 21H1 BUILD:19043.1288

