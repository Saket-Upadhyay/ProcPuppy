<!-- # ProcPuppy -->
<!-- Multi-threaded Yara-based process memory scanner for *nix systems. -->

![](https://github.com/Saket-Upadhyay/ProcPuppy/blob/main/ProcPuppy.png)

> By default it scans the exe and fd/* symlinks, but you can add your own list too.
> The default Yara rule file is `YaraRules/index.yar`.

## Initial setup
```
cd ~
sudo apt-get update && sudo apt-get upgrade
sudo apt-get install virtualenv git
git clone https://github.com/Saket-Upadhyay/ProcPuppy.git
cd ProcPuppy
virtualenv ProcPuppyEnv
source ProcPuppyEnv/bin/activate
pip install -r requirements.txt
deactivate
```

## Run
```
cd ~/ProcPuppy
source ProcPuppyEnv/bin/activate
python procpuppy.py
```

## Global Variables
```
YARARULEFILE = "<YOUR VALID YARA FILE HERE>"
NUMBEROFTHREADS = <NUMBER OF THREADS YOU WANT, must be integer>
ENABLEYARAINCLUDE= <True/False> (Enables or Disables 'include' capabilities of the yara compiler.)
```


## Import Custom Yara Rules
There are two ways to do it-

### Method 1
You can either add a import statement to "YaraRules/index.yar" like -
```yara
include "PhPinImages"
include "CustomExeSig"
include "<path to your custom rule>" 
```
(for this `ENABLEYARAINCLUDE` must be set to `True`) 

### Method 2
Or you can also direct the `YARARULEFILE` variable to your custom file directly.

_Suggestion: If you are using multiple rule files, the first option is better. If you are using single file with multiple rules defined in it, second option is better._

---

Tested on:

 - [x] Ubuntu 20.4
 - [x]  WSL 2.0 on Windows 10 Pro for Workstations 21H1 BUILD:19043.1288

> Presented at [PyCode Conference](https://pycode-conference.org/) 2021 (Online).
> See [Saket-Upadhyay/Talks_and_Presentation](https://github.com/Saket-Upadhyay/Talks_and_Presentation) for presentation slides and credits.

> _Thanks to macrovector for the base puppy vector in the logo, I downloaded it from www.freepik.com, then edited it for my use._
