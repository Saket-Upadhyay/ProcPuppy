import yara
from queue import Queue
from pathlib import Path
from yaramem import PIDsQueue

PIDsQueue = Queue()
yara.set_config(max_strings_per_rule=20000, stack_size=32768)
MALWARE_RULES = "YaraRules/index.yar"

rules = yara.compile(filepath=MALWARE_RULES, includes=True)



# stingvuild="/proc/"+PID+"/fd/3"


for x in Path('/proc').iterdir():
	if x.is_dir() and x.name.isdigit():
		# PIDsQueue.put(int(x.name))
		PIDsQueue.put("/proc/"+str(x.name)+"/exe")
		if Path("/proc/"+str(x.name)+"/fd").exists():
			try:
				for y in Path("/proc/"+str(x.name)+"/fd").iterdir():
					if y.name.isdigit() and int(y.name) > 2:
						PIDsQueue.put("/proc/"+str(x.name)+"/fd/"+str(y.name))
			except Exception:
				pass



def mycallback(data):
	print('[+] Rule: {}, MAP: {}, Strings: {}'.format(data.get('rule'), _file, data.get('strings')))

def scan(_file):
	try:
		print(_file)
		rules.match(_file, callback=mycallback, which_callbacks=yara.CALLBACK_MATCHES)
	except yara.Error:
		pass # process dead



while not PIDsQueue.empty():
	_file=PIDsQueue.get()
	scan(_file)
