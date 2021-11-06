# MIT License

# Copyright (c) 2021 Saket Upadhyay

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


import yara # star of the show
from pathlib import Path # to work with /proc file paths easily
from queue import Queue # to manage process listings; we used Queue because once fetched the element will be removed, hence no two threads will have same element, We can also use any other Data Structure. 

import threading # needed for multi-threading awesomeness
from time import sleep # who doesn't need some sleep?


#USER DEFINED VARIABLES
YARARULEFILE = "YaraRules/index.yar"
NUMBEROFTHREADS = 6		# A name suggests, 
ENABLEYARAINCLUDE=True	# This should be True if you want to add your rules by adding them as imports in index.yar


#Other configurations
yara.set_config(max_strings_per_rule=20000, stack_size=32768)
lock = threading.Lock()
MapperQueue = Queue()
SCANCOUNT = 0

# Main function that each thread will run
class MainYaraThreadFunction(threading.Thread):

	# yara callback function
	def YaraCallback(self,data):
		print('[+] Rule: {}, MAP: {}, Strings: {}'.format(data.get('rule'), self._file, data.get('strings')))

	def __init__(self):
		threading.Thread.__init__(self)
		self.rules = yara.compile(filepath=YARARULEFILE, includes=ENABLEYARAINCLUDE)

	def run(self):
		while True:
			self._file=MapperQueue.get()
			self.scan(self._file)
			MapperQueue.task_done()
			with lock:
				global SCANCOUNT
				SCANCOUNT += 1

	def scan(self,_file):
		try:
			# OG debug tactic lol
			# print(_file)
			self.rules.match(_file, callback=self.YaraCallback, which_callbacks=yara.CALLBACK_MATCHES)
		except yara.Error:
			pass 

		

# Logic to add target files in the Queue
for x in Path('/proc').iterdir():
	if x.is_dir() and x.name.isdigit():
		# exe maps to the target executable, we want that and we will add this to our Queue
		MapperQueue.put("/proc/"+str(x.name)+"/exe")
		if Path("/proc/"+str(x.name)+"/fd").exists():
			# we TRY because you might not have access to this in kernel or system process
			try:
				for y in Path("/proc/"+str(x.name)+"/fd").iterdir():
					# we check if entries in fd are integers and we skip 0, 1 and 2
					if y.name.isdigit() and int(y.name) > 2 and int(y.name) < 5: #this last condition is just to make the demo fast
						MapperQueue.put("/proc/"+str(x.name)+"/fd/"+str(y.name))
			except Exception:
				pass



print('[!] {} Processes loaded\n[!] Init threads...'.format(MapperQueue.qsize()))

for _ in range(NUMBEROFTHREADS):
	_ = MainYaraThreadFunction()
	_.setDaemon(True)
	_.start()

sleep(3)

while not MapperQueue.empty():
	print('[%] Scanned: {} | Queue size: {} | Active Threads: {}'.format(SCANCOUNT, MapperQueue.qsize(), threading.active_count()-1))
	sleep(10)

MapperQueue.join()