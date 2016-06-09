from __future__ import print_function
from threading import Lock
import sys

mylock = Lock()
canPrint = True

def syncprint(*a, **b):
	with mylock:
		if canPrint == True:
			print(*a, **b)

def synckill(*a, **b):
	with mylock:
		print(*a, **b)
		canPrint = False
		sys.exit()
