import hashlib

def checksum(s):
	"""
	s: bytes
	return: bytes[4]
	"""
	cs = hashlib.sha256(s).digest()
	cs = hashlib.sha256(cs).digest()
	return cs[:4]

Base58Table = b"rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"
def b2b58(s):
	"""
	s: bytes
	return: ([0-9a-zA-Z] - {0, I, O, l})[]
	"""
	ds = list(s)
	v = 0
	for d in ds:
		v = v*256+d
	b = b""
	while v > 0:
		b = bytes([Base58Table[v % 58]]) + b
		v = v // 58
	return b

def i2b58(v):
	"""
	i: int
	return: ([0-9a-zA-Z] - {0, I, O, l})[]
	"""
	b = b""
	while v > 0:
		b = bytes([Base58Table[v % 58]]) + b
		v = v // 58
	return b

def b582b(s):
	"""
	s: ([0-9a-zA-Z] - {0, I, O, l})[]
	return: bytes
	"""
	h = dict([(c, i) for i, c in enumerate(Base58Table)])
	v = 0
	for i in range(len(s)):
		v = v*58 + h[s[i]]
	rv = b''
	while v>0:
		rv = bytes([v%256]) + rv
		v = v//256
	return rv

def b2hex(b):
	"""
	b: bytes
	return: [0-9A-F][]
	"""
	return b''.join([b"%02X" % c for c in b])

def hex2b(b):
	"""
	b: [0-9A-F][]
	return: bytes
	"""
	assert len(b) % 2 == 0
	return bytes.fromhex(b.decode('utf-8'))

def genXRPSecret(b16):
	"""
	b16: [0, 256)[16]
	see: https://wiki.ripple.com/Encodings

	Example:
	h = genXRPSecret([0]*16)
	print(h)
	"""
	withH = bytes([33]) + b16
	s = withH + checksum(withH)
	h = b2b58(s)
	return h

if __name__ == "__main__":
	import sys
	import random
	argv = sys.argv[1:] + [""]*100
	if "lab1" in argv[0]:
		# Base58 playground
		for i in range(65536):
			print(i, i2b58(i))
	elif "min_max" in argv[0]:
		# Show min and max secret key
		"""
		[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
		b'sp6JS7f14BuwFY8Mw6bTtLKWauoUs'
		[255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255]
		b'saGwBRReqUNKuWNLpUAq8i8NkXEPN'
		"""
		bs = [
			bytes([0]*16),
			bytes([255]*16),
		]
		for b in bs:
			print(list(b))
			h = genXRPSecret(b)
			print(h)
	elif "gen" in argv[0]:
		prefix = bytes(argv[1], 'utf-8')
		for i in range(10000000):
			b = bytes([ random.randint(0, 255) for i in range(16) ])
			h = genXRPSecret(b)
			if h[2:2+len(prefix)].lower()==prefix:
				print(h.decode('utf-8'))
#			print(h)
	else:
		# Tests
		print(b2hex(b582b(b'abc')))
		assert b2hex(b582b(b'abc')) == b'498B'

		h = genXRPSecret(bytes([0]*16))
		print(h)
		assert h==b'sp6JS7f14BuwFY8Mw6bTtLKWauoUs'

		# Valid known secret
		h = b"shszLwduksA4JXoLxx1mm2Xc3xTqg"
		b = b582b(h)
		s = b2hex(b)
		print("shszLwduksA4JXoLxx1mm2Xc3xTqg -> hex", s)
		assert s==b'216161A0389AC521D362F9A472315C4D841851B997'

		# Extract checksum
		body = b[:-4]
		print("except checksum", b2hex(body), list(body))

		# Generate checksum and check matches.
		s = body + checksum(body)
		print("with checksum", b2hex(s))
		s = b2b58(s)
		print("base58 encoded", s)
		assert h==s, (h, s)

