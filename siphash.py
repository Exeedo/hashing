def print_hex(name, value, length=16):
	''' Print varname = value in hexadecimal (length is number of digits to be printed) '''
	print(f"{name} = {value:#0{length+2}x}")

def split_lower_upper_words(big_int):
	''' Split a big integer (> 64 bits) into lower 64-bit and upper (the rest) '''
	lower = big_int & ((1 << 64) - 1)
	upper = big_int >> 64
	return lower, upper

def circular_shift(var, shift):
	''' Circular shift to the left within a 64-bit word '''
	lower, upper = split_lower_upper_words(var << shift)
	return lower | upper

def str2int(str_msg):
	''' Convert a string to byte array as an integer form '''
	int_msg = 0
	for i, c in enumerate(str_msg):
		int_msg |= ord(c) << (i << 3)
	return int_msg

def negate(val):
	''' Negate the value as hashes are printed as a signed 64-bit integer '''
	return -(val ^ ((1 << 64) - 1)) - 1

class SipHash:
	''' Class to apply siphash algorithm '''
	def __init__(self, secret_key=None, verbose=False, allow_negative=False):
		self.__secret_key = self.__get_default_secret_key() if secret_key is None else secret_key
		print_hex('Hashing using key', self.__secret_key, length=32)
		self.__state_variables = [0, 0, 0, 0]
		self.__hash_value = 0
		self.__verbose = verbose
		self.__allow_negative = allow_negative

	def __reset(self):
		''' Reset state variables and hash value '''
		self.__state_variables = [0, 0, 0, 0]
		self.__initialization()
		self.__hash_value = 0

	@staticmethod
	def __get_default_secret_key():
		''' Get the internal value of the built-in siphash function '''
		from ctypes import c_uint64, pythonapi, Structure, Union
		class SIPHASH(Structure):
			_fields_ = [('k0', c_uint64), ('k1', c_uint64),]
		class _Py_HashSecret_t(Union):
			_fields_ = [('siphash', SIPHASH)]
		hashsecret = _Py_HashSecret_t.in_dll(pythonapi, '_Py_HashSecret')
		siphash_secret_key = (hashsecret.siphash.k1 << 64) | hashsecret.siphash.k0
		return siphash_secret_key

	def set_secret_key(self, new_secret_key):
		''' Set the value of the secret key '''
		self.__secret_key = new_secret_key
		self.__reset()

	def __add_size_byte(self, msg):
		''' Append the byte indicating the size of the message to be hashed '''
		size_bits = len(bin(msg)) - 2
		size_bytes = (size_bits + 7) >> 3
		size_words = (size_bytes + 8) >> 3
		size_bytes &= 0xFF
		size_words <<= 6
		updated_msg = msg | (size_bytes << (size_words - 8))
		if self.__verbose:
			print(f"size of {msg:#x}: {size_bits}, {size_bytes}, {size_words}")
			print(f"new val {updated_msg:#x}")
		return updated_msg

	def __print_state_variables(self):
		''' Print the internal state variables in hexadecimal format '''
		for i in range(4):
			print_hex(f'v{i}', self.__state_variables[i])

	def __half_sipround(self, s, t):
		''' Apply half the operation of a sipround function '''
		var = self.__state_variables
		var[0], _ = split_lower_upper_words(var[0] + var[1])
		var[2], _ = split_lower_upper_words(var[2] + var[3])
		var[1] = circular_shift(var[1], s) ^ var[0]
		var[3] = circular_shift(var[3], t) ^ var[2]
		var[0] = circular_shift(var[0], 32)
		var[0], var[2] = var[2], var[0]

	def __double_sipround(self):
		''' Equivalent to calling sipround function twice '''
		if self.__verbose:
			print('----- before double sipround -----')
			self.__print_state_variables()
			print('----------------------------------')
		self.__half_sipround(13, 16)
		self.__half_sipround(17, 21)
		self.__half_sipround(13, 16)
		self.__half_sipround(17, 21)
		if self.__verbose:
			print('----- after  double sipround -----')
			self.__print_state_variables()
			print('----------------------------------')

	def __siphash_main(self, int_msg):
		''' Main siphash algorithm '''
		self.__compression(int_msg)
		self.__finalization()
		for v in self.__state_variables:
			self.__hash_value ^= v
		if self.__hash_value & (1 << 63) and not self.__allow_negative:
			self.__hash_value = negate(self.__hash_value)

	def __initialization(self):
		''' Initialization step of siphash algorithm '''
		k0, k1 = split_lower_upper_words(self.__secret_key)
		if self.__verbose:
			print_hex('key', self.__secret_key)
			print_hex('k0', k0)
			print_hex('k1', k1)
		self.__state_variables[0] = k0 ^ 0x736F6D6570736575
		self.__state_variables[1] = k1 ^ 0x646F72616E646F6D
		self.__state_variables[2] = k0 ^ 0x6C7967656E657261
		self.__state_variables[3] = k1 ^ 0x7465646279746573
		if self.__verbose:
			print('----- initial values -----')
			self.__print_state_variables()
			print('--------------------------')

	def __compress_word(self, word):
		''' Compress 1 word as a part of compression step '''
		self.__state_variables[3] ^= word
		self.__double_sipround()
		self.__state_variables[0] ^= word

	def __compression(self, msg):
		''' Compression step of siphash algorithm '''
		updated_msg = self.__add_size_byte(msg)
		lower, upper = split_lower_upper_words(updated_msg)
		self.__compress_word(lower)
		while upper:
			lower, upper = split_lower_upper_words(upper)
			self.__compress_word(lower)

	def __finalization(self):
		''' Finalization step of siphash algorithm '''
		self.__state_variables[2] ^= 0xFF
		self.__double_sipround()
		self.__double_sipround()
		if self.__verbose:
			print('-----  final  values -----')
			self.__print_state_variables()
			print('--------------------------')

	def get_hash(self, input_msg):
		''' Hashing the input message '''
		self.__reset()
		if isinstance(input_msg, str):
			self.__siphash_main(str2int(input_msg))
		elif isinstance(input_msg, int):
			self.__siphash_main(input_msg)
		else:
			# If input is neither integer nor string, apply the hash to the id
			self.__siphash_main(id(input_msg))
		return self.__hash_value

if __name__ == '__main__':
	siphash = SipHash()
	msg = 'hello'
	print_hex(f'user-defined hash of {msg}', siphash.get_hash(msg))
	print_hex(f'built-in hash of {msg}', hash(msg))
