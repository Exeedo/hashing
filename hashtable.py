import random
from siphash import SipHash, print_hex

class HashTableEntry:
	''' Class to represent an entry in hash table internal list '''
	__siphash = SipHash(allow_negative=True, secret_key=None)
	hash_compress_bits = 0

	def __init__(self, key=None, value=None, hash_value=None):
		self.__key = key
		self.__value = value
		self.__hash_value = None if key is None else self.__get_hash(key)
		self.__dummy = False

	def __eq__(self, other):
		if self.__hash_value != other.__hash_value:
			return False
		return self.__key == other.__key

	def set_dummy(self):
		''' Set the entry to dummy to indicate it is deleted from the hash table '''
		self.__dummy = True

	@property
	def __state(self):
		'''
		Get the state of the entry
			-1: dummy
			 0: empty
			 1: filled
		'''
		if self.__dummy:
			return -1
		if self.__hash_value is None:
			return 0
		return 1

	@property
	def is_dummy(self):
		''' Check if the entry is dummy '''
		return self.__state == -1

	@property
	def is_filled(self):
		''' Check if the entry is filled '''
		return self.__state == 1

	def is_empty(self):
		''' Check if the entry is filled '''
		return self.__state == 0

	@property
	def key(self):
		''' Define key as a read-only attribute '''
		return self.__key

	@property
	def value(self):
		''' Define value as a read-only attribute '''
		return self.__value

	@property
	def hash_value(self):
		''' Define hash_value as a read-only attribute '''
		return self.__hash_value

	@property
	def hash_str(self):
		return 'None' if self.__hash_value is None else f"{self.__hash_value:#018x}"

	def print(self, index):
		''' Printing the entry'''
		hash_str = None if self.__hash_value is None else f"{self.__hash_value:#018x}"
		print(f"{index} {hash_str} {self.__key} {self.__value} {self.__dummy}")

	def __get_hash(self, key):
		''' Return the hash of the given key '''
		hash_value = self.__siphash.get_hash(key)
		if self.hash_compress_bits:
			return self.__compress_hash(hash_value)
		return hash_value

	def __compress_hash(self, hash_value):
		'''
		Compress the hash value into a certain number of bits
		This is used to increase chances of getting hash collisions for analysis purposes
		'''
		lower = (1 << self.hash_compress_bits) - 1
		compressed_hash = 0
		while hash_value:
			compressed_hash ^= hash_value & lower
			hash_value >>= self.hash_compress_bits
		return compressed_hash


class HashTable:
	''' Class to create a hash table datastructure '''
	load_factor = 1 # must be <= 1

	def __init__(self, hash_key=None, verbose=False, collision_resolution='simple'):
		self.__size = 8
		self.__used = 0
		self.__update_used = True
		self.__verbose = verbose
		self.__internal_list = self.__init_internal_list()
		self.collision_counter = 0
		self.__hash_key = hash_key
		assert collision_resolution in ['simple', 'modified', 'pythonic']
		if collision_resolution == 'simple':
			self.__get_new_index = self.__simple_linear_probing
		elif collision_resolution == 'modified':
			self.__get_new_index = self.__modified_linear_probing
		elif collision_resolution == 'pythonic':
			self.__get_new_index = self.__pythonic_linear_probing
		else:
			assert False, f"Undefined collision resolution technique '{collision_resolution}'"

	def get(self, key):
		''' Getter function of a key '''
		index = self.__lookup_key(key)
		if self.__internal_list[index].is_filled:
			return self.__internal_list[index].value
		if self.__verbose:
			print(f"Key '{key}' does not exist in hash table")
		return None

	def remove(self, key):
		''' Deleter function to a key-value pair '''
		index = self.__lookup_key(key)
		if self.__internal_list[index].is_filled:
			self.__internal_list[index].set_dummy()
			self.__print_internal_list()
		else:
			if self.__verbose:
				print(f"Key '{key}' does not exist in hash table")

	def update(self, key, value):
		''' Setter function for a key-value pair '''
		if (self.__used + 1) / self.__size > self.load_factor:
			self.__increment_size()
		index = self.__lookup_key(key, skip_dummy=False)
		if not self.__internal_list[index].is_dummy and self.__update_used:
			self.__used += 1
		self.__internal_list[index] = HashTableEntry(key=key, value=value)
		self.__print_internal_list()

	def keys(self):
		''' Return the keys as a list '''
		return self.__get_items()[0]

	def values(self):
		''' Return the values as a list '''
		return self.__get_items()[1]

	def items(self):
		''' Return the keys and values as two combined lists '''
		keys, values, _ = self.__get_items()
		return zip(keys, values)

	def __lookup_key(self, key, skip_dummy=True):
		'''
		Return the index at which key exists, or an empty index to enter key
		skip_dummy should be True for getter and deleter functions, but False for setter
		'''
		entry = HashTableEntry(key=key)
		hash_value = entry.hash_value
		index = hash_value & (self.__size - 1) # initial index
		while True:
			if self.__internal_list[index].is_dummy:
				if not skip_dummy:
					return index
			elif self.__internal_list[index].is_filled:
				if entry == self.__internal_list[index]:
					return index
			else:
				return index
			self.__print_collision(index, key, entry.hash_value)
			index, hash_value = self.__get_new_index(index, hash_value)
			if self.__verbose:
				hash_str = 'None' if hash_value is None else f"{hash_value:#018x}"
				print(f"new index: {index}, new hash value: {hash_str}")

	def __get_items(self):
		''' Return keys, values and hashes as lists '''
		keys, values, hashes = [], [], []
		for entry in self.__internal_list:
			if entry.is_filled:
				hashes.append(entry.hash_value)
				keys.append(entry.key)
				values.append(entry.value)
		return keys, values, hashes

	def __init_internal_list(self):
		''' Initializing the internal list with correct size '''
		return [HashTableEntry()] * self.__size

	def __print_internal_list(self):
		''' Print the elements of the internal list '''
		if not self.__verbose:
			return
		print('-'*18, 'internal list', '-'*17)
		for index, entry in enumerate(self.__internal_list):
			entry.print(index)
		print('-' * 50)

	def __print_collision(self, index, key, hash_value):
		''' Print the details of the hash collision for analysis purposes '''
		self.collision_counter += 1
		if not self.__verbose:
			return
		old = self.__internal_list[index]
		hash_str = None if hash_value is None else f"{hash_value:#018x}"
		old_str = None if old.hash_value is None else f"{old.hash_value:#x}"
		print(f"Found collision at index {index}, "
				f"found key:'{old.key}' with hash:{old_str}, "
				f"entered key:'{key}' with hash:{hash_str}")
		# breakpoint()

	def __increment_size(self):
		''' Doubling the size of the hash table (internal list) '''
		verbose = self.__verbose
		self.__verbose = False
		self.__update_used = False
		if verbose:
			print(f"Resizing the intenal list from {self.__size} to {self.__size << 1}")
		self.__size <<= 1
		items = self.items()
		self.__internal_list = self.__init_internal_list()
		for key, value in items:
			self.update(key, value)
		self.__verbose = verbose
		self.__print_internal_list()
		self.__update_used = True

	def __simple_linear_probing(self, prev_index, hash_value):
		''' New index = previous index + 1 (mod size) '''
		return (prev_index + 1) & (self.__size - 1), hash_value

	def __modified_linear_probing(self, prev_index, hash_value):
		''' New index = 5 x previous index + 1 (mod size) '''
		return (5 * prev_index + 1) & (self.__size - 1), hash_value

	def __pythonic_linear_probing(self, prev_index, hash_value):
		''' New index = 5 x previous index + 1 + hash value (mod size) '''
		return (5 * prev_index + 1 + hash_value) & (self.__size - 1), hash_value >> 5

if __name__ == '__main__':
	average_simple = 0
	average_modified = 0
	average_pythonic = 0
	n, m = 100, 100
	for _ in range(n):
		secret_key = random.getrandbits(128)
		squares_simple = HashTable(hash_key=secret_key, verbose=False, collision_resolution='simple')
		squares_modified = HashTable(hash_key=secret_key, verbose=False, collision_resolution='modified')
		squares_pythonic = HashTable(hash_key=secret_key, verbose=False, collision_resolution='pythonic')
		for i in range(m):
			squares_simple.update(i, i*i)
			squares_modified.update(i, i*i)
			squares_pythonic.update(i, i*i)
		average_simple += squares_simple.collision_counter
		average_modified += squares_modified.collision_counter
		average_pythonic += squares_pythonic.collision_counter
	average_simple /= n
	average_modified /= n
	average_pythonic /= n
	print(f"Average collisions using simple collision resolution technique for {m} keys over {n} iterations: {average_simple}")
	print(f"Average collisions using modified collision resolution technique for {m} keys over {n} iterations: {average_modified}")
	print(f"Average collisions using pythonic collision resolution technique for {m} keys over {n} iterations: {average_pythonic}")
