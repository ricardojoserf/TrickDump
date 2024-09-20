import os
import sys
import json
import zipfile
import argparse


def get_args():
	parser = argparse.ArgumentParser()
	parser.add_argument('-l', '--lock_json',   required=False, default='lock.json', action='store', help='File path for lock.json')
	parser.add_argument('-s', '--shock_json',  required=False, default='shock.json', action='store', help='File path for shock.json')
	parser.add_argument('-b', '--barrel_json', required=False, default='barrel.json', action='store', help='File path for barrel.json')
	parser.add_argument('-z', '--barrel_zip',  required=False, default='barrel.zip', action='store', help='Zip file containing the regions memory dumps')
	parser.add_argument('-d', '--barrel_directory',  required=False, default='barrel_output', action='store', help='Directory containing the regions memory dumps')
	parser.add_argument('-o', '--output_file', required=False, default='oogie.dmp', action='store', help='Dump file name')
	my_args = parser.parse_args()
	return my_args


def read_binary_file(file_path):
    with open(file_path, 'rb') as file:
        byte_array = file.read()
    return byte_array


def get_dump_bytearr(lock_json, shock_json, barrel_json, zip_file, files_dir):
	# Calculations
	number_modules = str(len(shock_json))
	modulelist_size = 4
	modulelist_size += 108*int(number_modules)
	for module in shock_json:
		module_fullpath_len = len(module.get("field1"))
		modulelist_size += (module_fullpath_len*2 + 8)

	mem64list_offset = modulelist_size + 0x7c
	mem64list_size = 16 + 16*len(barrel_json)
	offset_memory_regions = mem64list_offset + mem64list_size

	print("[+] Total number of modules: \t" + number_modules)
	print("[+] ModuleListStream size:   \t" + str(modulelist_size))
	print("[+] Mem64List offset: \t\t" + str(mem64list_offset))
	print("[+] Mem64List size: \t\t" + str(mem64list_size))

	# Header
	header  = b'\x4d\x44\x4d\x50' # Signature
	header += b'\x93\xa7' # Version
	header += b'\x00\x00' # ImplementationVersion
	header += b'\x03\x00\x00\x00' # NumberOfStreams
	header += b'\x20\x00\x00\x00' # StreamDirectoryRva
	header += b'\x00'*(32 - len(header)) # Other fields

	# Stream Directory
	stream_directory =  b'\x04\x00\x00\x00' # Type 4 = ModuleListStream
	stream_directory += modulelist_size.to_bytes(4, 'little') # Size
	stream_directory += b'\x7c\x00\x00\x00' # Address

	stream_directory += b'\x07\x00\x00\x00' # Type 7 = SystemInfoStream
	stream_directory += b'\x38\x00\x00\x00' # Size = 56 (constant)
	stream_directory += b'\x44\x00\x00\x00' # Address = 0x44 (constant)

	stream_directory += b'\x09\x00\x00\x00' # Type 9 = Memory64ListStream
	stream_directory += mem64list_size.to_bytes(4, 'little') # # Size
	stream_directory += mem64list_offset.to_bytes(4, 'little') # Address

	# SystemInfoStream
	processor_architecture = 9
	majorversion = int(lock_json.get("field0"))
	minorversion = int(lock_json.get("field1"))
	build_number = int(lock_json.get("field2"))
	systeminfo_stream = processor_architecture.to_bytes(2, 'little') # Processor architecture
	systeminfo_stream += b'\x00'*6
	systeminfo_stream += majorversion.to_bytes(4, 'little') # Major version
	systeminfo_stream += minorversion.to_bytes(4, 'little') # Minor version
	systeminfo_stream += build_number.to_bytes(4, 'little') # Build number
	systeminfo_stream += b'\x00'*(56-len(systeminfo_stream))

	# ModuleListStream
	modulelist_stream = int(number_modules).to_bytes(4, 'little') # NumberOfModules
	pointer_index = 0x7c
	pointer_index += len(modulelist_stream) # 4 
	pointer_index += 108*int(number_modules)

	for module in shock_json:
		modulelist_stream += int(module.get("field2"),16).to_bytes(8, 'little') # Module Address
		modulelist_stream += int(module.get("field3")).to_bytes(8, 'little') # Module Size
		modulelist_stream += b'\x00'*4
		modulelist_stream += pointer_index.to_bytes(8, 'little') # Pointer to unicode string
		full_path = module.get("field1")
		pointer_index += len(full_path)*2 + 8
		modulelist_stream += b'\x00'*(108-(8+8+4+8))

	for module in shock_json:
		full_path = module.get("field1")
		unicode_bytearr = bytearray(full_path.encode('utf-16-le'))
		modulelist_stream += (len(full_path)*2).to_bytes(4, 'little') # Unicode length
		modulelist_stream += unicode_bytearr # Unicode string
		modulelist_stream += 4*b'\x00' # Empty character + padding

	# Memory64List
	memory64list_stream = len(barrel_json).to_bytes(8, 'little') # NumberOfEntries
	memory64list_stream += offset_memory_regions.to_bytes(8, 'little') # MemoryRegionsBaseAddress
	for mem64 in barrel_json:
		memory64list_stream += int(mem64.get("field1"),16).to_bytes(8, 'little') # Mem64 Address
		memory64list_stream += int(mem64.get("field2")).to_bytes(8, 'little')    # Mem64 Size

	# Add memory regions from zip file
	memory_bytearr = b''

	if os.path.exists(zip_file):
		with zipfile.ZipFile(zip_file, 'r') as zip_file_handle:
			for file_info in zip_file_handle.infolist():
				with zip_file_handle.open(file_info.filename) as file:
					file_bytes = file.read()
					memory_bytearr += file_bytes

	elif os.path.exists(files_dir):
		files = os.listdir(files_dir)
		full_paths = [os.path.join(files_dir, file) for file in files]		
		for f_p in full_paths:
			try:
				with open(f_p, 'rb') as f_:  # Open the file in binary mode ('rb')
					file_bytes = f_.read()  # Read all bytes from the file
					memory_bytearr += file_bytes
			except Exception as e:
				print("Error " + str(e))

	dump_file = header + stream_directory + systeminfo_stream + modulelist_stream + memory64list_stream + memory_bytearr
	return dump_file


def create_file(output_file, dump_file):
	with open(output_file, "wb") as binary_file:
	    binary_file.write(dump_file)


def show_banner():
	print("  _______   _      _    _____                        ")
	print(" |__   __| (_)    | |  |  __ \\                       ")
	print("    | |_ __ _  ___| | _| |  | |_   _ _ __ ___  _ __  ")
	print("    | | '__| |/ __| |/ / |  | | | | | '_ ` _ \\| '_ \\ ")
	print("    | | |  | | (__|   <| |__| | |_| | | | | | | |_) |")
	print("    |_|_|  |_|\\___|_|\\_\\_____/ \\__,_|_| |_| |_| .__/ ")
	print("                                              | |    ")
	print("                           by @ricardojoserf  |_|    ")
	print("")


def main():
	args = get_args()
	lock_file = args.lock_json
	shock_file = args.shock_json
	barrel_file = args.barrel_json
	memory_files = args.barrel_zip
	memory_dir = args.barrel_directory
	output_file = args.output_file

	show_banner()

	# Generate JSON object from file
	if os.path.exists(lock_file):
		lock_json   = json.loads(open(lock_file).read().splitlines()[0])[0]
	else:
		print("[-] File " + lock_file + " not found")
		sys.exit(0)
	if os.path.exists(shock_file):
		shock_json  = json.loads(open(shock_file).read().splitlines()[0])
		shock_json = [obj for obj in shock_json if obj.get('field0') != ""]
	else:
		print("[-] File " + shock_file + " not found")
		sys.exit(0)
	if os.path.exists(barrel_file):
		barrel_json = json.loads(open(barrel_file).read().splitlines()[0])
	else:
		print("[-] File " + barrel_file + " not found")
		sys.exit(0)
	if not os.path.exists(memory_files) and not os.path.exists(memory_dir):
		print("[-] File " + memory_files + " and directory " +  memory_dir + " not found")
		sys.exit(0)

	dump_file = get_dump_bytearr(lock_json, shock_json, barrel_json, memory_files, memory_dir)
	create_file(output_file, dump_file)
	print("[+] Dump file " + output_file + " created ")


if __name__ == "__main__":
	main()