import hashlib
import sys
import json
import socket
import os
import shutil
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256

# 服务器地址和端口号
SERVER_HOST = '106.13.232.108'
SERVER_PORT = 12346

# public key
RSA_PUBLIC_KEY = '../rsa_key/id_rsa_public.pem'

# signed data hex length
SIGN_HEX_DATA_LEN = 512

def calculate_sha256(file_path, left_cnt):
	with open(file_path, "rb") as file:
		file_data = file.read()
		if left_cnt != 0:
			data_to_hash = file_data[:-left_cnt]
		else:
			data_to_hash = file_data

	# 计算数据的 SHA-256 散列值
	sha256 = hashlib.sha256()
	sha256.update(data_to_hash)
	hash_result = sha256.hexdigest().upper()

	return hash_result

def tcp_client_req(send_data):
	received_data = None
	client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

	try:
		client_socket.connect((SERVER_HOST, SERVER_PORT))

		while True:            
			client_socket.sendall(send_data.encode())
			received_data = client_socket.recv(1024)
			if received_data is not None:            
				break
	
	except Exception as e:
		print("catch exception:", e)
		return None

	finally:
		client_socket.close()
		return received_data

def get_file_sign_from_remote(file_path):
	hash_value = calculate_sha256(file_path, 0)
	#print("sha256: ", hash_value)

	json_data = {}
	json_resp = None

	json_data['operation'] = 'rsa_sign_req'
	json_data['digest'] = hash_value
	json_str = json.dumps(json_data, separators=(',', ':'))
	print(json_str)

	received_data = tcp_client_req(json_str)
	if received_data is None:
		print("Get none resp data")
	#print("sign resp:", received_data.decode())
	json_resp = json.loads(received_data.decode())
	json_resp_str = json.dumps(json_resp, separators=(',', ':'))
	#print(json_resp['sign'])
	print(json_resp_str)
	
	return json_resp['sign']

def create_signed_file(file_path):
	print('Creating signature data of %s' % file_path)
	sign_data = get_file_sign_from_remote(file_path)
	dir_name = os.path.dirname(file_path)
	file_simple_name = os.path.splitext(os.path.basename(file_path))[0]
	file_suffix = os.path.splitext(file_path)[-1]
	signed_file_path = dir_name + '/' + file_simple_name + '-signed' + file_suffix

	#print(signed_file_path)
	shutil.copyfile(file_path, signed_file_path)
	with open(signed_file_path, "a") as file:
		file.write(sign_data)

	print('Creating signatured file %s' % signed_file_path)
	return signed_file_path

def verify_signed_file(signed_file_path):
	print('Checking signature data of %s' % signed_file_path)
	#hash_value_new = calculate_sha256(signed_file_path, SIGN_HEX_DATA_LEN)
	#print(hash_value_new)

	with open(signed_file_path, 'rb') as file:
		file.seek(-SIGN_HEX_DATA_LEN, 2)  # 从文件的末尾倒数第 512 个字节开始读取
		last_512_bytes = file.read()

	try:
		#print(last_512_bytes.decode())
		sign_data = bytes.fromhex(last_512_bytes.decode())
		#print(sign_data)
		#print(len(sign_data))
	except (ValueError, TypeError):
		print("Get Signature data failed.")
		return False

	with open(signed_file_path, "rb") as file:
		file_data = file.read()
		data_to_hash = file_data[:-SIGN_HEX_DATA_LEN]
	#print(data_to_hash)

	with open(RSA_PUBLIC_KEY, "r") as key_file:
		public_key = RSA.importKey(key_file.read())

	h = SHA256.new(data_to_hash)
	try:
		PKCS1_v1_5.new(public_key).verify(h, sign_data)
		print("Signature successfully.")
		return True
	except (ValueError, TypeError):
		print("Signature verification failed.")
		return False

def run_axf_file(axf_file):
	is_verify_ok = verify_signed_file(axf_file)
	if is_verify_ok:
		print("Verify ok, begin to run axf file ...")
		cmd = "/opt/VHT/bin/FVP_MPS2_Cortex-M7 --stat --simlimit 8000 -f ../AVH-CM7/vht_config.txt " + axf_file
		os.system(cmd)
	else:
		print("Verify fail, stop to run axf file ...")

def help():
	print("Usage: python " + sys.argv[0] + " [sign | verify | run] <file_path>")

if __name__ == "__main__":
	if len(sys.argv) < 3:
		help()
		sys.exit(1)

	if len(sys.argv) > 3:
		SERVER_PORT = int(sys.argv[3])

	operation = sys.argv[1]
	if operation == "sign":		
		file_path = sys.argv[2]
		signed_file_path = create_signed_file(file_path)
	elif operation == "verify":		
		signed_file_path = sys.argv[2]
		verify_signed_file(signed_file_path)
	elif operation == "run":
		axf_file = sys.argv[2]
		run_axf_file(axf_file)
	else:
		help()
		sys.exit(1)

	sys.exit(0)