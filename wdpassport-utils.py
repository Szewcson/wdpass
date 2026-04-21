#!/usr/bin/env python3
import sys
import os
import struct
import getpass
import json
import pwd
import random
import string
from hashlib import sha256
from random import randint
import argparse
import pyudev
import contextlib
import base64
import secretstorage

try:
	import py3_sg as py_sg
except ImportError as e:
	print("You need to install the \"py_sg\" module. Try 'pip3 install --user git+https://github.com/crypto-universe/py_sg'.")
	sys.exit(1)

BLOCK_SIZE = 512
HANDSTORESECURITYBLOCK = 1
dev = None
device_name = None
device_model = None
device_serial = None

## Print fail message with red leading characters
def fail(str):
	return "\033[91m" + "[!]" + "\033[0m" + " " + str

## Print fail message with green leading characters
def success(str):
	return "\033[92m" + "[*]" + "\033[0m" + " " + str

## Print fail message with blue leading characters
def question(str):
	return "\033[94m" + "[+]" + "\033[0m" + " " + str

## Convert an integer to his human-readable secure status
def sec_status_to_str(security_status):
	if security_status == 0x00:
		return "No lock"
	elif security_status == 0x01:
		return "Locked"
	elif security_status == 0x02:
		return "Unlocked"
	elif security_status == 0x06:
		return "Locked, unlock blocked"
	elif security_status == 0x07:
		return "No keys"
	else:
		return "unknown"

## Convert an integer to his human-readable cipher algorithm
def cipher_id_to_str(cipher_id):
	if cipher_id == 0x10:
		return "AES_128_ECB"
	elif cipher_id == 0x12:
		return "AES_128_CBC"
	elif cipher_id == 0x18:
		return "AES_128_XTS"
	elif cipher_id == 0x20:
		return "AES_256_ECB"
	elif cipher_id == 0x22:
		return "AES_256_CBC"
	elif cipher_id == 0x28:
		return "AES_256_XTS"
	elif cipher_id == 0x30:
		return "Full Disk Encryption"
	else:
		return "Unknown ({})".format(hex(cipher_id))

## Transform "cdb" in char[]
def _scsi_pack_cdb(cdb):
	return struct.pack('{0}B'.format(len(cdb)), *cdb)

## Convert int from host byte order to network byte order
def htonl(num):
    return struct.pack('!I', num)

## Convert int from  host byte order to network byte order
def htons(num):
    return struct.pack('!H', num)

## Call the device and get the selected block of Handy Store.
def read_handy_store(page):
	cdb = [0xD8,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x01,0x00]
	i = 2
	for c in htonl(page):
		cdb[i] = c
		i+=1
	data = py_sg.read_as_bin_str(dev, _scsi_pack_cdb(cdb), BLOCK_SIZE)
	return data

## Call the device and set the selected block of Handy Store.
def write_handy_store(page, data):
	cdb = [0xDA,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x01,0x00]
	i = 2
	for c in htonl(page):
		cdb[i] = c
		i+=1
	py_sg.write(dev, _scsi_pack_cdb(cdb), data)

## Calculate checksum on the returned data
def hsb_checksum(data):
	c = 0
	for i in range(510):
		c = c + data[i]
	c = c + data[0]  ## Some WD Utils count data[0] twice, some other not ...
	r = (c * -1) & 0xFF
	return r

## Call the device and get the encryption status.
## The function returns three values:
##
## SecurityStatus: 
##		0x00 => No lock
##		0x01 => Locked
##		0x02 => Unlocked
##		0x06 => Locked, unlock blocked
##		0x07 => No keys
## CurrentCipherID
##		0x10 =>	AES_128_ECB
##		0x12 =>	AES_128_CBC
##		0x18 =>	AES_128_XTS
##		0x20 =>	AES_256_ECB
##		0x22 =>	AES_256_CBC
##		0x28 =>	AES_256_XTS
##		0x30 =>	Full Disk Encryption
## KeyResetEnabler (4 bytes that change every time)
##
def get_encryption_status():
	cdb = [0xC0, 0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x00]
	data = py_sg.read_as_bin_str(dev, _scsi_pack_cdb(cdb), BLOCK_SIZE)
	if data[0] != 0x45:
		print(fail("Wrong encryption status signature: %s." % hex(data[0])))
		sys.exit(1)
	return {
		"Locked": data[3],
		"Cipher": data[4],
		"PasswordLength": struct.unpack('!H', data[6:8])[0],
		"KeyResetEnabler": data[8:12],
	}

## Call the device and get the first block of Handy Store.
## The function returns three values:
## 
## Iteration - number of iteration (hashing) in password generation
## Salt - salt used in password generation
## Hint - hint of the password if used.
def read_handy_store_block1():
	signature = [0x00, 0x01, 0x44, 0x57] # "01WD"
	sector_data = read_handy_store(1)
	## Check if retrieved Checksum is correct
	if hsb_checksum(sector_data) != sector_data[511]:
		print(fail("Wrong HSB1 checksum."))
		sys.exit(1)
	## Check if retrieved Signature is correct. If not,
	# there is no hashing parameter data set.
	for i in range(0,4):
		if signature[i] != sector_data[i]:
			return None

	iteration = struct.unpack_from("<I",sector_data[8:])
	salt = sector_data[12:20]
	hint = sector_data[24:226]
	return (iteration[0], salt, hint)

def write_handy_store_block1(iteration, salt, hint):
	sector_data = [0x00, 0x01, 0x44, 0x57] # "01WD" signature
	sector_data += [0, 0, 0, 0] # reserved
	sector_data += struct.pack("<I", iteration)
	sector_data += salt[0:8]
	sector_data += [0, 0, 0, 0] # reserved
	sector_data += hint[0:202]
	sector_data += [0] * 285
	sector_data += [hsb_checksum(bytes(sector_data))]
	print(sector_data)
	assert len(sector_data) == BLOCK_SIZE
	write_handy_store(1, bytes(sector_data))

## Perform password hashing with requirements obtained from the device
def mk_password_block(passwd, iteration, salt):
	clean_salt = ""
	salt += bytes([0x00, 0x00])
	for i in range(int(len(salt)/2)):
		if salt[2 * i] == 0x00 and salt[2 * i + 1] == 0x00:
			break
		clean_salt = clean_salt + chr(salt[2 * i])

	password = clean_salt + passwd
	password = password.encode("utf-16")[2:]

	for i in range(iteration):
		password = sha256(password).digest()

	return password

def _resolve_secret_service_uid():
	sudo_uid = os.environ.get("SUDO_UID")
	if sudo_uid is not None:
		try:
			return int(sudo_uid)
		except ValueError:
			pass

	pkexec_uid = os.environ.get("PKEXEC_UID")
	if pkexec_uid is not None:
		try:
			return int(pkexec_uid)
		except ValueError:
			pass

	return os.getuid()


def _session_bus_path(uid):
	return f"/run/user/{uid}/bus"


def _session_bus_address(uid):
	return f"unix:path={_session_bus_path(uid)}"


def _session_bus_path_from_address(address):
	prefix = "unix:path="
	if address.startswith(prefix):
		return address[len(prefix):]
	return None

def _secret_service_unavailable_message(uid):
	return (
		f"Secret Service is not reachable because no session bus was found for uid {uid}. "
		"Saved-password unlock will not work until a user session bus is available."
	)


def _configure_secret_service_bus(uid):
	bus_address = os.environ.get("DBUS_SESSION_BUS_ADDRESS")
	if bus_address:
		bus_path = _session_bus_path_from_address(bus_address)
		if bus_path is not None and not os.path.exists(bus_path):
			raise RuntimeError(_secret_service_unavailable_message(uid))
		return

	if os.path.exists(_session_bus_path(uid)):
		os.environ["DBUS_SESSION_BUS_ADDRESS"] = _session_bus_address(uid)
	else:
		raise RuntimeError(_secret_service_unavailable_message(uid))


def _resolve_secret_service_user():
	uid = _resolve_secret_service_uid()
	try:
		return pwd.getpwuid(uid)
	except KeyError as e:
		raise RuntimeError(f"Unable to resolve account information for uid {uid}.") from e


def _prepare_secret_service_process():
	user = _resolve_secret_service_user()
	uid = user.pw_uid
	runtime_dir = f"/run/user/{uid}"

	if os.geteuid() == 0:
		os.initgroups(user.pw_name, user.pw_gid)
		os.setgid(user.pw_gid)
		os.setuid(uid)
	elif os.geteuid() != uid:
		raise RuntimeError(
			f"Secret Service access requires uid {uid}, but the helper is running as uid {os.geteuid()}."
		)

	os.environ["HOME"] = user.pw_dir
	os.environ["LOGNAME"] = user.pw_name
	os.environ["USER"] = user.pw_name
	if os.path.exists(runtime_dir):
		os.environ["XDG_RUNTIME_DIR"] = runtime_dir

	_configure_secret_service_bus(uid)

	return user

def _run_secret_service_action_impl(action, device_name, password=None):
	_prepare_secret_service_process()

	try:
		with contextlib.closing(secretstorage.dbus_init()) as con:
			col = secretstorage.get_default_collection(con)
			if col.is_locked():
				col.unlock()

			attributes = {
				'application': 'wdpassport-utils',
				'device': device_name,
			}

			if action == "get":
				items = col.search_items(attributes)

				for item in items:
					if item.get_label().startswith('WD Passport'):
						if item.is_locked():
							item.unlock()
						stored_password = base64.b64decode(item.get_secret())
						return {
							"ok": True,
							"password": base64.b64encode(stored_password).decode("ascii"),
						}

				return {"ok": False, "message": "No password found"}

			if action == "save":
				items = list(col.search_items(attributes))
				encoded = base64.b64encode(password)
				label = f"WD Passport: {device_name.replace('_', ' ')}"

				if items:
					item = items[0]
					if item.is_locked():
						item.unlock()
					item.set_secret(encoded)
					return {"ok": True, "message": f"Updated password for {device_name}"}

				col.create_item(label, attributes, encoded, replace=True)
				return {"ok": True, "message": f"Saved password for {device_name}"}

			raise RuntimeError(f"Unsupported Secret Service action: {action}")
	except Exception as e:
		return {"ok": False, "message": f"Secret Service failed: {e}"}


def _run_secret_service_action(action, device_name, password=None):
	request_read_fd, request_write_fd = os.pipe()
	response_read_fd, response_write_fd = os.pipe()
	pid = os.fork()

	if pid == 0:
		try:
			_prepare_secret_service_process()
			os.close(request_write_fd)
			os.close(response_read_fd)
			os.dup2(request_read_fd, sys.stdin.fileno())
			os.dup2(response_write_fd, sys.stdout.fileno())
			os.close(request_read_fd)
			os.close(response_write_fd)
			os.execv(sys.executable, [
				sys.executable,
				os.path.abspath(__file__),
				"--secret-service-helper",
			])
		except Exception as e:
			response = {"ok": False, "message": f"Secret Service failed: {e}"}
			os.close(request_read_fd)
			os.close(request_write_fd)
			os.close(response_read_fd)
			with os.fdopen(response_write_fd, "w") as pipe:
				json.dump(response, pipe)
			os._exit(1)

	os.close(request_read_fd)
	os.close(response_write_fd)
	request = {
		"action": action,
		"device_name": device_name,
	}
	if password is not None:
		request["password_b64"] = base64.b64encode(password).decode("ascii")

	with os.fdopen(request_write_fd, "w") as pipe:
		json.dump(request, pipe)

	with os.fdopen(response_read_fd) as pipe:
		payload = pipe.read()

	_, status = os.waitpid(pid, 0)
	if not payload:
		return {"ok": False, "message": "Secret Service helper exited without a response."}

	try:
		response = json.loads(payload)
	except json.JSONDecodeError:
		return {"ok": False, "message": "Secret Service helper returned an invalid response."}

	if os.WIFSIGNALED(status):
		return {
			"ok": False,
			"message": f"Secret Service helper terminated with signal {os.WTERMSIG(status)}.",
		}

	if os.WIFEXITED(status) and os.WEXITSTATUS(status) != 0 and response.get("ok", False):
		return {"ok": False, "message": "Secret Service helper exited unexpectedly."}

	return response

def _run_secret_service_helper():
	try:
		request = json.load(sys.stdin)
	except json.JSONDecodeError as e:
		print(json.dumps({"ok": False, "message": f"Invalid Secret Service helper request: {e}"}))
		return

	action = request.get("action")
	device_name = request.get("device_name")
	password = None

	if not action or not device_name:
		print(json.dumps({
			"ok": False,
			"message": "Invalid Secret Service helper request: missing action or device_name.",
		}))
		return

	password_b64 = request.get("password_b64")
	if password_b64 is not None:
		try:
			password = base64.b64decode(password_b64)
		except Exception as e:
			print(json.dumps({"ok": False, "message": f"Invalid Secret Service helper password: {e}"}))
			return

	print(json.dumps(_run_secret_service_action_impl(action, device_name, password)))


def get_password_from_secret_service(device_name):
	response = _run_secret_service_action("get", device_name)
	if not response.get("ok"):
		print(fail(response["message"]))
		sys.exit(1)

	return base64.b64decode(response["password"])

def save_password_to_secret_service(device_name, password):
	response = _run_secret_service_action("save", device_name, password)
	if response.get("ok"):
		print(success(response["message"]))
	else:
		print(fail(response["message"]))
	

## Unlock the device
def unlock(save_passwd, unlock_with_saved_passwd):
	global device_name
	global device_model
	global device_serial

	## Device should be in the correct state 
	status = get_encryption_status()
	if (status["Locked"] in (0x00, 0x02)):
		print(fail("Your device is already unlocked!"))
		return
	elif (status["Locked"] != 0x01):
		print(fail("Wrong device status!"))
		sys.exit(1)
	
	## Get password from user
	if not unlock_with_saved_passwd:
		print(question("Insert password to Unlock the device"))
		passwd = getpass.getpass("[wdpassport] password for {}: ".format(device_name))
		
		hash_parameters = read_handy_store_block1()
		if not hash_parameters:
			print(fail("Key hash parameters are not valid."))
			sys.exit(1)
		iteration, salt, hint = hash_parameters
		
		pwd_hashed = mk_password_block(passwd, iteration, salt)
	
	## Get password from secrt service
	else:
		print(success("Unlock use saved password"))
		pwd_hashed = get_password_from_secret_service(f"{device_model}_{device_serial}")

	pw_block = [0x45,0x00,0x00,0x00,0x00,0x00]
	pwblen = status["PasswordLength"]
	for c in htons(pwblen):
		pw_block.append(c)

	pwblen = pwblen + 8
	cdb = [0xC1,0xE1,0x00,0x00,0x00,0x00,0x00,0x00,0x28,0x00]
	cdb[8] = pwblen

	try:
		## If there aren't exceptions the unlock operation is OK.
		py_sg.write(dev, _scsi_pack_cdb(cdb), _scsi_pack_cdb(pw_block) + pwd_hashed)
		print(success("Device unlocked."))
	except:
		## Wrong password or something bad is happened.
		print(fail("Wrong password."))
		return

	if save_passwd:
		save_password_to_secret_service(f"{device_model}_{device_serial}", pwd_hashed)

## Change device password
## If the new password is empty the device state change and become "0x00 - No lock" meaning encryption is no more used.
## If the device is unencrypted a user can choose a password and make the whole device encrypted.
## 
## DEVICE HAS TO BE UNLOCKED TO PERFORM THIS OPERATION
##
def change_password():
	# Check drive's current status.
	status = get_encryption_status()
	if (status["Locked"] not in (0x00, 0x02)):
		print(fail("Device has to be unlocked or without encryption to perform this operation."))
		sys.exit(1)

	# Get and confirm the current and new password.
	if status["Locked"] == 0x00:
		# The device doesn't have a password.
		old_passwd = ""
	else:
		old_passwd = getpass.getpass("Current password: ")
	new_passwd = getpass.getpass("New password: ")
	new_passwd2 = getpass.getpass("New password (again): ")
	if new_passwd != new_passwd2:
		print(fail("Password didn't match."))
		sys.exit(1)

	## Both passwords shouldn't be empty
	if (len(old_passwd) <= 0 and len(new_passwd) <= 0):
		print(fail("Password can't be empty. The device doesn't yet have a password."))
		sys.exit(1)

	# Construct the command.
	pw_block = [0x45,0x00,0x00,0x00,0x00,0x00]

	# Get the length in bytes of the key for the drive's current cipher
	# and put that length into the command.
	pwblen = status["PasswordLength"]
	pw_block += list(htons(pwblen))

	# For compatibility with the WD encryption tool, use the same
	# hashing mechanism and parameters to turn the user's password
	# input into a key. The parameters are stored in unencrypted data.
	hash_parameters = read_handy_store_block1()
	if hash_parameters is None:
		# No password hashing parameters are stored on the device.
		# Make some up and write them to the device.
		hash_parameters = (
			1000,
			''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(8)).encode("ascii"), # eight-byte salt
			b'wdpassport-utils'.ljust(202)
		)
		write_handy_store_block1(*hash_parameters)
		assert read_handy_store_block1() == hash_parameters
	iteration, salt, hint = hash_parameters

	if (len(old_passwd) > 0):
		old_passwd_hashed = mk_password_block(old_passwd, iteration, salt)
		pw_block[3] = pw_block[3] | 0x10
	else:
		old_passwd_hashed = bytes([0x00]*32)

	if (len(new_passwd) > 0):
		new_passwd_hashed = mk_password_block(new_passwd, iteration, salt)
		pw_block[3] = pw_block[3] | 0x01
	else:
		new_passwd_hashed = bytes([0x00]*32)

	if pw_block[3] & 0x11 == 0x11:
		pw_block[3] = pw_block[3] & 0xEE

	cdb = [0xC1, 0xE2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x00]
	pwblen = 8 + 2 * pwblen
	cdb[8] = pwblen
	try:
		## If exception isn't raised the unlock operation gone ok.
		py_sg.write(dev, _scsi_pack_cdb(cdb), _scsi_pack_cdb(pw_block) + old_passwd_hashed + new_passwd_hashed)
		print(success("Password changed."))
	except:
		## Wrong password or something bad is happened.
		print(fail("Error changing password."))
		pass

## Change the internal key used for encryption, every data on the device would be permanently unaccessible.
## Device forgets even the partition table so you have to make a new one.
def secure_erase():
	cdb = [0xC1, 0xE3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00]
	status = get_encryption_status()

	cipher_id = status["Cipher"]

	pw_block = [0x45,0x00,0x00,0x00,cipher_id,0x00,0x00,0x00]

	# For old ciphers, this code used to set the "combine" flag.
	# pw_block[3] = 0x01

	## Set the actual lenght of pw_block (8 bytes + pwblen pseudorandom data)
	pwblen = status["PasswordLength"]
	cdb[8] = pwblen + 8
	## Fill pw_block with random data
	for rand_byte in os.urandom(pwblen):
		pw_block.append(rand_byte)

	## key_reset needs to be retrieved immidiatly before the reset request
	#status, current_cipher_id, key_reset = get_encryption_status()
	key_reset = status["KeyResetEnabler"]
	i = 2
	for c in key_reset:
		cdb[i] = c
		i += 1

	try:
		py_sg.write(dev, _scsi_pack_cdb(cdb), _scsi_pack_cdb(pw_block))
		print(success("Device erased. You need to create a new partition on the device (Hint: fdisk and mkfs)"))
	except:
		## Something bad is happened.
		print(fail("Something went wrong."))
		pass

## Enable mount operations 
## Tells the system to scan the "new" (unlocked) device
def enable_mount(device):
	status = get_encryption_status()
	## Device should be in the correct state 
	if status["Locked"] not in (0x00, 0x02):
		print(fail("Device needs to be unlocked in order to mount it."))
		return

	scsi_host = device.find_parent(subsystem="scsi", device_type="scsi_host").sys_name

	# Detach(?) the device.
	with open("/sys/block/{}/device/delete".format(device.sys_name), "w") as f:
		f.write("1\n")

	# Scan for devices.
	with open("/sys/class/scsi_host/{}/scan".format(scsi_host), "w") as f:
		f.write("- - -\n")
	print(success("Device re-scanned."))


## Main function, get parameters and manage operations
def main(argv): 
	global dev
	global device_name
	global device_model
	global device_serial

	parser = argparse.ArgumentParser()
	parser.add_argument("-u", "--unlock", required=False, action="store_true", help="Unlock")
	parser.add_argument("-us", "--unlock_with_saved_passwd", required=False, action="store_true", help="Unlock with saved passwd")
	parser.add_argument("-m", "--mount", required=False, action="store_true", help="Enable mount point for an unlocked device")
	parser.add_argument("-c", "--change_passwd", required=False, action="store_true", help="Change (or disable) password")
	parser.add_argument("-sp", "--save_passwd", required=False, action="store_true", help="Save passwd")
	parser.add_argument("-e", "--erase", required=False, action="store_true", help="Secure erase device")
	parser.add_argument("-d", "--device", dest="device", required=False, help="Force device path (ex. /dev/sdb). Usually you don't need this option.")
	parser.add_argument("--secret-service-helper", dest="secret_service_helper", action="store_true", help=argparse.SUPPRESS)

	args = parser.parse_args()

	if args.secret_service_helper:
		_run_secret_service_helper()
		return
	
	if len(sys.argv) == 1:
		args.status = True
	
	## Get occurrences of "Passport" devices. Iterate over each disk block device
	## and go up to its parents to find a "WD Passport" device.
	passport_devices = []
	context = pyudev.Context()
	for disk_device in context.list_devices(subsystem='block', DEVTYPE='disk'):
		# If -d is used, filter devices.
		if args.device and disk_device.device_node != args.device:
			continue

		# skip virtul CD-ROM with windows unlocker
		if'ID_CDROM_MEDIA' not in disk_device.properties:
			# Scan parent for device name.
			device = disk_device
			while device is not None:
				if "ID_SERIAL" in device:
					if device.properties["ID_SERIAL"].startswith("Western_Digital_My_"):
						 passport_devices.append(disk_device)
				device = device.parent

	if len(passport_devices) == 0:
		print(fail("No Western Digital Passport device found."))
		sys.exit(1)
	elif len(passport_devices) > 1:
		print(fail("Multiple Western Digital Passport devices found. Use --device /dev/___ to choose."))
		sys.exit(1)

	device = passport_devices[0]
	device_name = device.device_node
	device_model = device.properties["ID_MODEL"]
	device_serial = device.properties["ID_SERIAL_SHORT"]


	## Open the device.
	try:
		dev = open(device.device_node, "r+b")
	except PermissionError:
		print(fail("Could not open {}. Try running as root as 'sudo {}'.".format(
			device_name,
			sys.argv[0])))
		sys.exit(1)
	except:
		print(fail("Something wrong opening {}".format(device_name)))
		sys.exit(1)

	if args.save_passwd and not args.unlock:
		  parser.error("--save_passwd (-sp) requires --unlock (-u)")

	## Report device state if no specific command is given.
	if not args.unlock and not args.change_passwd and not args.erase and not args.mount and not args.unlock_with_saved_passwd:
		status = get_encryption_status()
		print("Device: %s" % device_name)
		print("Security status: %s" % sec_status_to_str(status["Locked"]))
		print("Encryption type: %s" % cipher_id_to_str(status["Cipher"]))

	## Perform actions.
	if args.unlock:
		unlock(args.save_passwd, False)
	if args.unlock_with_saved_passwd:
		unlock(args.save_passwd, True)
	if args.change_passwd:
		print("Changing password for {}...".format(device_name))
		change_password()
	if args.erase:
		print(question("All data on {} will be lost. Are you sure you want to continue? [y/N]".format(
			device_name
		)))
		r = sys.stdin.read(1)
		if r.lower() == 'y':
			secure_erase()
		else:
			print(success("Ok, nevermind."))
	if args.mount:
		enable_mount(device)

if __name__ == "__main__":
	main(sys.argv[1:])
