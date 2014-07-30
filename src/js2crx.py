#!/usr/bin/env python
import os, re, sys, json, base64, shutil, struct, urllib, hashlib, subprocess;
version_info = [ 1 , 0 ];



# Python 2/3 support
if (sys.version_info[0] == 3):
	# Version 3
	def py_2or3_str_to_bytes(text, encoding="ascii", errors="strict"):
		return bytes(text, encoding, errors);
	def py_2or3_bytes_to_str(text, encoding="ascii", errors="strict"):
		return text.decode(encoding, errors);
	def py_2or3_byte_ord(char):
		return char;
else:
	# Version 2
	def py_2or3_str_to_bytes(text, encoding="ascii", errors="strict"):
		return text.encode(encoding, errors);
	def py_2or3_bytes_to_str(text, encoding="ascii", errors="strict"):
		return text.decode(encoding, errors);
	def py_2or3_byte_ord(char):
		return ord(char);



# Exceptions
class ExeNotFoundError(Exception):
	pass;
class DataURIError(Exception):
	pass;



# Argument parser
def arguments_parse(arguments, start, descriptor, flagless_argument_order=[], stop_after_all_flagless=False, return_level=0):
	# Setup data
	argument_values = {};
	argument_aliases_short = {};
	argument_aliases_long = {};
	errors = [];

	for k,v in descriptor.items():
		if ("bool" in v and v["bool"] == True):
			argument_values[k] = False;
		else:
			argument_values[k] = None;

		if ("short" in v):
			for flag in v["short"]:
				argument_aliases_short[flag] = k;

		if ("long" in v):
			for flag in v["long"]:
				argument_aliases_long[flag] = k;

	# Parse command line
	end = len(arguments);
	while (start < end):
		# Check
		arg = arguments[start];
		if (len(arg) > 0 and arg[0] == "-"):
			if (len(arg) == 1):
				# Single "-"
				errors.append("Invalid argument {0:s}".format(repr(arg)));
			else:
				if (arg[1] == "-"):
					# Long argument
					arg = arg[2 : ];
					if (arg in argument_aliases_long):
						# Set
						arg_key = argument_aliases_long[arg];
						if (argument_values[arg_key] == False):
							# No value
							argument_values[arg_key] = True;
						else:
							if (start + 1 < end):
								# Value
								start += 1;
								argument_values[arg_key] = arguments[start];
							else:
								# Invalid
								errors.append("No value specified for flag {0:s}".format(repr(arg)));

						# Remove from flagless_argument_order
						if (arg_key in flagless_argument_order):
							flagless_argument_order.pop(flagless_argument_order.index(arg_key));
					else:
						# Invalid
						errors.append("Invalid long flag {0:s}".format(repr(arg)));

				else:
					# Short argument(s)
					arg = arg[1 : ];
					arg_len = len(arg);
					i = 0;
					while (i < arg_len):
						if (arg[i] in argument_aliases_short):
							# Set
							arg_key = argument_aliases_short[arg[i]];
							if (argument_values[arg_key] == False):
								# No value
								argument_values[arg_key] = True;
							else:
								if (i + 1 < arg_len):
									# Trailing value
									argument_values[arg_key] = arg[i + 1 : ];
									i = arg_len; # Terminate
								elif (start + 1 < end):
									# Value
									start += 1;
									argument_values[arg_key] = arguments[start];
								else:
									# Invalid
									errors.append("No value specified for flag {0:s}".format(repr(arg)));

							# Remove from flagless_argument_order
							if (arg_key in flagless_argument_order):
								flagless_argument_order.pop(flagless_argument_order.index(arg_key));
						else:
							# Invalid
							in_str = "";
							if (arg[i] != arg): in_str = " in {0:s}".format(repr(arg));
							errors.append("Invalid short flag {0:s}{1:s}".format(repr(arg[i]), in_str));

						# Next
						i += 1;

		elif (len(flagless_argument_order) > 0):
			# Set
			arg_key = flagless_argument_order[0];
			if (argument_values[arg_key] == False):
				# No value
				argument_values[arg_key] = True;
			else:
				# Value
				argument_values[arg_key] = arg;

			# Remove from flagless_argument_order
			flagless_argument_order.pop(0);
		else:
			# Invalid
			errors.append("Invalid argument {0:s}".format(repr(arg)));

		# Next
		start += 1;
		if (stop_after_all_flagless and len(flagless_argument_order) == 0): break; # The rest are ignored


	# Return
	if (return_level <= 0):
		return argument_values;
	else:
		return ( argument_values , errors , flagless_argument_order , start )[0 : return_level + 1];



# Custom escape function
def escape_command_line_text(text):
	escapes = {
		"\\": "\\",
		"\"": "\"",
		"'": "'",
		"a": "\a",
		"b": "\b",
		"f": "\f",
		"n": "\n",
		"r": "\r",
		"t": "\t",
	};

	re_format = re.compile(r"\\([" + re.escape("".join(escapes.keys())) + "]|x([0-9a-fA-F]{2})|u([0-9a-fA-F]{4}))", re.U | re.DOTALL);

	text = text.decode("utf-8", "ignore");

	def replacer(m, escapes):
		if (m.group(2) is not None):
			return unichr(int(m.group(2), 16));
		elif (m.group(3) is not None):
			return unichr(int(m.group(3), 16));
		else:
			return escapes[m.group(1)];

		return m.group(0);

	return re_format.sub(lambda m: replacer(m, escapes), text);



# Get a unique file name
def get_unique_filename(filename, suffix=None, id_start=0, id_prefix="[" , id_suffix="]", id_limit=-1, return_none=False):
	# Setup
	filename = os.path.abspath(filename);
	if (suffix is None):
		prefix, suffix = os.path.splitext(filename);
	else:
		prefix = filename;

	# Begin
	fn = prefix + suffix;
	has_limit = (id_limit > id_start);

	while (os.path.exists(fn)):
		# Update filename
		fn = "{0:s}{1:s}{2:d}{3:s}{4:s}".format(prefix, id_prefix, id_start, id_suffix, suffix);

		# Update id
		id_start += 1;

		# Limit
		if (has_limit and id_start >= id_limit):
			if (return_none): return None;
			break;

	# Done
	return fn;



# Decode a data:uri into its mime type and data
def decode_data_uri(uri):
	re_data_uri = re.compile(r"^data:([^;,]+)?(?:;charset=([^;,]*))?(;base64)?,(.*)$", re.I | re.U);

	match = re_data_uri.match(uri);
	if (match is not None):
		# Is a proper data uri
		mime_type = match.group(1);
		charset = match.group(2);
		is_base64 = match.group(3) is not None;
		source = match.group(4);

		# Mime type
		if (mime_type is None):
			mime_type = "text/plain";
		else:
			mime_type = mime_type.lower();

		# Charset
		if (not charset):
			charset = "US-ASCII";

		# Decode data
		if (is_base64):
			try:
				source = base64.b64decode(source);
			except TypeError:
				raise DataURIError("Invalid base64");
		else:
			source = source.unquote();
			try:
				source = source.decode(charset);
			except UnicodeDecodeError:
				raise DataURIError("Invalid format");
			except LookupError:
				raise DataURIError("Invalid charset");

		# Return
		return {
			"mime_type": mime_type,
			"data": source,
		};

	# Done
	return None;



# Get ffmpeg info about a file
def ffprobe(input_file, ffprobe_exe="ffprobe"):
	# Info
	cmd = [
		ffprobe_exe,
		"-v", "quiet",
		"-print_format", "json",
		"-show_format",
		"-show_streams",
		"-i", input_file,
	];

	# Start process and communicate
	try:
		p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE);
	except OSError:
		raise ExeNotFoundError("The executable file {0:s} was not found".format(repr(ffprobe_exe)));

	comm = p.communicate()[0];

	# Parse return
	try:
		info_str = comm.decode("utf-8");
	except UnicodeDecodeError:
		return {};

	try:
		info = json.loads(info_str);
	except ValueError:
		return {};

	return info;



# Create a scaled copy of an image
def create_png(input_file, output_file, width=-1, height=-1, scaler="bilinear", ffmpeg_exe="ffmpeg"):
	# Command
	cmd = [
		ffmpeg_exe,
		"-y",
		"-i", input_file,
		"-vf", "scale=w={0:d}:h={1:d}:flags={2:s}".format(width, height, scaler),
		"-f", "image2",
		"-vframes", "1",
		"-compression_level", "10",
		output_file,
	];

	# Start process and communicate
	try:
		p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE);
	except OSError:
		raise ExeNotFoundError("The executable file {0:s} was not found".format(repr(ffmpeg_exe)));

	p.communicate();

	# Parse return
	return (p.returncode == 0);




# Class to build .crx files
class CRXBuilder:
	# Static data
	icon_mime_types = {
		"image/png": ".png",
		"image/jpeg": ".jpg",
		"image/gif": ".gif",
		"image/bmp": ".bmp",
	};
	error_messages = {
		"chrome-not-found": "Chrome executable not found",
		"ffmpeg-not-found": "FFmpeg executable not found",
		"ffprobe-not-found": "FFprobe executable not found",
		"private-key-not-found": "Private key file not found, and auto-generation is not enabled",
		"userscript-not-found": "Userscript input file not found",
		"crx-filename-error": "Invalid filename for .crx file",
		"userscript-encoding": "Userscript source not properly encoded in UTF-8",
		"userscript-metadata-missing": "No ==UserScript== metadata block found",
		"userscript-copy": "Could not copy userscript",
		"requirement-copy": "Could not copy a requirement",
		"resource-copy": "Could not copy a resource",
		"chrome-extension-metadata-missing": "No ==ChromeExtension== metadata block found",
		"error-writing-manifest": "Manifest file could not be opened",
		"private-key-creation-failure": "Could not create a private key",
		"private-key-rename-failure": "Could not rename private key file",
		"crx-creation-failure": "Could not create .crx file",
		"crx-rename-failure": "Could not rename .crx file",
		"crx-read": "Could not read the .crx file",
		"crx-bad-format": "The .crx file contains badly formatted data",
		"error-writing-update-file": "The update file could not be written to",
	};



	# Exceptions
	class ExecutionOrderException(Exception):
		pass;
	class ArgumentException(Exception):
		pass;



	# Get userscript metadata
	@classmethod
	def get_userscript_metadata(cls, source):
		# Patterns
		re_comment = re.compile(r"^\s*(?:\/\/(.*))$", re.U);
		re_header = re.compile(r"^\s*==(.+?)==\s*$", re.U);
		re_param = re.compile(r"^\s@([a-zA-Z0-9_-]+)\s+(.+?)\s*$", re.U);
		re_footer = None;

		# Data
		block_map = {};
		block_list = [];
		block_name = None;
		block_current = None;
		block_current_value_map = None;
		block_current_value_list = None;

		# Read lines
		source_lines = source.splitlines(False);
		last_line_number = 0;
		for i in range(len(source_lines)):
			line = source_lines[i];
			match = re_comment.match(line);
			if (match is None): break; # Not a comment

			line = match.group(1);
			if (line is None): continue; # Empty line

			last_line_number = i;

			if (re_footer is None):
				# Find header
				match = re_header.match(line);
				if (match is not None):
					# Create footer regex
					block_name = match.group(1);
					re_footer = re.compile(r"^\s*==\/(" + re.escape(block_name) + r")==\s*$", re.U);

					# Add to blocks
					block_current_value_map = {};
					block_current_value_list = [];
					block_current = {
						"name": block_name,
						"start": i,
						"end": -1,
						"value_map": block_current_value_map,
						"value_list": block_current_value_list,
					};
					block_list.append(block_current);
					if (block_name in block_map):
						block_map[block_name].append(block_current);
					else:
						block_map[block_name] = [ block_current ];
			else:
				# Footer match
				match = re_footer.match(line);
				if (match):
					# Reset
					re_footer = None;
					block_current["end"] = i;

				# Param match
				else:
					match = re_param.match(line);
					if (match is not None):
						param_name = match.group(1);
						param_value = ( param_name , match.group(2) );

						block_current_value_list.append(param_value);
						if (param_name in block_current_value_map):
							block_current_value_map[param_name].append(param_value);
						else:
							block_current_value_map[param_name] = [ param_value ];



		# Finish
		if (re_footer is not None):
			block_current["end"] = last_line_number;

		# Done
		return {
			"map": block_map,
			"list": block_list,
		};



	# Getting a .crx appid
	@classmethod
	def get_crx_public_key(cls, file):
		crx_magic_signature = "Cr24";
		crx_version = 2;

		# Read header info
		signature = py_2or3_bytes_to_str(file.read(4), "utf-8", "ignore");
		if (signature != crx_magic_signature): return None;

		version = file.read(4);
		if (len(version) != 4 or struct.unpack("<i", version)[0] != crx_version): return None;

		# Public key length
		public_key_byte_length = file.read(4);
		if (len(public_key_byte_length) != 4): return None;
		public_key_byte_length = struct.unpack("<i", public_key_byte_length)[0];

		# Skip
		file.read(4); # signature length

		# Public key
		public_key = file.read(public_key_byte_length);
		if (len(public_key) != public_key_byte_length): return None;
		return public_key;

	@classmethod
	def get_crx_appid_from_public_key(cld, public_key):
		# Hash it
		hashed_pkey = hashlib.sha256(public_key).digest();

		# Convert first 128 bits to mpdecimal
		offset = ord("a");
		appid = [];
		for c in hashed_pkey[0 : 128 // 8]:
			c = py_2or3_byte_ord(c);
			appid.append(chr((c // 16) + offset));
			appid.append(chr((c % 16) + offset));

		# Join and returjn
		return "".join(appid);



	# Private
	def __move_file(self, src, dest):
		try:
			os.remove(dest);
		except OSError:
			pass;

		try:
			os.rename(src, dest);
		except OSError:
			return False;

		return True;

	def __delete_file(self, path):
		try:
			os.remove(path);
		except OSError:
			return False;
		return True;

	def __delete_empty_directory(self, path):
		try:
			os.rmdir(path);
		except OSError:
			return False;
		return True;



	# Construct
	def __init__(self, chrome_exe, ffmpeg_exe, ffprobe_exe):
		# Set executable files
		self.chrome_exe = chrome_exe;
		self.ffmpeg_exe = ffmpeg_exe;
		self.ffprobe_exe = ffprobe_exe;

		self.input_userscript_filename = None;
		self.input_private_key_filename = None;
		self.input_private_key_can_generate = False;
		self.output_crx_filename = None;

		self.javascript_filenames = None;
		self.resource_filenames = None;

		self.userscript_metadata = None;

		self.directory_build = None;

		self.icon_filenames = None;

		self.manifest_filename = None;

	# Build setup
	def setup(self, input_userscript_filename, input_private_key_filename, input_private_key_can_generate, output_crx_filename):
		if (input_userscript_filename is None):
			raise self.ArgumentException("input_userscript_filename cannot be None");
		if (input_private_key_filename is None):
			raise self.ArgumentException("input_private_key_filename cannot be None");
		if (output_crx_filename is None):
			raise self.ArgumentException("output_crx_filename cannot be None");
		if (self.input_userscript_filename is not None):
			raise ExecutionOrderException();

		# Apply files
		self.input_userscript_filename = input_userscript_filename;
		self.input_private_key_filename = input_private_key_filename;
		self.input_private_key_can_generate = input_private_key_can_generate;
		self.output_crx_filename = output_crx_filename;

		# Check that any required input files exist
		if (not os.path.exists(self.input_private_key_filename) and not self.input_private_key_can_generate):
			return ( "private-key-not-found" , None );

		# Create temp folders
		self.directory_build = get_unique_filename(os.path.splitext(self.output_crx_filename)[0]);
		try:
			os.makedirs(self.directory_build);
		except OSError:
			pass;
		except Error:
			return ( "crx-filename-error" , None );

		# Okay
		return None;

	# Parse userscript metadata
	def read_metadata(self):
		if (self.input_userscript_filename is None or self.userscript_metadata is not None):
			raise ExecutionOrderException();

		# Copy
		js_filename = os.path.join(self.directory_build, os.path.split(self.input_userscript_filename)[1]);
		try:
			shutil.copyfile(self.input_userscript_filename, js_filename);
		except IOError:
			return ( "userscript-copy" , None );

		self.javascript_filenames = [ js_filename ];
		self.resource_filenames = [];

		# Open userscript
		try:
			input_file_userscript = open(js_filename, "rb");
		except IOError as e:
			return ( "userscript-not-found" , None );

		# Read
		source = input_file_userscript.read();
		input_file_userscript.close();

		# Decode using UTF-8
		try:
			source = source.decode("utf-8");
		except UnicodeDecodeError as e:
			return ( "userscript-encoding" , None );

		# Read metadata
		self.userscript_metadata = self.get_userscript_metadata(source);

		if ("UserScript" not in self.userscript_metadata["map"]):
			return ( "userscript-metadata-missing" , None );

		if ("ChromeExtension" not in self.userscript_metadata["map"]):
			return ( "chrome-extension-metadata-missing" , None );

		# Copy any @require/@resource
		cemd_values = self.userscript_metadata["map"]["ChromeExtension"][0]["value_map"];
		if ("resource" in cemd_values):
			for file in cemd_values["resource"]:
				file_path = os.path.abspath(os.path.join(os.path.split(self.input_userscript_filename)[0], file[1]));
				file_path_target = os.path.join(self.directory_build, os.path.split(file_path)[1]);

				try:
					shutil.copyfile(file_path, file_path_target);
				except IOError:
					return ( "resource-copy" , file[1] );

				self.resource_filenames.append(file_path_target);

		if ("require" in cemd_values):
			for file in cemd_values["require"]:
				file_path = os.path.abspath(os.path.join(os.path.split(self.input_userscript_filename)[0], file[1]));
				file_path_target = os.path.join(self.directory_build, os.path.split(file_path)[1]);

				try:
					shutil.copyfile(file_path, file_path_target);
				except IOError:
					return ( "requirement-copy" , file[1] );

				self.javascript_filenames.append(file_path_target);



		# Okay
		return None;

	# Generate all icons
	def generate_icons(self):
		if (self.userscript_metadata is None or self.icon_filenames is not None):
			raise ExecutionOrderException();

		self.icon_filenames = [];

		usmd_values = self.userscript_metadata["map"]["UserScript"][0]["value_map"];
		cemd_values = self.userscript_metadata["map"]["ChromeExtension"][0]["value_map"];
		if ("icon" in usmd_values):
			# Decode icon (if it's a data uri)
			icon_uri = usmd_values["icon"][0][1];
			try:
				icon_data = decode_data_uri(icon_uri);
			except DataURIError:
				icon_data = None;

			if (icon_data is not None and icon_data["mime_type"] in self.icon_mime_types):
				# Write to a file
				main_icon_filename = os.path.join(self.directory_build, "icon{0:s}".format(self.icon_mime_types[icon_data["mime_type"]]));

				try:
					main_icon_file = open(main_icon_filename, "wb");
				except IOError:
					main_icon_file = None;

				# Opened properly?
				if (main_icon_file is not None):
					main_icon_file.write(icon_data["data"]);
					main_icon_file.close();

					# Get info
					try:
						icon_info = ffprobe(main_icon_filename, ffprobe_exe=self.ffprobe_exe);
					except ExeNotFoundError:
						return ( "ffprobe-not-found" , None );

					# Find size
					main_icon_size = None;
					if ("streams" in icon_info):
						for stream in icon_info["streams"]:
							if (stream["codec_type"] == "video" and "width" in stream and "height" in stream):
								main_icon_size = ( stream["width"] , stream["height"] );
								break;

					if (main_icon_size is None):
						# Delete
						self.__delete_file(main_icon_filename);
					else:
						# Setup icon sizes
						re_icon_size = re.compile(r"^\s*([0-9]+)(?:\s*:(\w+))?\s*$", re.U);
						if ("icon-size" in cemd_values):
							icon_sizes = [];
							for icon_size in cemd_values["icon-size"]:
								match = re_icon_size.match(icon_size[1]);
								if (match is not None):
									size = int(match.group(1), 10);
									scaler = match.group(2);
									if (not scaler): scaler = "bilinear";
									else: scaler = scaler.lower();
									icon_sizes.append(( size , scaler ));
						else:
							icon_sizes = [ ( 16 , "bilinear" ) , ( 32 , "bilinear" ) , ( 48 , "bilinear" ) , ( 128 , "bilinear" ) ];

						# Create copies
						for icon_size in icon_sizes:
							if (icon_size[0] == main_icon_size[0] and icon_size[0] == main_icon_size[1]):
								# Already exists
								self.icon_filenames.append(( icon_size[0] , main_icon_filename ));
							else:
								# Create new
								icon_filename = os.path.join(self.directory_build, "icon{0:d}.png".format(icon_size[0]));

								try:
									created_okay = create_png(main_icon_filename, icon_filename, width=icon_size[0], height=icon_size[0], scaler=icon_size[1], ffmpeg_exe=self.ffmpeg_exe);
								except ExeNotFoundError:
									return ( "ffmpeg-not-found" , None );

								if (created_okay):
									# Add
									self.icon_filenames.append(( icon_size[0] , icon_filename ));

		# Done
		return None;

	# Create a manifest file
	def generate_manifest(self):
		if (self.icon_filenames is None or self.manifest_filename is not None):
			raise ExecutionOrderException();

		# Setup manifest
		manifest = {
			"name": None,
			"version": None,
			"manifest_version": 2,
			"description": None,
			"icons": {},
			"content_scripts": [{
				"js": [],
				"matches": [],
				"all_frames": True,
				"run_at": None,
			}],
			"permissions": []
		};

		usmd_values = self.userscript_metadata["map"]["UserScript"][0]["value_map"];
		cemd_values = self.userscript_metadata["map"]["ChromeExtension"][0]["value_map"];

		# Run at
		if ("run-at" in usmd_values and usmd_values["run-at"][0][1] == "document-start"):
			manifest["content_scripts"][0]["run_at"] = "document_start";
		else:
			manifest["content_scripts"][0]["run_at"] = "document_end";

		# Matches
		if ("match" in usmd_values):
			for match in usmd_values["match"]:
				manifest["content_scripts"][0]["matches"].append(match[1]);
		if ("include" in usmd_values):
			for match in usmd_values["include"]:
				manifest["content_scripts"][0]["matches"].append(match[1]);

		# Excludes
		if ("exclude" in usmd_values):
			manifest["content_scripts"][0]["exclude_matches"] = [];
			for match in usmd_values["exclude"]:
				manifest["content_scripts"][0]["exclude_matches"].append(match[1]);

		# Permissions
		if ("permission" in cemd_values):
			for permission in cemd_values["permission"]:
				manifest["permissions"].append(permission[1]);

		# Scripts
		for filename in self.javascript_filenames:
			path_relative = os.path.relpath(filename, self.directory_build);
			manifest["content_scripts"][0]["js"].append(path_relative);

		# Icons
		for icon in self.icon_filenames:
			path_relative = os.path.relpath(icon[1], self.directory_build);
			manifest["icons"][str(icon[0])] = path_relative;

		# Name/version/description
		single_map = {
			# "manifest_key": ( "usmd_values_key" , "default" )
			"name": ( "name" , "Userscript" ),
			"version": ( "version" , "1.0" ),
			"description": ( "description" , "" ),
		};
		for k,v in single_map.items():
			if (v[0] in usmd_values):
				manifest[k] = usmd_values[v[0]][0][1];
			else:
				manifest[k] = v[1];

		# Update url
		if ("update-url" in cemd_values):
			manifest["update_url"] = cemd_values["update-url"][0][1];

		# Write to file
		self.manifest_filename = os.path.join(self.directory_build, "manifest.json");

		try:
			manifest_file = open(self.manifest_filename, "wb");
		except IOError:
			return ( "error-writing-manifest" , None );

		manifest_file.write(py_2or3_str_to_bytes(json.dumps(manifest, indent=4, sort_keys=True, separators=(",", ": ")), "utf-8"));
		manifest_file.close();

		# Done
		return None;

	# Build the .crx file (create private key if allowed/necessary)
	def build_crx(self):
		if (self.manifest_filename is None):
			raise ExecutionOrderException();

		# Create private key
		if (not os.path.exists(self.input_private_key_filename)):
			if (not self.input_private_key_can_generate):
				return ( "private-key-not-found" , None );

			# Setup command
			cmd = [
				self.chrome_exe,
				"--pack-extension={0:s}".format(self.directory_build),
				"--no-message-box",
			];

			# Execute
			try:
				p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE);
			except OSError:
				return ( "chrome-not-found" , None );

			p.communicate();

			# Check for file
			pkey_filename = "{0:s}.pem".format(self.directory_build);
			if (not os.path.exists(pkey_filename)):
				return ( "private-key-creation-failure" , None );

			# Rename
			if (self.input_private_key_filename != pkey_filename and not self.__move_file(pkey_filename, self.input_private_key_filename)):
				self.__delete_file(pkey_filename);
				return ( "private-key-rename-failure" , None );

		# Create chrome extension
		cmd = [
			self.chrome_exe,
			"--pack-extension={0:s}".format(self.directory_build),
			"--pack-extension-key={0:s}".format(self.input_private_key_filename),
			"--no-message-box",
		];

		# Execute
		try:
			p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE);
		except OSError:
			return ( "chrome-not-found" , None );
		p.communicate();

		# Return code
		if (p.returncode != 0):
			return ( "crx-creation-failure" , "Code: {0:s}".format(str(p.returncode)) );

		# Check for file
		crx_filename = "{0:s}.crx".format(self.directory_build);
		if (not os.path.exists(crx_filename)):
			return ( "crx-creation-failure" , None );

		# Rename
		if (self.output_crx_filename != crx_filename and not self.__move_file(crx_filename, self.output_crx_filename)):
			self.__delete_file(crx_filename);
			return ( "crx-rename-failure" , None );

		# Done
		return None;

	# Build the .crx update .xml file
	def build_crx_update_xml(self, output_crx_update_filename):
		if (output_crx_update_filename is None):
			raise self.ArgumentException("output_crx_update_filename cannot be None");
		if (self.manifest_filename is None):
			raise ExecutionOrderException();

		# Find update url and version
		usmd_values = self.userscript_metadata["map"]["UserScript"][0]["value_map"];
		cemd_values = self.userscript_metadata["map"]["ChromeExtension"][0]["value_map"];
		if ("download-url" not in cemd_values):
			# Nothing to do; no @download-url specified in ChromeExtension metadata
			return None;
		download_url = cemd_values["download-url"][0][1];

		if ("version" in usmd_values):
			version = usmd_values["version"][0][1];
		else:
			version = "1.0";

		# Open extension
		try:
			input_file_crx = open(self.output_crx_filename, "rb");
		except IOError as e:
			return ( "crx-read" , None );

		# Get key
		public_key = self.get_crx_public_key(input_file_crx);
		if (public_key is None):
			return ( "crx-bad-format" , None );
		appid = self.get_crx_appid_from_public_key(public_key);



		# Write
		try:
			update_file = open(output_crx_update_filename, "wb");
		except IOError:
			return ( "error-writing-update-file" , None );


		xml_source = "\n".join([
			'<?xml version="1.0" encoding="UTF-8"?>',
			'<gupdate xmlns="http://www.google.com/update2/response" protocol="2.0">',
			'\t<app appid="{0:s}">'.format(appid),
			'\t\t<updatecheck codebase="{0:s}" version="{1:s}" />'.format(download_url, version),
			'\t</app>',
			'</gupdate>',
		]);
		update_file.write(xml_source.encode("utf-8"));
		update_file.close();


		# Done
		return None;

	# Clean
	def cleanup(self):
		# Nullify
		self.input_userscript_filename = None;
		self.input_private_key_filename = None;
		self.input_private_key_can_generate = False;
		self.output_crx_filename = None;

		self.userscript_metadata = None;

		if (self.javascript_filenames is not None):
			for file in self.javascript_filenames:
				self.__delete_file(file);
			self.javascript_filenames = None;

		if (self.resource_filenames is not None):
			for file in self.resource_filenames:
				self.__delete_file(file);
			self.resource_filenames = None;

		if (self.icon_filenames is not None):
			for file in self.icon_filenames:
				self.__delete_file(file[1]);
			self.icon_filenames = None;

		if (self.manifest_filename is not None):
			self.__delete_file(self.manifest_filename);
			self.manifest_filename = None;

		if (self.directory_build is not None):
			self.__delete_empty_directory(self.directory_build);
			self.directory_build = None;





# Usage info
def usage(arguments_descriptor, stream):
	usage_info = [
		"Usage:",
		"    {0:s} <arguments>".format(os.path.split(sys.argv[0])[1]),
		"\n",
		"Available flags:",
	];

	# Flags
	argument_keys = sorted(arguments_descriptor.keys());

	for i in range(len(argument_keys)):
		key = argument_keys[i];
		arg = arguments_descriptor[key];
		param_name = "";
		if (not ("bool" in arg and arg["bool"])):
			if ("argument" in arg):
				param_name = " <{0:s}>".format(arg["argument"]);
			else:
				param_name = " <value>";

		if (i > 0):
			usage_info.append("");

		if ("long" in arg):
			for a in arg["long"]:
				usage_info.append("  --{0:s}{1:s}".format(a, param_name));

		if ("short" in arg):
			usage_info.append("  {0:s}".format(", ".join([ "-{0:s}{1:s}".format(a, param_name) for a in arg["short"] ])));

		if ("description" in arg):
			usage_info.append("    {0:s}".format(arg["description"]));

	# More info
	usage_info.extend([
		"\n",
		"Formattable error messages:",
		"    Custom formattable error_str's can use basic escape sequences such as:",
		r"    \\ \" \' \a \b \f \n \r \t \xHH \uHHHH ",
	]);

	# Output
	stream.write("{0:s}\n".format("\n".join(usage_info)));



# Main
def main():
	# Command line argument settings
	arguments_descriptor = {
		"version": {
			"short": [ "v" ],
			"long": [ "version" ],
			"bool": True,
			"description": "Show version info and exit",
		},
		"help": {
			"short": [ "h" , "?" ],
			"long": [ "help" , "usage" ],
			"bool": True,
			"description": "Show usage info and exit",
		},
		"chrome": {
			"short": [ "c" ],
			"long": [ "chrome" ],
			"argument": "exe_path",
			"description": "Set the chrome.exe file path",
		},
		"ffmpeg": {
			"short": [ "f" ],
			"long": [ "ffmpeg" ],
			"argument": "exe_path",
			"description": "Set the ffmpeg.exe file path",
		},
		"ffprobe": {
			"short": [ "p" ],
			"long": [ "ffprobe" ],
			"argument": "exe_path",
			"description": "Set the ffprobe.exe file path",
		},
		"chrome-not-found-error": {
			"long": [ "chrome-not-found-error" ],
			"argument": "error_str",
			"description": "Custom formattable error to display if chrome.exe is not found",
		},
		"ffmpeg-not-found-error": {
			"long": [ "ffmpeg-not-found-error" ],
			"argument": "error_str",
			"description": "Custom formattable error to display if ffmpeg.exe is not found",
		},
		"ffprobe-not-found-error": {
			"long": [ "ffprobe-not-found-error" ],
			"argument": "error_str",
			"description": "Custom formattable error to display if ffprobe.exe is not found",
		},
		"private-key": {
			"short": [ "k" ],
			"long": [ "private-key" ],
			"argument": "path",
			"description": "Set the name of the private key (.pem) file used",
		},
		"private-key-generate-if-missing": {
			"long": [ "private-key-generate-if-missing" ],
			"bool": True,
			"description": "Enable to allow new private keys to be generated if it was missing",
		},
		"userscript": {
			"short": [ "u" ],
			"long": [ "userscript" ],
			"argument": "path",
			"description": "The main .user.js script file",
		},
		"crx": {
			"short": [ "x" ],
			"long": [ "crx" ],
			"argument": "path",
			"description": "The output path for the .crx extension file",
		},
		"crx-update-file": {
			"long": [ "crx-update-file" ],
			"argument": "path",
			"description": "The output path for the .xml update descriptor",
		},
		"no-cleanup": {
			"long": [ "no-cleanup" ],
			"bool": True,
			"description": "Disable file deleteion cleanup at the end (useful for testing)",
		},
	};
	arguments, errors = arguments_parse(sys.argv, 1, arguments_descriptor, return_level=1);



	# Command line parsing errors?
	if (len(errors) > 0):
		for e in errors:
			sys.stderr.write("{0:s}\n".format(e));
		sys.exit(-1);



	# Version
	if (arguments["version"]):
		sys.stdout.write("Version {0:s}".format(".".join([ str(v) for v in version_info ])));
		return 0;

	if (arguments["help"]):
		# Usage info
		usage(arguments_descriptor, sys.stdout);
		return 0;

	# Check for necessary values
	if (
		arguments["chrome"] is None or
		arguments["ffmpeg"] is None or
		arguments["ffprobe"] is None or
		arguments["private-key"] is None or
		arguments["userscript"] is None or
		arguments["crx"] is None
	):
		# Usage info
		usage(arguments_descriptor, sys.stderr);
		return -2;



	# Custom error mapping for CRXBuilder
	custom_error_argument_map = {
		"ffprobe-not-found": "ffprobe-not-found-error",
	};
	custom_error_modifier_map = {
		"private-key-not-found": "{0:s}\n  Add the command line flag --private-key-generate-if-missing to generate one",
	};



	# Create builder
	builder = CRXBuilder(arguments["chrome"], arguments["ffmpeg"], arguments["ffprobe"]);

	# Init files
	error = builder.setup(
		os.path.abspath(arguments["userscript"]),
		os.path.abspath(arguments["private-key"]),
		arguments["private-key-generate-if-missing"],
		os.path.abspath(arguments["crx"])
	);
	if (error is None):
		# Read metadata
		error = builder.read_metadata();
		if (error is None):
			# Generate icons
			error = builder.generate_icons();
			if (error is None):
				# Build manifest
				error = builder.generate_manifest();
				if (error is None):
					# Generate private key and .crx file
					error = builder.build_crx();
					if (error is None):
						# Generate update .xml
						update_file = arguments["crx-update-file"];
						if (update_file is not None):
							update_file = os.path.abspath(update_file);
							error = builder.build_crx_update_xml(update_file);



	# Clean
	if (not arguments["no-cleanup"]):
		builder.cleanup();

	# Error
	if (error is not None):
		# Custom message
		error_name = error[0];
		error_extra = error[1];
		if (error_name in custom_error_argument_map and arguments[custom_error_argument_map[error_name]] is not None):
			error_msg = escape_command_line_text(arguments[custom_error_argument_map[error_name]]).encode("utf-8", "ignore");
		else:
			error_msg = builder.error_messages[error_name];

		# Additional non-generic formatting
		if (error_name in custom_error_modifier_map):
			error_msg = custom_error_modifier_map[error_name].format(error_msg);

		# Output
		sys.stderr.write("{0:s}\n".format(error_msg));
		if (error_extra is not None):
			sys.stderr.write("{0:s}\n".format(error_extra));

		# Return
		return 1;



	# Done
	return 0;



# Execute
if (__name__ == "__main__"): sys.exit(main());

