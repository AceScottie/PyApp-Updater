import os, sys, threading, subprocess, shutil, tempfile, requests, configparser, traceback, hashlib, zlib
from tkinter import *
from tkinter.ttk import *
from urllib.request import urlopen
from win32api import GetFileVersionInfo, LOWORD, HIWORD
from acl import perms
from zipfile import ZipFile
from aceutil import Log
if os.name == 'nt':
    import win32api, win32con
    pass
if getattr(sys, 'frozen', False):
	exe_path = os.path.dirname(sys.executable)
elif __file__:
	exe_path = os.path.dirname(os.path.abspath(__file__))
	pass
class Updater:
	def __init__(self, cstate, base, tmp):
		self.cstate = cstate
		self.base = base
		self.log = Log("updater")
		self.tmp = tmp
		self.status_text = ""
		self.status_detail_text = ""
		self.pro = 0
		self.download=False
		self.copies = []
		self.zipping = False
		self.full = False
		self.beta_opt = False

	def update_root(self):
		self.root.update()
		self.root.update_idletasks()

	#====
	#Section for downloading, unzipping update and comparing hash.
	def download_update(self, url, fname):
		try:
			with open(self.tmp+"\\"+fname, 'wb') as f:
				response = requests.get(url, stream=True)
				total = response.headers.get('content-length')
				if total is None:
					f.write(response.content)
				else:
					downloaded = 0
					total = int(total)
					for data in response.iter_content(chunk_size=max(int(total/1000), 1024*1024)):
						downloaded += len(data)
						f.write(data)
						done = int(50*downloaded/total)
						self.pro=10+done
			self.download = True
		except Exception as err:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			self.log.error("download_update failed\n%s, %s, %s, %s" %(err, exc_type, exc_obj, traceback.print_tb(exc_tb)))
	def unzipt(self):
		try:
			with ZipFile(self.tmpdir+"\\"+self.latestversion+".zip", 'r') as zipObj:
				zipObj.extractall(self.tmpdir+"\\"+self.latestversion)
			self.zipping=False
		except Exception as err:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			self.log.error("unzipt failed\n%s, %s, %s, %s" %(err, exc_type, exc_obj, traceback.print_tb(exc_tb)))
	def start_install_update(self):
		try:
			self.download = False
			self.update_status("Download Completed, Applying Update\nPlease Wait.")
			self.pro = 30
			t = threading.Thread(target=self.unzipt)
			self.zipping = True
			t.start()
			while self.zipping:
				self.update_root()
			self.compare_existing_hash()
		except Exception as err:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			self.log.error("install_update failed\n%s, %s, %s, %s" %(err, exc_type, exc_obj, traceback.print_tb(exc_tb)))
	#===


	#===
	#Section for Compare existing files to ensure they are all as expected.
	def compare_existing_hash(self, sums, main=True):
		if main:
			base=self.base
		else:
			base=self.tmp
		for path, key in sums.items():
			if path != "":
				self.status_detail.configure(text="Checking %s integraty" %path)
				self.update_root()
				sums[paht][1] = test_sha256(path, key[0])
		for path, key in sums:
			if key[1] == False:
				self.status_detail.configure(text="%s failed integraty check, reverting to previous master build.")
				self.update_root()
				self.full = True
	def unlock_sha_file(self, version):
		with open(self.base+"%s.sha256"%version, "r+") as f:
			l = f.read().split("\n")
		sums = {}
		for row in l:
			if row != "":
				sums[row.split(",")[0]] = [row.split(",")[1], False]
		return sums
	def unlock_data_file(self):
		with open(self.tmp+"data.dat", "rb") as f:
			x = f.read()
		l = zlib.decompress(x).decode()
		sums = {}
		for row in l.split("\r\n"):
			if row != "":
				sums[row.split(",")[0]] = [row.split(",")[1], False]
		return sums
	def hash_bytestr_iter(self, bytesiter, hasher, ashexstr=False):
		for block in bytesiter:
			hasher.update(block)
		return hasher.hexdigest() if ashexstr else hasher.digest()
	def file_as_blockiter(afile, blocksize=65536):
		with afile:
			block = afile.read(blocksize)
			while len(block) > 0:
				yield block
				block = afile.read(blocksize)
	def test_sha256(self, path, sumed):
		base = "C:\\Program Files (x86)\\Patient System\\"
		sha = base64.b64encode(self.hash_bytestr_iter(self.file_as_blockiter(open(base+path, 'rb')), hashlib.sha256())).decode()
		return sha == sumed


	def start_updating(self, version):
		try:
			self.update_status("Starting Update Process.\nPlease Wait")
			try:
				perms(self.log, self.path, ["Users", "Everyone"]).check_perm()
			except:
				self.log.log("Could not set Permissions, This requires Administator Privilages")
			self.pro=10
			dl = "%s/%s.zip" %(self.url, version)
			t = threading.Thread(target=self.download_update,args=(dl, version+".zip"))
			t.start()
		except Exception as err:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			self.log.error("start_updating failed\n%s, %s, %s, %s" %(err, exc_type, exc_obj, traceback.print_tb(exc_tb)))
			self.update_status("This Application Requires to be run as Administator, or have Permission Granted.\nPlease Speak to your Administator.")
			self.pro=0
	


	def get_version_number(self, filename):
		try:
			info = GetFileVersionInfo (filename, "\\")
			ms = info['FileVersionMS']
			ls = info['FileVersionLS']
			return str(HIWORD (ms))+"."+str(LOWORD (ms))+"."+str(HIWORD (ls))+"."+str(LOWORD (ls))
		except Exception as err:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			self.log.error("get_version_number failed\n%s, %s, %s, %s" %(err, exc_type, exc_obj, traceback.print_tb(exc_tb)))
			return ["0", "0", "0", "0"]
	def get_versions(self, filename):
		respose = urlopen("https://octopusepr.com/updates.php")
		charset = respose.info().get_content_charset()
		versions = json.loads(respose.read().decode(charset))
		versions['current'] = self.get_version_number(filename)
		return versions
	def version_to_int(self, version):
		v = v.split(".")
		for i in len(v):
			v[i] = int(v[i])
		return v
	def compare_version(self, versions):
		current = self.version_to_int(versions['current'])
		main = self.version_to_int(versions['main'])
		patch = self.version_to_int(versions['patch'])
		beta = self.version_to_int(versions['beta'])
		update_required = False
		if not self.opt_beta: # if opted into beta
			for i in range(4):
				if current[3-i] < beta[3-i]:
					update_required = True
		elif not self.full: #if patch update is required anyway.
			for i in range(4):
				if current[3-i] < patch[3-i]:
					update_required = True
		else: #full update is required
			for i in range(4):
				if current[3-i] < main[3-i]:
					update_required = True
		if update_required: #if update is required and current patch level is lower than last major release, update to major release and patch from there.
			for i in range(4):
				if current[3-i] < main[3-i]:
					self.full = True
		return update_required

	##===
	#Section for UI elements
	def update_status(self):
		try:
			self.status.configure(text=self.status_text)
			self.progress['value'] = self.pro
			self.status_detail.configure(text=self.status_detail_text)
			self.root.after(100, self.update_status)
		except Exception as err:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			self.log.error("update_status failed\n%s, %s, %s, %s" %(err, exc_type, exc_obj, traceback.print_tb(exc_tb)))

	def UI(self):
		try:
			self.log.log("Application Starting")
			self.root = Tk()
			self.root.iconbitmap(exe_path+'\\Updater.ico')
			self.root.title("Updater")
			self.root.protocol("WM_DELETE_WINDOW", self.quitting)
			ws = self.root.winfo_screenwidth() # width of the screen
			hs = self.root.winfo_screenheight() # height of the screen
			x = (ws/2)-(300/2)
			y = (hs/2)-(50/2)
			self.root.geometry("300x50+%s+%s" %(int(x), int(y)))
			self.root.attributes("-topmost", True)
			self.root.attributes("-topmost", False)
			
			self.status = Label(self.root, text="Checking for Updates\n")
			self.status.pack(side=TOP, fill=X, expand=1)
			self.progress=Progressbar(self.root, orient=HORIZONTAL,length=100,mode='determinate')
			self.progress.pack(fill=X, expand=1)
			self.status_detail = Label(self.root, text="")
			self.status.pack(side=TOP, fill=X, expand=1)
			self.status_detail.pack(side=TOP, fill=X, expand=1)
			self.root.after(100, self.update_status)
			self.root.mainloop()
		except Exception as err:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			self.log.error("UI failed\n%s, %s, %s, %s" %(err, exc_type, exc_obj, traceback.print_tb(exc_tb)))
	#====
	def quitting(self):
		self.root.quit()
		self.root.destroy()
if __name__ == "__main__":
	base = ""
	tmp = ""
	if len(sys.argv) > 1:
		continue_state = sys.argv[1]
		if continue_state == "init":
			base = sys.argv[2]
			tmp = sys.argv[3]
	else:
		continue_state = None
	u = Updater(continue_state, base, tmp)
	u.UI()