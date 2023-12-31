import traceback
import socket
import sys
import time
import os
import unicodedata


def no():  # fix for cButton function, used as a default command
    pass


class Error(Exception):
    pass


class utils():
    def __init__(self):
        import time
        self.varstore = {}
        self.textlen = 0

    def writelines(self, text):  # print over same line
        self.text = text
        sys.stdout.write('\r' + ' ' * self.textlen + '\r')
        sys.stdout.flush()
        sys.stdout.write('\r' + str(self.text) + '\r')
        sys.stdout.flush()
        self.textlen = len(text)

    def sleeper(self, interval):  # sleep in miliseconds
        interval = interval/1000
        time.sleep(interval)

    def var_store(self, text="", key=""):
        if ley != "":
            if text != "":
                self.varstore[key] = text
            else:
                return self.varstore[key]

    def pad(self, input, length):
        x = "".join("0" for _ in range(length-len(str(input))))
        x += str(input)
        return x

    def help(self):
        return """
        writelines(text): wrights the text string to the stdout and then flushes the line, overwrights line each time.
        sleeper(interval): same as time.sleep(interval) but uses interval in miliseconds rather than seconds.
        var_store(text, key): stores the text string as a instanced variable. Stores multiple using unique key.
        pad(input, length): adds leading 0s to input untill input meets lenght
        """

    def remove_control_characters(self, s):
        return "".join(ch for ch in s if unicodedata.category(ch)[0] != "C")


class serialHandler():
    def __init__(self, ser="", timeout=1, baudrate=9600):
        import serial
        if ser == "" or not isinstance(ser, basestring):
            raise Error(
                "Exception: 'serialHandler(address)'. please include the serial port address as a string")
        self.ser = serial.Serial(ser, baudrate=9600, bytesize=8, parity='N',
                                 stopbits=1, timeout=timeout, xonxoff=False, rtscts=False, dsrdtr=False)
        print("created serial port with options p:%s b:%s t:%s" %
              (ser, str(baudrate), str(timeout)))

    def read(self):
        count = 0
        msg = ""
        tries = 4
        while len(msg) < 1:
            msg = self.ser.readline()
            count += 1
            if count >= tries:
                return "Error reading from serial"
        return msg

    def write(self, text):  # sourcery skip: remove-unnecessary-else
        if text == "" or not isinstance(text, basestring):
            raise Error("Exception: 'serialHandler.write(text)'. text must be a valid string")
        else:
            self.ser.write(text)
            self.ser.flush()

    def close(self):
        self.ser.close()

    def help():
        return """
        init(serial): uses serial string to create an instanced serial connection using default values. serial string is the port.
        'baudrate=9600, bytesize=8, parity='N', stopbits=1, timeout=1, xonxoff=False, rtscts=False, dsrdtr=False'
        read(): reads data from the serial. if there is no data will retry untill there is data or it has tried 1000 times. returs string of the data.
        write(text): wrights data to the instanced serial connection.
        """


class TkUtils:
    def __init__(self, root: object) -> object:
        try:
            import Tkinter
            self.TkUtil = Tkinter
        except Exception as err:
            import tkinter
            self.TkUtil = tkinter
        import threading
        import time
        import traceback
        self.traceback = traceback
        self.time = time
        self.threading = threading
        self.root = root
        self.active_window = None
        self.active_side = None
        self.active_scroll = None
        self.run = False
        self.moving = False
        self.att = 0

    def cButton(self, element, borderwidth=1, width=0, height=0, fg="black", bg="white", text="", relief="raised", padx=0, pady=0, command=no(), side=None, expand=0, fill=None, state="normal", anchor="nsew", cursor=None, font=None, image=None, justify=None, compound=None):  # basic button
        if state != "normal":
            cursor = "arrow"
        elif state == "disabled":
            cursor = "tcross"
        if cursor == None:
            cursor = "hand2"
        b = self.TkUtil.Button(element, borderwidth=borderwidth, width=width, height=height, fg=fg, bg=bg, text=text, padx=padx, pady=pady, relief=relief, command=command, state=state, cursor=cursor, font=font, image=image, justify=justify, compound=compound)
        b.pack(side=side, expand=expand, fill=fill)
        return b
    def cFrame(self, element, bg="white", borderwidth=0, relief="groove", side=None, padx=0, pady=0, height=0, width=0, expand=0, fill=None, image=None, highlightbackground=None, highlightcolor=None, highlightthickness=0, ipadx=0, ipady=0):
        f = self.TkUtil.Frame(element, bg=bg, borderwidth=borderwidth, relief=relief, height=height, width=width, image=image, highlightbackground=highlightbackground, highlightcolor=highlightcolor, highlightthickness=highlightthickness)
        f.pack(side=side, padx=padx, pady=pady, ipadx=ipadx, ipady=ipady, expand=expand, fill=fill)
        return f
    def create_overlay(self, over, event, title, height=400, width=400):
        if self.active_window is not None:
            self.clear_overlay(self.TkUtil.Event())
            self.create_overlay(over, event, title, height, width)
        else:
            try:
                rootx = self.root.winfo_width()
                rooty = self.root.winfo_height()
            except Exception as err:
                rootx = 200
                rooty = 150
            window = self.TkUtil.Canvas(over, width=width, height=height, bg="white", relief="groove",
                                        highlightbackground="black", highlightcolor="black", highlightthickness=1, borderwidth=4)
            self.active_window = window
            window.pack_propagate(False)
            window.place(x=rootx/2-(width/2), y=(rooty/2)-(height/4))
            self.root.update_idletasks()
            self.root.update()
            spacer = self.cFrame(window, padx=7, pady=7, fill=self.TkUtil.BOTH)
            Title = self.TkUtil.Label(spacer, text=title, justify=self.TkUtil.RIGHT, font=("Helvetica", 10), bg="#EEEEEE", padx=10, pady=5, cursor="fleur")
            Title.pack(side=self.TkUtil.LEFT, expand=1, fill=self.TkUtil.X)
            Title.bind("<B1-Motion>", lambda e=event, w=window: self.move_window_thread(w, e))
            close = self.cButton(spacer, text="X", relief="raised", borderwidth=1, fg="black", side=self.TkUtil.RIGHT, command=lambda e=self.TkUtil.Event(): self.clear_overlay(e))
            spacer = self.cFrame(window, side=self.TkUtil.BOTTOM, pady=3)
            self.set_pos(window)
            return "break"
    def clear_overlay(self, event): 
        if self.active_window != None:
            if self.active_window.winfo_exists():
                for child in self.active_window.winfo_children():
                    child.unbind('<Configure>')
                    child.pack_forget()
                    child.destroy()
            self.active_window.destroy()
            self.active_window = None
        return "break"
    def overlay(self, over, event, title, height=400, width=400):
        if self.active_window != None:
            self.clear_overlay(self.TkUtil.Event())
        self.create_overlay(over, event, title, width=width, height=height)
        return self.active_window
    def move_window(self, event, window, run):
        self.run = run
        if self.run:
            t = self.threading.Thread(target=self.move_window_thread, args=(window, event))
            print("starting thread move_window_thread")
            print(t.name)
            t.start()
    def move_window_thread(self, window, event):
        if not self.moving:
            self.moving = True
            self.root.update_idletasks()
            self.root.update()
            if(self.root.winfo_pointerx() != "??" and self.root.winfo_pointery() != "??"):
                window.place(x=(self.root.winfo_pointerx() - self.root.winfo_rootx()) - window.winfo_width()/2, y=self.root.winfo_pointery() - self.root.winfo_rooty()-10)
            self.moving = False
    def set_pos(self, window):
        try:
            rootx = self.root.winfo_width()
            rooty = self.root.winfo_height()
            wx = window.winfo_width()
            wy = window.winfo_height()
        except Exception as err:
            rootx = 200
            rooty = 150
            wx = 400
            wy = 400
        window.place(x=(rootx/2)-(wx/2), y=(rooty/2)-(wy/2))
    def scrollable_area2(self, holder):
        base_frame = self.cFrame(holder, fill=self.TkUtil.BOTH, expand=1, padx=5, pady=5)
        base_frame.rowconfigure(0, weight=0)
        base_frame.columnconfigure(0, weight=1)
        can = self.TkUtil.Canvas(base_frame, bg="white")
        can.pack(side=self.TkUtil.LEFT, expand=1, fill=self.TkUtil.BOTH)
        scrollArea = self.cFrame(base_frame, bg="white", side=self.TkUtil.LEFT, expand=1, fill=self.TkUtil.BOTH)
        can.create_window(0, 0, window=scrollArea, anchor='nw')
        Scroll = self.TkUtil.Scrollbar(base_frame, orient=self.TkUtil.VERTICAL)
        Scroll.config(command=can.yview)
        Scroll.pack(side=self.TkUtil.RIGHT, fill=self.TkUtil.Y)
        can.config(yscrollcommand=Scroll.set)
        scrollArea.bind("<Configure>", lambda e=self.TkUtil.Event(), c=can: self.update_scrollregion(e, c))
        base_frame.bind("<Enter>", lambda e=self.TkUtil.Event(): self.set_active(e, can))
        base_frame.bind("<Leave>", lambda e=self.TkUtil.Event(): self.unset_active(e))
        return scrollArea, can
    def h_scrollable_area(self, holder):
        base_frame = self.cFrame(holder, fill=self.TkUtil.BOTH, expand=1, padx=5, pady=5)
        base_frame.rowconfigure(0, weight=0)
        base_frame.columnconfigure(0, weight=1)
        can = self.TkUtil.Canvas(base_frame, bg="white")
        can.pack(side=self.TkUtil.TOP, expand=1, fill=self.TkUtil.BOTH)
        scrollArea = self.cFrame(base_frame, bg="white", side=self.TkUtil.TOP, expand=1, fill=self.TkUtil.BOTH)
        can.create_window(0, 0, window=scrollArea, anchor='nw')
        Scroll = self.TkUtil.Scrollbar(base_frame, orient=self.TkUtil.HORIZONTAL)
        Scroll.config(command=can.xview)
        Scroll.pack(side=self.TkUtil.BOTTOM, fill=self.TkUtil.X)
        can.config(xscrollcommand=Scroll.set)
        scrollArea.bind("<Configure>", lambda e=self.TkUtil.Event(), c=can: self.update_scrollregion(e, c))
        return scrollArea, can
    def set_active(self, event, canvas):
        self.active_scroll = canvas
    def unset_active(self, event):
        self.active_scroll = None
    def reset_scroll(self, element):
        self.root.nametowidget(element.winfo_parent()).yview_moveto(0)
        self.root.nametowidget(element.winfo_parent()).yview_scroll(0, "units")
    def _on_mousescroll(self, event):
        if self.active_scroll != None:
            self.active_scroll.yview_scroll(-1*(event.delta/120), "units")
            self.active_scroll.update()
            self.root.update()
    def update_scrollregion(self, event, can):
        if can.winfo_exists():
            can.configure(scrollregion=can.bbox("all"))
    def OnCanvasConfigure(self, event, can, scroll):
        canvas_width = event.width
        can.itemconfig(scroll, width=canvas_width)
    def test_buttons(self, main, defaultIcon):
        self.root.update_idletasks()
        self.root.update()
        for i in range(20):
            Packer, state = self.cFrame(main, bg="white", borderwidth=2, width=400, relief=self.TkUtil.RAISED, fill=self.TkUtil.X, expand=1)
            L = self.TkUtil.Label(Packer, anchor=self.TkUtil.W, justify=self.TkUtil.LEFT, text="Test %s" % i, bg="red", borderwidth=0)
            L.pack(side=self.TkUtil.LEFT, fill=self.TkUtil.X)
            L2 = self.TkUtil.Label(Packer, anchor=self.TkUtil.W, image=defaultIcon)
            L2.pack(side=self.TkUtil.RIGHT)


class Socket_Log():
    def __init__(self, port):
        self.port = port
        self.sock = None
        self.quit = False
        self.create_socket()

    def set_name(self, name):
        try:
            self.sock.sendall(str("Name%s" % name).encode('utf-8'))
            time.sleep(0.01)
        except:
            self.create_socket(f="name", l=name)

    def manual_error(self):
        try:
            strtime = str(time.strftime("%d-%m-%Y,(%z),%H:%M:%S"))
            self.sock.sendall(
                str("Error: %s, User has generated a manual Error" % (strtime)).encode('utf-8'))
            time.sleep(0.01)
        except:
            self.create_socket(f="man")

    def tester(self):
        try:
            self.sock.sendall(b'Error while quitting')
            time.sleep(0.01)
        except:
            self.create_socket()

    def log(self, log):
        try:
            strtime = str(time.strftime("%d-%m-%Y,(%z),%H:%M:%S"))
            #print("sending data")
            #print(str("log: %s, %s\r" %(strtime, log)).encode('utf-8'))
            self.sock.sendall(str("Log: %s, %s" %
                              (strtime, log)).encode('utf-8'))
            time.sleep(0.01)
        except:
            self.create_socket(f="log", l=log)

    def error(self, error):
        try:
            print("Error Detected")
            exc_type, exc_obj, exc_tb = sys.exc_info()
            trace_stack = traceback.extract_tb(exc_tb)[-1]
            trace_format = "\r\n\r\nError in file "+str(trace_stack[0])+"\r		on line "+str(
                trace_stack[1])+", from module '"+str(trace_stack[2])+"'\r		"+str(trace_stack[3])
            strtime = str(time.strftime("%d-%m-%Y,(%z),%H:%M:%S"))
            self.sock.sendall(str("Error: %s, %s, %s" %
                              (strtime, error, trace_format)).encode('utf-8'))
            time.sleep(0.01)
        except:
            self.create_socket(f="err", l=error)

    def gen_log(self, func, err, exc_type, exc_obj, exc_tb):
        print("%s failed\n%s, %s, %s, %s" % (func, err, exc_type,
              exc_obj, ''.join(traceback.format_tb(exc_tb))))
        self.error("%s failed\n%s, %s, %s, %s" % (
            func, err, exc_type, exc_obj, ''.join(traceback.format_tb(exc_tb))))

    def create_socket(self, f=None, l=None):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((socket.gethostname(), self.port))
            if f == "err":
                self.error(l)
            elif f == "log":
                self.log(l)
            elif f == "man":
                self.manual_error()
            elif f == "name":
                self.set_name(name)
        except:
            if not self.quit:
                self.create_socket()

    def quitter(self):
        self.sock.sendall(b'exit')
        time.sleep(0.01)
        self.quit = True


class Log:  # class to write to log file with time stamps
    def __init__(self, appname):
        import os
        import traceback
        import time
        self.traceback = traceback
        self.os = os
        self.time = time
        if getattr(sys, 'frozen', False):  # windows path fix
            self.exe = self.os.path.dirname(sys.executable)
        elif __file__:
            self.exe = self.os.path.dirname(__file__)
        if not os.path.exists(os.path.dirname(str(os.environ['USERPROFILE'])+"\\Documents\\%s\\" % appname)):
            os.makedirs(str(os.environ['USERPROFILE']) +
                        "\\Documents\\%s\\" % appname)
        self.fname = str(os.environ['USERPROFILE']) + \
            "\\Documents\\%s\\debug.log" % appname
        self.logfile = None

    def error(self, error):
        exc_type, exc_obj, exc_tb = sys.exc_info()
        trace_stack = self.traceback.extract_tb(exc_tb)[-1]
        trace_format = "Error in file "+str(trace_stack[0])+"\r		on line "+str(
            trace_stack[1])+", from module '"+str(trace_stack[2])+"'\r		"+str(trace_stack[3])
        try:
            self.logfile = open(self.fname, "a+")
        except:
            self.logfile = open(self.fname, "w+")
        strtime = str(self.time.strftime("%d-%m-%Y,(%z),%H:%M:%S"))
        self.logfile.write("error: %s, %s, %s\r" %
                           (strtime, error, trace_format))
        self.logfile.close()
        self.logfile = None

    def log(self, log):
        try:
            self.logfile = open(self.fname, "a+")
        except:
            self.logfile = open(self.fname, "w+")
        strtime = str(self.time.strftime("%d-%m-%Y,(%z),%H:%M:%S"))
        self.logfile.write("log: %s, %s\r" % (strtime, log))
        self.logfile.close()
        self.logfile = None


class Log_Linux:  # class to write to log file with time stamps
    def __init__(self, appname):
        import os
        import traceback
        import time
        self.traceback = traceback
        self.os = os
        self.time = time
        if getattr(sys, 'frozen', False):  # windows path fix
            self.exe = self.os.path.dirname(sys.executable)
        elif __file__:
            self.exe = self.os.path.dirname(__file__)
        if not os.path.exists(os.path.dirname("~/%s/" % appname)):
            os.makedirs(os.path.dirname("~/%s/" % appname))
        self.fname = "~/%s/debug.log" % appname
        self.logfile = None

    def error(self, error):
        exc_type, exc_obj, exc_tb = sys.exc_info()
        trace_stack = self.traceback.extract_tb(exc_tb)[-1]
        trace_format = "Error in file "+str(trace_stack[0])+"\r		on line "+str(
            trace_stack[1])+", from module '"+str(trace_stack[2])+"'\r		"+str(trace_stack[3])
        try:
            self.logfile = open(self.fname, "a+")
        except:
            self.logfile = open(self.fname, "w+")
        strtime = str(self.time.strftime("%d-%m-%Y,(%z),%H:%M:%S"))
        self.logfile.write("error: %s, %s, %s\r" %
                           (strtime, error, trace_format))
        self.logfile.close()
        self.logfile = None

    def log(self, log):
        try:
            self.logfile = open(self.fname, "a+")
        except:
            self.logfile = open(self.fname, "w+")
        strtime = str(self.time.strftime("%d-%m-%Y,(%z),%H:%M:%S"))
        self.logfile.write("log: %s, %s\r" % (strtime, log))
        self.logfile.close()
        self.logfile = None


class passwd:
    def __init__(self):
        import traceback
        self.charset = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T",
                        "U", "V", "W", "X", "Y", "Z", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", " ", "!", '"', "#", "$", "%", "&", "'", "(", ")", "*", "+", ",", "-", ".", "/", ":", ";", "<", "=", ">", "?", "@", "[", "\\", "]", "^", "_", "`", "{", "|", "}", "~"]
        self.passwd = ""
        self.traceback = traceback

    def get_next_char(self, letter):
        if len(letter) > 1 or len(letter) < 1:
            raise Error(
                "Exception: 'get_next_char(string)' string expects lenght of 1. example 'next = get_next_char('a')'.")
        accepted = any(letter == i for i in self.charset)
        if not accepted:
            raise Error(
                "Exception: 'get_next_char(string)', the character %s is not in the standard character set" % letter)
        if letter == "~":
            return "a"
        for i in range(len(self.charset)):
            if letter == self.charset[i]:
                return self.charset[i+1]

    def get_passwd(self, passwd=""):
        pwd = self.passwd
        if passwd == "":
            mod = False
            arr = [i for i in pwd]
            pwdsize = len(pwd)-1
            for i in range(pwdsize):
                if arr[pwdsize-i] == "~":
                    arr[pwdsize-(i+1)] = self.get_next_char(arr[pwdsize-(i+1)])
                    arr[pwdsize-i] = "a"
                elif not mod:
                    arr[-1] = self.get_next_char(arr[-1])
                    mod = True
            for i in arr:
                passwd += i
            if passwd != self.passwd:
                self.passwd = passwd
            return self.passwd
        else:
            self.passwd = passwd

    def check_passwd(self):
        return self.passwd

    def create_passwd(self, key1, key2):  # second level encryption
        # sourcery skip: aug-assign, extract-method, move-assign
        try:
            key = key1+key2
            x = [None] * 64
            for i in range(len(key)):
                x[i] = int((ord(key[i]) - 32) ** 2)
            n1 = int(((x[20] * (x[7] + x[15])) * x[10])**6)
            n2 = int((x[3] % (x[28] * x[19])) / (x[6]+1))
            n3 = int((((x[21] ** 7) / (x[23]+1)) ** 4)+(x[29] % x[32]))
            n4 = ((x[16] * x[6] / (x[14]+1) * x[25])**3)
            n5 = int(((x[12] * x[31] + x[2])**7) - x[18])
            n6 = int((x[11] * (x[26]+x[8]) * x[24]) ** 13)
            n7 = int(((x[22] / (x[27]+1)+65565)**2)/(x[9]+1)+(((x[17]) ** 4)))
            n8 = int((((n7+x[1]) / (x[5]+1)) - (x[13] ** 21)) * x[33])
            n9 = int((x[34] * (x[48] + x[39]) * x[40])**6)
            n10 = int(x[42] % (x[28]*x[54]) / (x[41]+1))
            n11 = int(((((x[59]) ** 7) / (x[53]+1)) ** 4)+(x[63] % x[46]))
            n12 = int(((x[58]*x[47]/(x[61]+1)*x[60]) ** 3))
            n13 = int(((x[52] * x[37] + x[55]) ** 7) - x[63])
            n14 = int((((x[49] * x[36])+x[56]) * x[62]) ** 13)
            n15 = int(((x[38] / (x[35]+1)+65565) ** 2) /
                      (x[44]+1)+(((x[49]) ** 4)))
            n16 = int((((n7+x[43]) / (x[50]+1)) - (x[51] ** 21)) * x[45])
            final_int_1 = int(((n1+n2+1)/(n3+n4+1))+((n5/(n6+n7+1))+n8))
            final_int_2 = int(((n9+n10+1)/(n11+n12+1))+((n13/(n14+n15+1))+n16))
            final_int = int(final_int_1+final_int_2)
            if (final_int < 0):  # final_int < 0
                final_int = 0 - final_int
            i = 2
            small = 1000000000000000000000000000000000000000000000000000000000000000
            big = 9999999999999999999999999999999999999999999999999999999999999999
            while (final_int < small):  # final_int < small
                final_int = final_int**i
                i += 1
            test = final_int % small
            if (test < small):  # test < small
                final_int = int(big - test)
            final_string = str(final_int)
            rtn_str = final_string
            print(final_string)
            result = ""
            while (len(result) <= 31):
                result += self.conv_toStr(int(final_string[0:2]))
                final_string = final_string[2:len(final_string)]
            result = result[0:32]
            result = result.replace("\\", "{")
            result = result.replace("\"", "|")
            result = result.replace("'", "}")
            return result
        except Exception as err:
            raise

    def conv_toStr(self, num):  # converts number back into ascii character
        res = num+32
        if res > 94:
            res = (res % 94)+32
        return chr(res)

    def help():
        set = ",".join(self.charset)
        return """
		get_next_char(letter): gets the next letter in the character set based on the input letter (as a string)
		character set = %s
		get_passwd(text(optional)):
		if text variable set: sets the instanced password variable to the text variable.
		if text variable not set: takes the instanced password variable and increments it by 1 letter, then returns the new password variable as a string.
		check_passwd(): checks the current instanced password variable and returns it as a string.
		""" % set
