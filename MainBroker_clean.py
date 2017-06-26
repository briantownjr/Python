import sys
import socket
from ldap3 import Server, Connection, ALL, NTLM, Reader,Attribute, ObjectDef
from PyQt5.QtCore import *
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from Crypto.Cipher import AES
import base64
import _thread
import subprocess
import getpass
import paramiko
from paramiko import SSHClient
from scp import SCPClient
from time import strftime

class Broker(QMainWindow):

    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):

        self.brokerui = Brokerui(self)
        self.setCentralWidget(self.brokerui)
        self.setFixedSize(500, 220)
        self.center()
        self.setWindowTitle('Landsat 8 Connection Broker')
        self.setWindowIcon(QIcon('/home/btown/spacekitty.jpg'))
        self.show()

    def center(self):
        screen = QDesktopWidget().screenGeometry()
        size = self.geometry()
        self.move((screen.width()-size.width())/2,(screen.height()-size.height())/2)


class Brokerui(QWidget):

    #choice = ''

    def __init__(self, parent):

        super().__init__(parent)
        self.initUI()

    def initUI(self):

        self.system_list = []
        # Windows Systems for Users
        self.ltsphostname = socket.gethostname()
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.ipAddr = subprocess.check_output(["hostname", "-I"]).decode('utf-8')
        if 'l8b' in self.ltsphostname:
            s.connect(('DC_IP', 0))
        else:
            s.connect(('DC_IP', 0))
        self.ipaddress = s.getsockname()[0]

        #Dicts of all systems for users to connect to
        #if you need to add a system to a list make sure to follow the python standard
        self.fdslist = {'Dictionary of system hostnames and aliases'}
        self.bfdslist = {'Dictionary of system hostnames and aliases'}
        self.attlist = {'Dictionary of system hostnames and aliases'}
        self.battlist = {'bAttention B': 'l8bmosram02'}
        self.capewinlist = {'Dictionary of system hostnames and aliases'}
        self.bcapewinlist = {'Dictionary of system hostnames and aliases'}
        self.gsilist = {'Dictionary of system hostnames and aliases',
                        }
        self.bgsilist = {'Dictionary of system hostnames and aliases'}
        self.bitpslist = {'Dictionary of system hostnames and aliases'}
        self.itpslist = {'Dictionary of system hostnames and aliases'}

        #Linux systems for users
        self.hfmslist = { 'Dictionary of system hostnames and aliases'}
        self.bhfmslist = {'Dictionary of system hostnames and aliases'}
        self.flexlist = {'Dictionary of system hostnames and aliases'}
        self.bflexlist = {'Dictionary of system hostnames and aliases'}
        self.arclist = {'Dictionary of system hostnames and aliases'}
        self.barclist = {'Dictionary of system hostnames and aliases'}
        self.dmslist = {'Dictionary of system hostnames and aliases'}
        self.bdmslist = {'Dictionary of system hostnames and aliases'}
        self.prtl = {'Dictionary of system hostnames and aliases'}
        self.bprtl = {'Dictionary of system hostnames and aliases'}
        self.prd = {'Dictionary of system hostnames and aliases'}
        self.bprd = {'Dictionary of system hostnames and aliases'}
        self.feplist = {'Dictionary of system hostnames and aliases'}
        self.bfeplist = {'Dictionary of system hostnames and aliases'}
        self.itoslist = {
                        'Dictionary of system hostnames and aliases'
                        }
        self.gseitoslist = {
                        'Dictionary of system hostnames and aliases'
                        }
        self.personal_itos = {
                        'Dictionary of users matched to dictionary of system hostnames and aliases'}
                        }

        self.user_itoslist = {
                        'Dictionary of system hostnames and aliases'
                        }
        self.bitoslist = {
            'Dictionary of system hostnames and aliases',
        }
        self.snaslist = {'Dictionary of system hostnames and aliases'}
        self.bsnaslist = {'Dictionary of system hostnames and aliases'}
        self.simwinlist = {'Dictionary of system hostnames and aliases'}
        self.bsimwinlist = {'Dictionary of system hostnames and aliases'}
        self.simlinlist = {'Dictionary of system hostnames and aliases'}
        self.bsimlinlist = {'Dictionary of system hostnames and aliases'}
        self.gssrfeplist = {'Dictionary of system hostnames and aliases'}
        self.dictupdatelist = []
        self.fulldict = {}

        password = self.password_get()
        #userlogic goes here
        self.username = getpass.getuser() #get user information

        if 'l8b' in self.ltsphostname:
            server = Server('DC_IP')
        else:
            server = Server('DC_IP')
        conn = Connection(server, user='bind_account', password=str(password), authentication=NTLM, auto_bind=True)
        search_filter = '(&(objectClass=user)(sAMAccountName='+self.username+'))'
        conn.search(search_base='domain_base', search_filter=search_filter, attributes=['memberOf'])
        #conn.search(search_base='DC=example,DC=com', search_filter=search_filter, attributes=['memberOf'])
        self.groups = conn.response
        self.user_logic(self.groups)

        #Setting up combobox and label for it
        self.label = QLabel("Choose system to connect to", self)
        self.label.setAlignment(Qt.AlignCenter)
        self.combo = QComboBox(self)
        for system in self.system_list:
            self.combo.addItem(system) #add the system names to combo box to select from
        self.combo.move(175,50)
        self.label.move(160, 30)
        self.combo.currentIndexChanged.connect(self.system_select)

        QToolTip.setFont(QFont('SansSerif', 10))  # sets font for tooltip
        # Quit Button
        quit_btn = QPushButton('Quit', self)
        quit_btn.setToolTip('Quit broker')
        # quit_btn.clicked.connect(QCoreApplication.instance().quit) #quits application
        quit_btn.clicked.connect(self.appquit)
        quit_btn.resize(quit_btn.sizeHint())
        quit_btn.move(10, 190)

        #Suspend button
        suspend_btn = QPushButton('Free Session', self)
        suspend_btn.setToolTip('Suspend sessions')
        suspend_btn.clicked.connect(self.suspend_session)
        suspend_btn.resize(suspend_btn.sizeHint())
        suspend_btn.move(200, 190)

        # Connect Button
        con_btn = QPushButton('Connect', self)
        con_btn.setToolTip('Connect to selected system')
        con_btn.clicked.connect(self.system_connect)
        con_btn.resize(con_btn.sizeHint())
        con_btn.move(410, 190)

    def lockfile_copy(self, file):
        ssh = SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        password = self.password_get()
        ssh.connect(self.ipAddr, 22, 'ltspbroker', str(password))
        scp = SCPClient(ssh.get_transport())
        scp.put(file, '/etc/ltsp_broker/system_locks/')

    def lockfile_remove(self, file):
        ssh = SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        password = self.password_get()
        ssh.connect(self.ipAddr, 22, 'ltspbroker', str(password))
        stdin, stdout, stderr = ssh.exec_command('rm /etc/ltsp_broker/system_locks/'+file+'*')
        ssh.close()

    def lockfile_check(self):
        ssh = SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        password = self.password_get()
        ssh.connect(self.ipAddr, 22, 'ltspbroker', str(password))
        stdin, stdout, stderr = ssh.exec_command('ls /etc/ltsp_broker/system_locks/')
        files = stdout.readlines()
        for x in files:
            if self.fulldict[str(self.connect)] in x:
                return True
        ssh.close()

    def system_use_check(self):
        ssh = SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        password = self.password_get()
        ssh.connect(self.ipAddr, 22, 'ltspbroker', str(password))
        stdin, stdout, stderr = ssh.exec_command('ls /etc/ltsp_broker/system_locks/')
        files = stdout.readlines()
        return files
        ssh.close()

    def password_get(self):
        password = self.decryption('encrypted_password')
        return password

    def user_logic(self, output): #Function to match user groups and append systems to their list
        if ("Domain Admins" in str(output) or self.username == 'root'):
            if 'l8b' in self.ltsphostname:
                self.dictupdatelist.append(self.bgsilist.copy())  # append copies of the dictionaries
                self.dictupdatelist.append(self.bitoslist.copy())
                self.dictupdatelist.append(self.bfdslist.copy())
                self.dictupdatelist.append(self.bflexlist.copy())
                self.dictupdatelist.append(self.barclist.copy())
                self.dictupdatelist.append(self.bdmslist.copy())
                self.dictupdatelist.append(self.bfeplist.copy())
                self.dictupdatelist.append(self.bprd.copy())
                self.dictupdatelist.append(self.bsnaslist.copy())
                self.dictupdatelist.append(self.bsimwinlist.copy())
                self.dictupdatelist.append(self.bsimlinlist.copy())
                self.dictupdatelist.append(self.bprtl.copy())
                self.dictupdatelist.append(self.bcapewinlist.copy())
                self.dictupdatelist.append(self.battlist.copy())
                self.dictupdatelist.append(self.bitpslist.copy())
                self.dictupdatelist.append(self.bhfmslist.copy())
                self.update_list(self.dictupdatelist)
            else:
                self.dictupdatelist.append(self.gsilist.copy())
                self.dictupdatelist.append(self.itoslist.copy())
                self.dictupdatelist.append(self.fdslist.copy())
                self.dictupdatelist.append(self.flexlist.copy())
                self.dictupdatelist.append(self.arclist.copy())
                self.dictupdatelist.append(self.dmslist.copy())
                self.dictupdatelist.append(self.feplist.copy())
                self.dictupdatelist.append(self.prd.copy())
                self.dictupdatelist.append(self.snaslist.copy())
                self.dictupdatelist.append(self.simwinlist.copy())
                self.dictupdatelist.append(self.simlinlist.copy())
                self.dictupdatelist.append(self.prtl.copy())
                self.dictupdatelist.append(self.capewinlist.copy())
                self.dictupdatelist.append(self.attlist.copy())
                self.dictupdatelist.append(self.itpslist.copy())
                self.dictupdatelist.append(self.user_itoslist.copy())
                self.dictupdatelist.append(self.hfmslist.copy())
                self.dictupdatelist.append(self.gssrfeplist.copy())
                self.update_list(self.dictupdatelist)
        if "charlie" in self.username:
            self.dictupdatelist.append({'Dictionary of system hostnames and aliases'})
            self.update_list(self.dictupdatelist)
        if "GSE Users" in str(output):
            if 'l8b' not in self.ltsphostname:
                self.dictupdatelist.append(self.gseitoslist.copy())
                self.update_list(self.dictupdatelist)
        if "ITOS Users" in str(output):
            if 'l8b' in self.ltsphostname:
                self.dictupdatelist.append(self.bitoslist.copy())
                self.update_list(self.dictupdatelist)
            else:
                if self.username in self.personal_itos:
                    your_itos = self.personal_itos[self.username]
                    self.dictupdatelist.append(your_itos)
                self.dictupdatelist.append(self.itoslist.copy())
                self.update_list(self.dictupdatelist)
        if "FDS Users" in str(output):
            if 'l8b' in self.ltsphostname:
                self.dictupdatelist.append(self.bfdslist.copy())
                self.update_list(self.dictupdatelist)
            else:
                self.dictupdatelist.append(self.fdslist.copy())
                self.update_list(self.dictupdatelist)
        if "Flexplan Users" in str(output):
            if 'l8b' in self.ltsphostname:
                self.dictupdatelist.append(self.bflexlist.copy())
                self.update_list(self.dictupdatelist)
            else:
                self.dictupdatelist.append(self.flexlist.copy())
                self.update_list(self.dictupdatelist)
        if "Archiva Users" in str(output):
            if 'l8b' in self.ltsphostname:
                self.dictupdatelist.append(self.barclist.copy())
                self.update_list(self.dictupdatelist)
            else:
                self.dictupdatelist.append(self.arclist.copy())
                self.update_list(self.dictupdatelist)
        if "DMS Users" in str(output):
            if 'l8b' in self.ltsphostname:
                self.dictupdatelist.append(self.bdmslist.copy())
                self.update_list(self.dictupdatelist)
            else:
                self.dictupdatelist.append(self.dmslist.copy())
                self.update_list(self.dictupdatelist)
        if "FEP Users" in str(output):
            if 'l8b' in self.ltsphostname:
                self.dictupdatelist.append(self.bfeplist.copy())
                self.update_list(self.dictupdatelist)
            else:
                self.dictupdatelist.append(self.feplist.copy())
                self.update_list(self.dictupdatelist)
        if "PRD Users" in str(output):
            if 'l8b' in self.ltsphostname:
                self.dictupdatelist.append(self.bprd.copy())
                self.update_list(self.dictupdatelist)
            else:
                self.dictupdatelist.append(self.prd.copy())
                self.update_list(self.dictupdatelist)
        if "SNAS Users" in str(output):
            if 'l8b' in self.ltsphostname:
                self.dictupdatelist.append(self.bsnaslist.copy())
                self.update_list(self.dictupdatelist)
            else:
                self.dictupdatelist.append(self.snaslist.copy())
                self.update_list(self.dictupdatelist)
        if "SIM Users" in str(output):
            if 'l8b' in self.ltsphostname:
                self.dictupdatelist.append(self.bsimwinlist.copy())
                self.dictupdatelist.append(self.bsimlinlist.copy())
                self.update_list(self.dictupdatelist)
            else:
                self.dictupdatelist.append(self.simwinlist.copy())
                self.dictupdatelist.append(self.simlinlist.copy())
                self.update_list(self.dictupdatelist)
        if "XPortal Users" in str(output):
            if 'l8b' in self.ltsphostname:
                self.dictupdatelist.append(self.bprtl.copy())
                self.update_list(self.dictupdatelist)
            else:
                self.dictupdatelist.append(self.prtl.copy())
                self.update_list(self.dictupdatelist)
        if "CAPE Users" in str(output):
            if 'l8b' in self.ltsphostname:
                self.dictupdatelist.append(self.bcapewinlist.copy())
                self.update_list(self.dictupdatelist)
            else:
                self.dictupdatelist.append(self.capewinlist.copy())
                self.update_list(self.dictupdatelist)
        if "Attention Users" in str(output):
            if 'l8b' in self.ltsphostname:
                self.dictupdatelist.append(self.battlist.copy())
                self.update_list(self.dictupdatelist)
            else:
                self.dictupdatelist.append(self.attlist.copy())
                self.update_list(self.dictupdatelist)
        if "ITPS Users" in str(output):
            if 'l8b' in self.ltsphostname:
                self.dictupdatelist.append(self.bitpslist.copy())
                self.update_list(self.dictupdatelist)
            else:
                self.dictupdatelist.append(self.itpslist.copy())
                self.update_list(self.dictupdatelist)
        if "HFMS Users" in str(output):
            if 'l8b' in self.ltsphostname:
                self.dictupdatelist.append(self.bhfmslist.copy())
                self.update_list(self.dictupdatelist)
            else:
                self.dictupdatelist.append(self.hfmslist.copy())
                self.update_list(self.dictupdatelist)
    def appquit(self):

        sys.exit()

    #function to update list
    def update_list(self, dict):

        #check = subprocess.Popen("/etc/monitor.sh", stdout=subprocess.PIPE)
        #checkdout = check.communicate()[0]
        #try:
        #    checkedout = subprocess.check_output("ps -ef | grep x2goclient | grep -v grep | grep -v -E '(sh -c)' | grep -v unixhelper", shell=True)
        #except subprocess.CalledProcessError:
        #    checkedout = ""
        checkedout = self.system_use_check()
        self.inuselist = []
        self.uselist = []
        for x in checkedout:
            self.inuselist.extend(x.split('_'))
        for x in dict:
            self.fulldict.update(x)
            for item in self.fulldict:
                if (str(self.fulldict[str(item)]+'-'+self.username) in str(self.inuselist) or self.fulldict[str(item)] not in str(self.inuselist) ):
                    if item not in self.system_list:
                        self.system_list.append(item)
                        self.system_list.sort()

    #obtains system choice
    def system_select(self, text):

        choice = self.combo.currentText()

    def linuxconnect(self):

        #subprocess.run('mate-terminal',shell=True)
        subprocess.run('vncviewer -fullscreen -UseLocalCursor=off -AutoSelect=0 -FullColour -PreferredEncoding=raw '+self.fulldict[str(self.connect)]+':4999 -passwd /passwordfile', shell=True)

    def windowsconnect(self):
        #/f /multimon
        subprocess.run("xfreerdp /f /multimon -window-drag -offscreen-cache -glyph-cache -themes -wallpaper /audio-mode:2 /sec:rdp /v:" + self.fulldict[str(self.connect)]+" /fullscreen /toggle-fullscreen /cert-ignore", shell=True)

    #checks for max sessions so that users don't hammer the hell out of the system or have 1000 windows open
    def max_sessions_windows(self):
        try:
            output = subprocess.check_output("ps -ef | grep xfreerdp | grep -v grep | grep -v -E '(sh -c)'", shell=True)
        except subprocess.CalledProcessError:
            output = ""
        running_sessions = []
        if output != "":
            running_sessions.extend(output.decode('utf-8').split('\n'))
        counter = 0
        session_running = False
        #find the active user amongst all sessions to get correct number
        for x in running_sessions:
            if self.username in x and 'defunct' not in x:
                counter += 1
        for y in running_sessions:
            if self.connect in y:
                session_running = True

        return session_running, counter


    def max_sessions_linux(self):
        try:
            output = subprocess.check_output("ps -ef | grep vncviewer | grep -v grep | grep -v -E '(sh -c)'", shell=True)
        except subprocess.CalledProcessError:
            output = ""
        running_sessions = []
        if output != "":
            running_sessions.extend(output.decode('utf-8').split('\n'))

        counter = 0
        session_running = False
        #find the active user amongst all sessions to get correct number
        for x in running_sessions:
            if self.username in x and 'defunct' not in x:
                counter += 1
        for y in running_sessions:
            if self.connect in y:
                session_running = True
        return session_running, counter

    def total_owned_check(self,system):
        try:
            output = subprocess.check_output('ls /etc/ltsp_broker/system_locks/', shell=True)
        except subprocess.CalledProcessError:
            output = ""
        running_sessions = []
        if output != "":
            running_sessions.extend(output.decode('utf-8').split('\n'))

        counter = 0
        #find the active user amongst all sessions to get correct number
        for x in running_sessions:
            if self.username in x and str(system) not in x:
                counter += 1
        return counter


    def suspend_session(self):
        self.connect = self.combo.currentText()
        lockstatus = str(self.system_use_check())
        if (self.fulldict[str(self.connect)] + '-' + self.username) in lockstatus:
            if "ITOS" in self.connect:
                msg = "Are you sure you want to free session for " + self.connect + " ? \nThis means that other users can connect to the system. \n                                   **WARNING**\nThis is an ITOS box, make sure you logged out properly if you used your domain account Before selecting yes"
            else:
                msg = "Are you sure you want to free session for " + self.connect + " ? \n\nThis means that other users can connect to the system. "
            reply = QMessageBox.question(self, "Are you sure?", msg, QMessageBox.Yes, QMessageBox.No)
            if reply == QMessageBox.Yes:
                try:
                    output = subprocess.check_output("ps -ef | grep -v grep | grep -v -E '(sh -c)' | grep "+self.fulldict[str(self.connect)]+" | awk '{print $2}'", shell=True)
                except subprocess.CalledProcessError:
                    output = ""
                session_pid=[]
                if output != "":
                    session_pid.extend(output.decode('utf-8').split('\n'))
                try:
                    session_pid = list(filter(None, session_pid))
                    subprocess.run('kill ' + session_pid[0], shell=True)
                    self.lockfile_remove(self.fulldict[str(self.connect)])
                except IndexError:
                    self.lockfile_remove(self.fulldict[str(self.connect)])
        else:
            msg = "You do not own this session "
            QMessageBox.question(self, "Warning", msg, QMessageBox.Ok)

    def system_connect(self, text):
        self.connect = self.combo.currentText()
        log_time = strftime("%m/%d/%Y--%H:%M")
        lock_file = '/tmp/'+self.fulldict[str(self.connect)]+'-'+self.username+'_'+self.ltsphostname+'_lock_file'
        lockfile_status = self.lockfile_check()
        log_file = '/var/log/ltsp/' + self.username + '.log'
        remote_lock = self.system_use_check()

        active_session_counter_linux = self.max_sessions_linux()
        active_session_counter_windows = self.max_sessions_windows()
        total_sessions = active_session_counter_linux[-1] + active_session_counter_windows[-1]
        linuxlist = []
        winlist = []
        total_owned_systems = self.total_owned_check(self.fulldict[str(self.connect)])
        for x in self.gseitoslist,self.personal_itos,self.user_itoslist,self.itoslist,self.bitoslist,self.feplist,self.bfeplist,self.simlinlist,self.bsimlinlist,self.snaslist,self.bsnaslist,self.dmslist,self.bdmslist,self.prtl,self.bprtl,self.prd,self.bprd,self.flexlist,self.bflexlist,self.arclist,self.barclist,self.hfmslist,self.bhfmslist:
            linuxlist.append(x)
        for y in self.gsilist, self.bgsilist, self.fdslist, self.bfdslist, self.capewinlist, self.bcapewinlist, self.attlist, self.battlist, self.simwinlist, self.bsimwinlist, self.bitpslist, self.itpslist:
            winlist.append(y)
        if self.connect in str(linuxlist):
            inuselist = []
            for x in remote_lock:
                inuselist.extend(x.split('_'))
            if ((self.fulldict[str(self.connect)]+'-'+self.username) not in str(inuselist) and lockfile_status == True):
                    #checks if system is in use already
                reply = QMessageBox.question(self, 'System in Use!',
                                                     "The system you selected is in use already. \n\n Please refer to the desktop for in use systems",QMessageBox.Ok)
            elif total_sessions > 1:
                    #checks active sessions currently open by user to limit them
                reply = QMessageBox.question(self, 'Max Session Value!',
                                                     "You have too many active sessions open, please close out sessions to open new ones. If you are logged into ITOS, fully logout of the system.",QMessageBox.Ok)
            elif total_owned_systems > 1:
                reply = QMessageBox.question(self, 'Too many owned systems!',
                                             "You have too many owned sessions, this means you have not freed up sessions you are no longer using. Please refer to 'Active Connections' on the desktop list to see all the systems owned to you. Select systems you are no longer using in the list and click 'Free Session' button \n\n If you see this warning and only see one system on desktop with your name, this most likely means you are logged into your personal ITOS workstation as well.",
                                             QMessageBox.Ok)
            else:
                if lockfile_status != True:
                    subprocess.run('touch ' + lock_file, shell=True)
                    subprocess.run('touch ' + log_file, shell=True)
                    # create log file
                    with open(log_file, 'a+') as edit_file:
                        if 'ldcmops' in self.connect:
                            edit_file.write(self.username + ' connected to ' + self.fulldict[str(
                                self.connect)] + ' at ' + log_time + ' from ' + self.ltsphostname + ' / ' + self.ipaddress + ' as ldcmops user \n')
                        else:
                            edit_file.write(self.username + ' connected to ' + self.fulldict[str(
                                self.connect)] + ' at ' + log_time + ' from ' + self.ltsphostname + ' / ' + self.ipaddress + '\n')
                    self.lockfile_copy('/tmp/' + self.fulldict[
                        str(self.connect)] + '-' + self.username + '_' + self.ltsphostname + '_lock_file')
                _thread.start_new_thread(self.linuxconnect, ())


        elif self.connect in str(winlist):
            inuselist = []
            for x in remote_lock:
                inuselist.extend(x.split('_'))
            if ((self.fulldict[str(self.connect)] + '-' + self.username) not in str(
                    inuselist) and lockfile_status == True):
                # checks if system is in use already
                reply = QMessageBox.question(self, 'System in Use!',
                                             "The system you selected is in use already. \n\n Please refer to the desktop for in use systems",
                                             QMessageBox.Ok)
            elif total_sessions > 1:
                # checks active sessions currently open by user to limit them
                reply = QMessageBox.question(self, 'Max Session Value!',
                                             "You have too many active sessions open, please close out sessions to open new ones. If you are logged into ITOS, fully logout of the system.",
                                             QMessageBox.Ok)
            elif total_owned_systems > 1:
                reply = QMessageBox.question(self, 'Too many owned systems!',
                                             "You have too many owned sessions, this means you have not freed up sessions you are no longer using. Please refer to 'Active Connections' on the desktop list to see all the systems owned to you. Select systems you are no longer using in the list and click 'Free Session' button \n\n If you see this warning and only see one system on desktop with your name, this most likely means you are logged into your personal ITOS workstation as well.",
                                             QMessageBox.Ok)
            else:
                if lockfile_status != True:
                    subprocess.run('touch ' + lock_file, shell=True)
                    subprocess.run('touch ' + log_file, shell=True)
                    # create log file
                    with open(log_file, 'a+') as edit_file:
                        if 'ldcmops' in self.connect:
                            edit_file.write(self.username + ' connected to ' + self.fulldict[str(
                                self.connect)] + ' at ' + log_time + ' from ' + self.ltsphostname + ' / ' + self.ipaddress + ' as ldcmops user \n')
                        else:
                            edit_file.write(self.username + ' connected to ' + self.fulldict[str(
                                self.connect)] + ' at ' + log_time + ' from ' + self.ltsphostname + ' / ' + self.ipaddress + '\n')
                    self.lockfile_copy('/tmp/' + self.fulldict[
                        str(self.connect)] + '-' + self.username + '_' + self.ltsphostname + '_lock_file')
                _thread.start_new_thread(self.windowsconnect, ())


    def encryption(privateInfo):

        BLOCK_SIZE = 16
        PADDING = '{'
        pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
        EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
        secret = base64.b64decode('encrypted_password')
        cipher = AES.new(secret)
        encoded = EncodeAES(cipher, privateInfo)
        print('encrypted string : ', encoded)

    def DecodeAES(self, c, e):

        PADDING = '{'
        cipher = c
        encode_string = e
        enc_str = base64.urlsafe_b64decode(encode_string)
        decrypted_string = cipher.decrypt(enc_str)
        return decrypted_string.decode('utf-8').rstrip(PADDING)

    def decryption(self, encryptedString):

        encryption = encryptedString
        key = base64.b64decode('encrypted_password')
        cipher = AES.new(key)
        decoded = self.DecodeAES(cipher, encryption)
        return decoded


if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = Broker()
    ex.show()
    sys.exit(app.exec_())





