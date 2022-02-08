#!/usr/bin/env python

import os
os.environ['PYTHON_EGG_CACHE'] = '/tmp'
import datetime
from sqlobject import *
import re
#import urllib
#from xml.dom.minidom import parse
from random import choice
#import sys
#import time , string
import ConfigParser


class Arp:
    def get_mac_from_arp( self, ip ):
        cmd = open( "/proc/net/arp" )
        a = cmd.readlines()
        for i in a:
            if( re.compile( ip+" " ).match( i ) ):
                s = i.split()
                return s[3]

class SystemCommand:
    
    def execute( self, cmd ):
        r = os.popen( cmd )
        a = r.readlines()
        return a

    def sudoexecute( self, cmd ):
	#sp = SystemProperties()
        r = os.popen( 'sudo  ' + cmd )
        a = r.readlines()
        return a

class FirewallUtil:

    def __init__(self):
        self.sc = SystemCommand()    
        self.sp = SystemProperties()
    
    def list(self):
        a = self.sc.sudoexecute(self.sp.get_iptables()+" -t mangle -L")
        l = []
        for i in a:
            s = i.split()
            if len(s) > 8:
                if( re.compile( 'MARK' ).match( s[0] ) ):
                    l.append(s[6])
        return l
	
    def is_on_firewall(self,mac):
        r = False
        for m in self.list():
            if m == mac:
                r = True
                break
            else:
                r = False
        return r


class SystemMessages:
        
    def __init__( self ):
        try :
            self.conf = ConfigParser.ConfigParser()
            self.conf.read("/etc/nspot/conf/nspot.conf")
            self.sp = SystemProperties()
        except :
            pass
    
    def get_title( self ):
        return self.conf.get("msg","title")
        
    def msg_login( self ):
        return self.conf.get("msg","msg_login")
        
    def msg_register( self ):
        return self.conf.get("msg","msg_register")
        
    def msg_registerok( self ):
        return self.conf.get("msg","msg_registerok")
        
    def get_initial_page(self):
        return self.conf.get("msg","initial_page")
    
    def get_head_redirect(self):
        return '<meta http-equiv="refresh" content="3; URL=http://'+self.sp.get_initial_page()+'/">'
    
    def get_head_to_login(self):
        return '<meta http-equiv="refresh" content="3; URL=http://'+self.sp.get_ip_internal()+':'+str(self.sp.get_web_port())+'/cgi-bin/index">'

    def msg_allfields( self ):
        return self.conf.get("msg","msg_allfields")
        
    def msg_notsamepassword( self ):
        return self.conf.get("msg","msg_notsamepassword")
        
    def msg_alreadyregistered( self ):
        return self.conf.get("msg","msg_alreadyregistered")
    
    def msg_existmail( self ):
        return self.conf.get("msg","msg_existmail")
        
    def msg_alreadyenabled( self ):
        return self.conf.get("msg","msg_alreadyenabled")
        
    def msg_notregistered( self ):
        return self.conf.get("msg","msg_notregistered")
        
    def msg_wrongip( self ):
        return self.conf.get("msg","msg_wrongip")
        
    def msg_wrongpassword( self ):
        return self.conf.get("msg","msg_wrongpassword")

    def msg_support( self ):
        return self.conf.get("msg","msg_support")        

    def msg_blocked( self ):
        return self.conf.get("msg","msg_blocked")       

    def msg_loginok( self ):
        return self.conf.get("msg","msg_loginok")       

    def msg_warning( self ):
        return self.conf.get("msg","msg_warning")       

    def msg_change_ok( self ):
        return self.conf.get("msg","msg_change_ok")       



class SystemProperties:
        
    def __init__( self ):
        try:
            self.conf = ConfigParser.ConfigParser()
            self.conf.read("/etc/nspot/conf/nspot.conf")

        except:
            self.conf = None
    
    def get_conf( self ):
        pass

    def get_tc( self ):
        sc = SystemCommand()
        return sc.execute( "which tc" )[0].strip('\n')
        
    def get_modprobe( self ):
        sc = SystemCommand()
        return sc.execute( "which modprobe" )[0].strip('\n')
    
    def get_iptables( self ):
        sc = SystemCommand()
        return sc.execute( "which iptables" )[0].strip('\n')
    
    def get_ifconfig( self ):
        sc = SystemCommand()
        return sc.execute( "which ifconfig" )[0].strip('\n')

    def get_if_internal( self ):
        return self.conf.get("config","if_internal")
    
    def get_if_external( self ):
        return self.conf.get("config","if_external")
        
    def get_ip_internal(self):
        return self.conf.get("config","ip_internal")
    
    def get_mysql_user( self ):
        return self.conf.get("config","mysql_user")        
    
    def get_mysql_password( self ):
        return self.conf.get("config","mysql_password")        
    
    def get_mysql_host( self ):
        return self.conf.get("config","mysql_host")        
    
    def get_webservice_port( self ):
        return self.conf.get("config","webservice_port")    
        
    def get_web_port( self ):
        return self.conf.get("config","web_port")
        
    def get_ssl_port( self ):
        return self.conf.get("config","ssl_port")
        
    def get_system_mode( self ):
        return self.conf.get("config","system_mode")

    def get_title( self ):
        return self.conf.get("config","title")
    
    def get_ip_classes( self ):
        return self.conf.get("config","ip_classes")
        
    def get_initial_page(self):
        return self.conf.get("config","initial_page")
        
    def default_bandwidth(self):
        return self.conf.get("config","default_bandwidth")
        
    def get_network(self):
        return self.conf.get("config","network")

    def get_files(self):
        return self.conf.get("config","files")

    def get_web_root(self):
        return self.conf.get("config","web_root")

    def get_admin_pass(self):
        return self.conf.get("config","admin_pass")


class DbConnection:
    def __init__( self ):
        sp = SystemProperties()
        self.strconn = "mysql://"+sp.get_mysql_user()+":"+sp.get_mysql_password()+"@"+sp.get_mysql_host()+"/nspot"
        self.connection = connectionForURI( self.strconn )
        
    def get_connection( self ):
        return self.connection

    # //To revise
    #def create_database(self):
    #    conn = self.connection


class BandwidthControl:
        
    def start( self ):

        sp = SystemProperties()
        tc = sp.get_tc()
        sc = SystemCommand()
        
        sc.sudoexecute( tc + " qdisc add dev "+ sp.get_if_internal() + " root handle 1: htb default 50" )
        sc.sudoexecute( tc + " class add dev "+ sp.get_if_internal() + " parent 1: classid 1:1 htb rate 1024kbit ceil 1024kbit" )

    def stop( self ):

        sp = SystemProperties()
        tc = sp.get_tc()
        sc = SystemCommand()
        
        sc.sudoexecute( tc + " qdisc del dev "+ sp.get_if_internal() + " root" )


class Banned( SQLObject ):
    _dbc = DbConnection()
    _connection = _dbc.get_connection()
    sqlhub.processConnection = _connection
    
    user_id = IntCol()
    time = DateTimeCol()


class BannedDAO:
    def create(self,user):
        if not self.is_banned(user):
            Banned(user_id = user.id, time = datetime.datetime.now())

    def delete(self,user):
        uid = self.retrieve_by_userid(user)
        if self.is_banned(user):
                Banned.delete(uid.id)
        
    def is_banned(self, user):
        if Banned.selectBy(user_id = user.id).count() > 0 :
            return True
        else:
            return False

    def retrieve_by_userid(self, user):
        if Banned.selectBy(user_id = user.id).count() > 0 :
            return Banned.selectBy(user_id = user.id).__getitem__(0)
        else:
            return None
        
    def retrieve_list( self ):
        if Banned.select().count() > 0 :
    	    l = Banned.select()
        else:
            l = None
            return l
    

class Blocked( SQLObject ):
    _dbc = DbConnection()
    _connection = _dbc.get_connection()
    sqlhub.processConnection = _connection

    user_id = IntCol()
    time = DateTimeCol()


class BlockedDAO:
    def create(self,user):
        if not self.is_blocked(user):
            Blocked(user_id = user.id, time = datetime.datetime.now())

    def delete(self,user):
        uid = self.retrieve_by_userid(user)
        if self.is_blocked(user):
                Blocked.delete(uid.id)

    def is_blocked(self, user):
        if Blocked.selectBy(user_id = user.id).count() > 0 :
            return True
        else:
            return False
        
    def retrieve_by_userid(self, user):
        if Blocked.selectBy(user_id = user.id).count() > 0 :
            return Blocked.selectBy(user_id = user.id).__getitem__(0)
        else:
            return None
        
        
    def retrieve_list( self ):
        if Blocked.select().count() > 0 :
    	    l = Blocked.select()
        else:
            l = None
            return l
    
class Converter:
    def get_hex(self,num):
        s = hex(num).__str__().split("x")[1].upper()
        if(len(s) == 1):
            return "00"+s
        elif(len(s) == 2):
            return "0"+s
        else:
            return s


class FirewallInitializer:
    def start( self ):
        self.flush()
        self.fire()

    def stop( self ):
        self.flush()
        self.free()

    # To revise
    #def status( self ):
    #	sc = SystemCommand()
    #   sp = SystemProperties()
            
    #	l = sc.sudoexecute( sp.get_iptables() + " -L -t nat"  )
    
    def flush( self ):
        sc = SystemCommand()
        sp = SystemProperties()
        
        sc.sudoexecute( sp.get_iptables() + " -F" )
        sc.sudoexecute( sp.get_iptables() + " -F -t nat" )
        sc.sudoexecute( sp.get_iptables() + " -F -t mangle" )

    def free( self ):
        sc = SystemCommand()
        sp = SystemProperties()
        
        sc.sudoexecute( sp.get_iptables() + " -t nat -A POSTROUTING -j MASQUERADE" )

    def fire( self ):
        sc = SystemCommand()
        sp = SystemProperties()
        bl = BannedDAO().retrieve_list()
        #sv = ServerDAO().retrieve_list()
	
        sc.sudoexecute( sp.get_modprobe() + " ipt_REDIRECT" )
        sc.sudoexecute( sp.get_modprobe() + " ipt_MASQUERADE" )
        sc.sudoexecute( sp.get_modprobe() + " ipt_MARK" )
        sc.sudoexecute( sp.get_modprobe() + " ipt_REJECT" )
        sc.sudoexecute( sp.get_modprobe() + " ipt_TOS" )
        sc.sudoexecute( sp.get_modprobe() + " ipt_LOG" )
        sc.sudoexecute( sp.get_modprobe() + " iptable_mangle" )
        sc.sudoexecute( sp.get_modprobe() + " iptable_filter" )
        sc.sudoexecute( sp.get_modprobe() + " iptable_nat" )
        sc.sudoexecute( sp.get_modprobe() + " ip_nat_ftp" )
        sc.sudoexecute( sp.get_modprobe() + " ip_conntrack" )
        sc.sudoexecute( sp.get_modprobe() + " ipt_mac" )
        sc.sudoexecute( sp.get_modprobe() + " ipt_limit" )
        sc.sudoexecute( sp.get_modprobe() + " ipt_state" )
        sc.sudoexecute( sp.get_modprobe() + " ipt_mark" )
        sc.sudoexecute( sp.get_modprobe() + " ip_nat_irc" )

        sc.sudoexecute( sp.get_iptables() + " -P INPUT ACCEPT" )
        sc.sudoexecute( sp.get_iptables() + " -P OUTPUT ACCEPT" )
        sc.sudoexecute( sp.get_iptables() + " -P FORWARD ACCEPT" )
        sc.sudoexecute( sp.get_iptables() + " -A PREROUTING -t mangle -j MARK --set-mark 4" )
        sc.sudoexecute( sp.get_iptables() + " -t nat -A POSTROUTING -m mark --mark 3 -j MASQUERADE" )
        sc.sudoexecute( sp.get_iptables() + " -t nat -A POSTROUTING -m mark --mark 4 -d " + sp.get_ip_internal() + " -j MASQUERADE" )
        sc.sudoexecute( sp.get_iptables() + " -t nat -A PREROUTING -m mark --mark 4 -p tcp --dport 80 -d ! " + sp.get_ip_internal() + " -j REDIRECT --to-port " + sp.get_web_port().__str__() )
        sc.sudoexecute( sp.get_iptables() + " -t nat -A PREROUTING -i " + sp.get_if_internal() + " -j ACCEPT" )
        sc.sudoexecute( sp.get_iptables() + " -t nat -A PREROUTING -m mark --mark 4 -p tcp --dport 53 -j REDIRECT --to-port 53" )
        #sc.sudoexecute( sp.get_iptables() + " -t nat -A PREROUTING -m mark --mark 3 -p tcp --dport 80 -j REDIRECT --to-port 3128" )
        sc.sudoexecute( sp.get_iptables() + " -t nat -I PREROUTING -m mark --mark 4 -j LOG --log-level debug --log-ip-options" )
        sc.sudoexecute( sp.get_iptables() + " -t mangle -A POSTROUTING -p tcp --dport 25 -j TOS --set-tos 8" )
        sc.sudoexecute( sp.get_iptables() + " -A INPUT -p icmp --icmp-type 8 -j DROP" )
        sc.sudoexecute( sp.get_iptables() + " -A INPUT -i eth0 -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s -j ACCEPT" )
        
        if bl != None:
            for i in bl:
                u = UserDAO().retrieve_by_id(i.user_id)
                sc.sudoexecute(sp.get_iptables()+ " -A INPUT -j DROP -m mac --mac-source "+ u.mac)
                sc.sudoexecute(sp.get_iptables()+ " -A FORWARD -j DROP -m mac --mac-source "+ u.mac)


class GeneratePassword:
    def password(self):
        c = "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
        s = ""
        for i in range( 8 ):
            s += choice( c )
        return s

class IpAssign:
    def networks(self):
        a = []
        for i in range( 0, 255, 4 ):
            a.append( [i, i+1, i+2, i+3] )
        return a
        

class Log( SQLObject ):
    _dbc = DbConnection()
    _connection = _dbc.get_connection()
    sqlhub.processConnection = _connection
    
    user_id = IntCol()
    time = DateTimeCol()
    message = StringCol( length = 200 )


class LogDAO:
    
    def create(self,user,msg):
        Log(user_id = user.id, time = datetime.datetime.now(),message = msg)


class Server( SQLObject ):
    _dbc = DbConnection()
    _connection = _dbc.get_connection()
    sqlhub.processConnection = _connection
    
    user_id = IntCol()
    descript = StringCol( length = 200 )


class ServerDAO:
    
    def create(self,user,msg):
        Server(user_id = user.id, descript = msg)

    def retrieve_list( self ):
        l = Server.select( orderBy = "user_id")
        return l
	


class Message( SQLObject ):
    _dbc = DbConnection()
    _connection = _dbc.get_connection()
    sqlhub.processConnection = _connection

    message = StringCol( length = 200 )
    user_id = IntCol()
    time = DateTimeCol()
    rd = BoolCol()


class MessageDAO:
    def create(self,user,msg):
        Message(message = msg, user_id = user.id, time = datetime.datetime.now(),rd = False)
        
    def retrieve_list(self,user):
        
        if Message.selectBy( user_id = user.id , rd = False ).count() > 0:
            l = Message.selectBy(user_id = user.id , rd = False)
        else:
            l = None
            return l
        
    def update(self,user):
        l = Message.selectBy( user_id = user.id , rd = False)
        for m in l:
	        m.rd = True


class PrepareDb:
    def install_tables(self):
        User.createTable()
        Message.createTable()
        Log.createTable()
        Blocked.createTable()
        Banned.createTable()
        Server.createTable()        

class Properties:
    def __init__( self ):
        sp = SystemProperties()
        self.title = sp.get_title()
        self.if_internal = sp.get_if_internal()


class User( SQLObject ):
    _dbc = DbConnection()
    _connection = _dbc.get_connection()
    sqlhub.processConnection = _connection

    name = StringCol( length = 50 )
    address = StringCol( length = 50 ) 
    neighborhood = StringCol( length = 50 )
    zip = StringCol( length = 50 )
    telephone = StringCol( length = 50 )
    celular = StringCol( length = 50 )
    email = StringCol( length = 50 )
    cpf = StringCol( length = 11 )
    ip = StringCol( length = 15 )
    mac = StringCol( length = 17 )
    payday = IntCol()
    network = StringCol( length = 50 )
    registerdate = DateTimeCol()
    password = StringCol( length = 20 )
    bandwidth = StringCol( length = 4 )
    contactemail = StringCol( length = 30 )
    rg = StringCol( length = 20 )
    birthday = DateTimeCol()
    

class UserDAO:
    def create( self, nam, add, nei, ziz, tel, cel, ema, cpc, ipi, mam, pay, net, reg, pas, ban, con, rgr , btd ):
        User(   name = nam, 
                address = add, 
                neighborhood = nei, 
                zip = ziz, 
                telephone = tel, 
                celular = cel, 
                email = ema, 
                cpf = cpc, 
                ip = ipi, 
                mac = mam, 
                payday = pay, 
                network = net, 
                registerdate = reg, 
                password = pas, 
                bandwidth = ban, 
                contactemail = con, 
                rg = rgr, 
	            birthday = btd)

    def retrieve_list( self ):
        l = User.select( orderBy = "id")
        return l
   
    def retrieve_by_mac( self, m ):
        if User.selectBy( mac = m ).count() > 0 :
            u = User.selectBy( mac = m ).__getitem__( 0 )
        else:
            u = None
        return u
    
    def retrieve_by_id( self, m ):
        if User.selectBy( id = m ).count() > 0 :
            u = User.selectBy( id = m ).__getitem__( 0 )
        else:
            u = None
        return u
    
    def retrieve_by_email( self, m ):
        if User.selectBy(email = m).count() > 0 :
            u = User.selectBy( email = m ).__getitem__( 0 )
        else:
            u = None
        return u
    
    def retrieve_id( self, m ):
        if User.selectBy( mac = m ).count() > 0 :
            u = User.selectBy( mac = m ).__getitem__( 0 )
        else:
            u = None
        return u.id
    
    def update_password( self, uid, p ):
        user = User.selectBy( id = uid ).__getitem__( 0 )
        user.password = p
        
    def update_band( self, uid, b ):
        user = User.selectBy( id = uid ).__getitem__( 0 )
        user.bandwidth = b
        
    def delete(self,uid):
	    User.delete(uid)

class UserHandler:
    
    def __init__(self,user):
        self.user = user
        self.bldao = BlockedDAO()
        self.bndao = BannedDAO()
        self.sc = SystemCommand()
        self.sp = SystemProperties()
        self.cv = Converter()
        self.logdao = LogDAO()


    def add_if(self):
        self.sc.sudoexecute(self.sp.get_ifconfig()+" "+self.sp.get_if_internal()+":"+self.cv.get_hex(self.user.id))

    def del_if(self):
        self.sc.sudoexecute(self.sp.get_ifconfig()+" "+self.sp.get_if_internal()+":"+self.cv.get_hex(self.user.id))

    def allow(self):
    	if not self.is_on_firewall():
	        self.sc.sudoexecute(self.sp.get_iptables()+ " -A PREROUTING -t mangle -j MARK --set-mark 3 -m mac --mac-source "+ self.user.mac+" -s "+self.user.ip)
    	    self.set_band()
    	    self.log("User Logged In")

    def deny(self):
        if self.is_on_firewall():
                self.sc.execute(self.sp.get_iptables()+ " -D PREROUTING -t mangle -j MARK --set-mark 3 -m mac --mac-source "+ self.user.mac+" -s "+self.user.ip)

    def ban(self):
        self.deny()
        self.sc.sudoexecute(self.sp.get_iptables()+ " -A INPUT -j DROP -m mac --mac-source "+ self.user.mac)
        self.sc.sudoexecute(self.sp.get_iptables()+ " -A FORWARD -j DROP -m mac --mac-source "+ self.user.mac)

    def unban(self):
        self.sc.sudoexecute(self.sp.get_iptables()+ " -D FORWARD -j DROP -m mac --mac-source "+ self.user.mac)
        self.sc.sudoexecute(self.sp.get_iptables()+ " -D INPUT -j DROP -m mac --mac-source "+ self.user.mac)
        
    def block_user(self):
        self.bldao.create(self.user)
        self.deny()
        self.log("User Blocked")

    def unblock_user(self):
        self.bldao.delete(self.user)
        self.log("User Unblocked")

    def ban_user(self):
        self.bndao.create(self.user)
        self.deny()
        self.ban()
        self.log("User Banned")

    def unban_user(self):
        self.bndao.delete(self.user)
        self.unban()
        self.log("User Unbanned")
        
    def log(self,msg):
        self.logdao.create(self.user,msg)
    
    def set_band( self ):

        tc = self.sp.get_tc()
        
        self.sc.sudoexecute( tc + " class add dev "+ self.sp.get_if_internal() + " parent 1:1 classid 1:1"+ self.cv.get_hex( int(self.user.id) )+ " htb rate 64kbit ceil " + str(self.user.bandwidth) + "kbit" )
        self.sc.sudoexecute( tc + " filter add dev "+ self.sp.get_if_internal() + " protocol ip parent 1:1 prio 1 u32 match ip src "+ self.user.ip + " flowid 1:1"+ self.cv.get_hex( int(self.user.id) ) )
        self.sc.sudoexecute( tc + " filter add dev "+ self.sp.get_if_internal() + " protocol ip parent 1:0 prio 1 u32 match ip dst "+ self.user.ip + " flowid 1:1"+ self.cv.get_hex( int(self.user.id) ) )
        self.sc.sudoexecute( tc + " filter add dev "+ self.sp.get_if_internal() + " protocol ip parent 1:0 prio 1 u32 match ip src "+ self.user.ip + " flowid 1:1"+ self.cv.get_hex( int(self.user.id) ) )

    def del_band( self ):
        pass
    
    def is_on_firewall(self):
        fu = FirewallUtil()
        return fu.is_on_firewall(self.user.mac)
            
