# Gravy
Gravy is a Minecraft protocol/server testing toolkit with a full protocol implementation written in python

## Usage
###Dependencies
- pycrypto<br>
- simplejson<br>
```
python Gravy.py
```

### Attack mode
- Creative drop: random item drop (must have a creative account)<br>
- Chat flood <br>
- Reconnect flood: every bot will connect/reconnect in loop<br>
- Packet flood: tries to bypass reconnect flood check<br>
- Timeout: join the server and stop sending packets triggering timeout<br>
- Slot fuller: fill the server with bots<br>

### Nick mode
- Random: Random nicks<br>
- Nicklist: nicknames from list, takes a random from nicks.txt<br>
- Static: Single nick<br>
- Alts: nick premium for premium servers<br>

### Proxy
All bots pass through HTTPS / HTTP proxies (see proxies.txt)

### Contact us
[@Arm4x](https://twitter.com/Arm4x) & [@marcoggl](https://twitter.com/marcoggl)
Feel free to contact us for help or anything else
