## Packet Capture Daemon
Capturering and Analyzing packets by using Raw Socket
It works on Linux

```
% pktcaptdctl dump
{
	"interface" : "enp13s0f0",
	"flows" : [
		{
			"count":276,
			"size" :107596,
			"src_mac" : "00:E0:4D:10:8C:0C",
			"dst_mac" : "DC:53:60:03:DD:4C",
			"src_ip4" : "192.168.1.100",
			"dst_ip4" : "192.168.0.38",
			"l4proto" : "tcp",
			"src_port" : 22,
			"dst_port" : 59144
		},
		{
			"count":390,
			"size" :34856,
			"src_mac" : "DC:53:60:03:DD:4C",
			"dst_mac" : "00:E0:4D:10:8C:0C",
			"src_ip4" : "192.168.0.38",
			"dst_ip4" : "192.168.1.100",
			"l4proto" : "tcp",
			"src_port" : 59144,
			"dst_port" : 22
		}
	],
	"total_flow" : 60
}

```

### Build

requires Libevent
```
sudo apt install libevent-dev
```

```
make
```

### Config

Text File

```
<IF1 name> : <Using protocol>
<IF2 name> : <Using protocol>
```
 - <Using protocol>
  - mac, ip, port

### Running

```
sudo pktcaptd [-P <PID file>] [-S <Socket file>] [-C <Config file>]
```

### control

```
sudo pktcaptdctl -S <Socket file> <commands ...>
```
 - <commands>
  - dump, clear
