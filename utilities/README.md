# Utilities to support datamodel deployments

## active-port

This directory has active-port utility which implements active-port ubus object. This object contains one function: dump, which dumps information of all active tcp ports.

```bash
root@sh31b-f04dd44304e0:~# ubus call active-port dump
{
	"connections": [
		{
			"local_ip": "127.0.0.1",
			"local_port": "5038",
			"remote_ip": "0.0.0.0",
			"remote_port": "*",
			"status": "LISTEN"
		},
		{
			"local_ip": "0.0.0.0",
			"local_port": "8080",
			"remote_ip": "0.0.0.0",
			"remote_port": "*",
			"status": "LISTEN"
		},
		...
	]
}
```

## Usage 

This ubus call is used by Device.IP.ActivePort datamodel object.
