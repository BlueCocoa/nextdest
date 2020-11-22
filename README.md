# nextdest

NextDest allows your device that has a public IPv6 address to be automatically register and update its DNS record.

### Motivation
With more and more ISPs offering public IPv6 addresses to their users, we can directly access our devices that has a public IPv6 address. But the public IPv6 address of your device can change from time to time and it's extremely hard to memorise an IPv6 address. 

Therefore we have DNS, a solution from long time ago. Yet it's also boring and painful if we have to set the DNS record by hand.

That's why I wrote NextDest. The client side detects the public IPv6 address on your device (by sending request to the server side, so everything is in your hand). Once it finds any available public IPv6 address, it will send a registration request to the server side along with predefined device name (so that the server side can decide which domain name should be updated). If everything works, the client side will display the latest DNS record and the public IPv6 address of your device.

However, this is NOT the end of the story. If NextDest exposes your public IPv6 address to the Internet, your device could be attacked. 

So NextDest supports 4 modes:

1. direct mode: Internet <-> Endpoint
	The real IPv6 on that device will be used for DNS resolving. 
	All ports can be accessed from the Internet.
	
2. proxy mode: Internet <-> nextdest <-> Endpoint
	An available IP will be used from your IP pool (defined in CIDR format, in server side config file).
	Cloudflare (or other) only acts like a DNS, i.e, the real IP will show up in DNS record.
	Network traffic is forwarded by NextDest.
	Only ports defined in `ports` (in server side config file) can be accessed from the Internet.

3. cdn mode: Internet <-> Cloudflare <-> Endpoint
	The real IPv6 on that device will be only used for DNS zone settings
	All network traffic will be proxied by Cloudflare (or any equvilent), i.e, only CDN's IP will show up in DNS record.
	Only 80 or 443 or other CDN provider allowed ports can be accessed from the Internet.
	
4. hybrid mode
	It is the combination of proxy mode and cdn mode.

### Compile
```bash
cargo build
```

### Usage
```bash
cp config.example.json config.json
# edit config.json and then
nextdest config.json
```
