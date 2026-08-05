# EvilARP
EvilARP - advanced ARP poisoning tool.
# Synopsis
```shell
earp -i <interface> -t <target> [-b <second_target] [options]
```
# Description

EvilARP is command-line utility designed for network security testing. EvilARP sends crafted ARP frames that poison ARP tables of other devices on the network.
By spoofing the MAC address of legitimate device, it enables the attacker to capture traffic.

Supported types of attacks:
- **Single target mode** sends packets to a single victim.
- **Dual target mode** sends packets to two hosts, positioning the atacker between them for a Man-in-the-Middle attack.
- 
Supported ARP frame types:
- **ARP Reply (unicast)** sends a frame to one host.
- **Gratuitous ARP Reply (broadcast)** sends a frame to all hosts in the local network.

Other features:
- **Random random delay time** specifies minimum and maximum random delay between packets via rand_min and rand_max.
- **ARP Storm mode** sends packets without delay.
- **Timer setting** exits program when timer time expires. Specifies in seconds.

# Options: 
	-h, --help              Show help message.
	-t, --target            Specify the target IP address.
	-a, --target-a          Target IP A (only in dual target mode).
	-b, --target-b          Target IP B (only in dual target mode).
	-d, --dual-target       Enable dual target mode (MITM).
	-g, --gratuitous        Send gratuitous ARP packets.
	-i, --interface         Specify the network interface (e.g., eth0, wlan0).
	-m, --rand-min          Minimum delay between packets (ms).
	-M, --rand-max          Maximum delay between packets (ms).
	-s, --storm             ARP storm mode (send packets without delay).
	-T, --timer             Set timeout in seconds. Program will exit, when time expires.
# Notes
 - **ARP Storm mode: can crash the network (use with caution)**
 - **Use Gratuitous ARP only when needed: it may trigger firewall alerts**
 - **EvilARP in single target mode sends only gratuitous frames**
 - **Wait for the program to send re-arping target packets: overwise the ARP tables may not restore immediately**
# Warning
**This tool is for authorized network testing only! Use at your own risk.**
# Examples
**Sending gratuitous frames for 192.168.1.1 via eth0 for 5 seconds:**
```shell
sudo earp -t 192.168.1.1 -i eth0 -T 5
```
**Sending ARP Replies for 192.168.1.1 and 192.168.1.2 via wlan0 with storm mode:**
```shell
sudo earp -a 192.168.1.1 -b 192.168.1.2 -i wlan0 -s
```
