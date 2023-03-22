---
author: Chance Johnson
layout: post
---
# Introduction
This post will walk you through the steps of deciphering a hex dump of captured network packets. By the end of this post, you will be able to analyze a packet hex dump like the following to identify each part of the packet and extract useful information from it:
```
00 00 00 00 00 00 00 00 00 00 00 00 08 00 45 00
00 41 55 69 40 00 40 06 e7 4b 7f 00 00 01 7f 00
00 01 1f 40 da 48 bc 97 ee ea d3 13 28 3a 80 18
02 00 fe 35 00 00 01 01 08 0a e4 09 f0 1b e4 09
f0 1b 6a 41 38 32 36 57 35 41 42 25 64 64 0a
```

While packet analysis tools like Wireshark perform this process automatically, it's important to understand exactly how this process works. By the end of this post, you will have a comprehensive understanding of how Wireshark interprets captured packet bytes to identify each part of the packet, as well as any data it contains. 

## Post Structure:
1. Setup an HTTP server to serve a file.
2. Capture an HTTP request and response.
3. Analyze the packet bytes.

I encourage you to follow along with me in this post and perform the following steps on your own machine. If you do not wish to perform the packet capture yourself, you can download the capture that I'll be using for this post [here](https://drive.google.com/file/d/1ELTtVO8geU4tlGwtRO_MiBsBT_02a7Q4/view). 

This post assumes you are using a Linux distribution, and that you have Python installed. Familiarity with TCP/IP networking concepts is a plus. 

# Setup HTTP Server
I will start off by creating a file called "password" which will contain a password:
```
echo "jA826W5AB%dd" > password
```

Create an HTTP server via Python:
```
python3 -m http.server -b 127.0.0.1
```
- `-b 127.0.0.1` ensures the server will only be available from your own machine.

This will start an HTTP server at 127.0.0.1 (the loopback interface) on port 8000 (default port used by the http.server Python module).

# Capture an HTTP Request
Before creating the HTTP GET request, we need to setup a program to capture any packets that are sent across 127.0.0.1 on port 8000. For this purpose, I have created simple program that uses the [libpcap](https://www.tcpdump.org/) packet capture library. This is the same library that the tools Wireshark and tcpdump use to capture network traffic.

This program requires the libpcap development libraries to be installed. If you're using Debian, these libraries can be installed with the following command: 
```
sudo apt-get install libpcap-dev
```

Download the program:
```
wget https://raw.githubusercontent.com/chancej715/raw-traffic/main/rawtraffic.c
```

Compile it:
```
gcc rawtraffic.c -o rawtraffic -l pcap
```

Monitor port 8000 on the loopback interface:
```
sudo ./rawtraffic lo 8000
```

Open another terminal session, and connect to the HTTP server via Netcat:
```
nc 127.0.0.1 8000
```

This will establish a connection with the HTTP server. Send an HTTP GET request to retrieve the file that was created earlier:
```
GET /password HTTP/1.1

```

Don't forget the blank line at the end, because it marks the end of the HTTP request. Press enter one more time, and you should see the HTTP response printed to your terminal screen. Now press CTRL+D on your keyboard. At this point the Netcat process should have ended, and you should be back at your usual terminal prompt. 

# Analyze Packet Bytes
There should now be a file called "capture" located in the same directory as the packet capture program. This file contains all the packets that were sent and received in this communication, as well as the HTTP request and response data. You may also download this file [here](https://drive.google.com/file/d/1ELTtVO8geU4tlGwtRO_MiBsBT_02a7Q4/view). 

The following command will display the contents of the file in canonical hex+ASCII format:
```
hexdump -C capture
```

The output of this command is what's referred to as a "hex dump". It's what appears at the bottom of Wireshark when you select a packet. 

I'll use this command to make things a bit cleaner:
```
hexdump -e '16/1 "%02x " "\n"' capture
```

It's the same as the previous command, but it doesn't include the ASCII or the input offset.

Each hexadecimal number in the hex dump represents a single byte. There is a maximum of 16 bytes per line. At first glance this may look intimidating, especially if it's your first time examining a hex dump. Rest assured that after doing this process once, you will come to realize it's quite simple.

Before we try to make sense of these bytes, let's first run the following command to understand a bit more about the file itself:
```
file capture
```

You'll notice that the output says "pcap capture file". This is the file format the libpcap library uses to save captured packets. [This](https://www.ietf.org/archive/id/draft-ietf-opsawg-pcap-02.html) document describes the structure of the PCAP capture file format. It states:
> A capture file begins with a File Header, followed by zero or more Packet Records, one per packet.
> [PCAP Capture File Format](https://www.ietf.org/archive/id/draft-ietf-opsawg-pcap-02.html#section-3-1)

According to the document, the File Header is 24 bytes. Use dd to copy the first 24 bytes of the capture into another file called "capture_file_header":
```
dd if=capture of=capture_file_header bs=1 count=24
```

Print the hex dump of this file:
```
hexdump -e '16/1 "%02x " "\n"' capture_file_header
```

Here is the output:
```
d4 c3 b2 a1 02 00 04 00 00 00 00 00 00 00 00 00
00 20 00 00 01 00 00 00
```

This is the File Header of the PCAP file. I'm not going to spend any time on this, because I want to focus on decoding the packets.

As the document states, following the File Header is the Packet Record. This field begins with a 16 byte header, followed by data from the packet. Let's copy the Packet Record header of the first packet into its own file. 

From an offset of 24 bytes (because that's the length of the File Header), use dd to copy the next 16 bytes into its own file:
```
dd if=capture of=capture_packet1_record_header bs=1 skip=24 count=16 iflag=skip_bytes,count_bytes
```

Use the hexdump to see the hex dump of the file:
```
hexdump -e '16/1 "%02x " "\n"' capture_packet1_record_header
```

The output:
```
51 dc 17 64 fc 1e 05 00 4a 00 00 00 4a 00 00 00
```

If you have performed your own capture, then your output may not be the same as mine, but it's okay. 

The hex dump above is the Packet Record header of the first captured packet. Each captured packet has its own Packet Record header. This header contains information about the packet, including a timestamp, as well as the length of the captured packet. 

According to the document linked above, the first 8 bytes of the Packet Record header are timestamp fields. I will skip these fields and move on to the next field. 

The document states that the next 4 bytes is the "Captured Packet Length" field. In the hex dump, these bytes are `4a 00 00 00`. We only need the non-zero byte here. 0x4A converted to decimal is 74, which means the following packet should be 74 bytes in long. 

The next 4 bytes in the hex dump represent the "Original Packet Length" field. As you can see, it has the same value as the "Captured Packet Length". The bytes immediately after this field mark the beginning of the first packet. 

I will use dd to copy the 74 bytes of this packet into a separate file called "capture_packet1". Remember that the File Header is 24 bytes long, and the Packet Record header that follows it is 16 bytes long. Therefore, I will start at an offset of 40 bytes, and I will copy the next 74 bytes to its own file:
```
dd if=capture of=capture_packet1 bs=1 skip=40 count=74 iflag=skip_bytes,count_bytes
```

## Ethernet Frame Header
Print the hex dump of this new file:
```
hexdump -e '16/1 "%02x " "\n"' capture_packet1
```

Here's the output:
```
00 00 00 00 00 00 00 00 00 00 00 00 08 00 45 00
00 3c f2 d9 40 00 40 06 49 e0 7f 00 00 01 7f 00
00 01 da 48 1f 40 d3 13 28 21 00 00 00 00 a0 02
ff d7 fe 30 00 00 02 04 ff d7 04 02 08 0a e4 09
db fc 00 00 00 00 01 03 03 07 
```

This is a hex dump of the first packet. Actually, this is a packet contained within an Ethernet frame. To decode this hex demp, we can reference the following diagram of an Ethernet II frame:
![[Ethernet Type II Frame Structure Diagram.png]]
[Source](https://en.wikipedia.org/wiki/Ethernet_frame)

According to this diagram, the first 6 bytes of an Ethernet II frame define the destination MAC address. These are the first 6 bytes in the hex dump:
```
00 00 00 00 00 00
```

MAC addresses are usually written in 6 pairs of hexadecimal numbers separated by colons, so the destination MAC address for this frame is 00:00:00:00:00:00. This makes sense, because the packet was sent over the loopback interface, which doesn't really have a MAC address. 

The diagram says the next 6 bytes are the source MAC address. In the hex dump, these values are the same.

The next 2 bytes are the EtherType field. This field indicates which protocol is encapsulated in the payload of the Ethernet frame. In our hex dump, we can see that the value for this field is `08 00`. A hexadecimal value of 0x0800 in the EtherType field indicates an IPv4 packet. 

## IPv4 Packet Header
Now it's time to look inside the payload of this Ethernet frame which is, in this case, an IPv4 packet. Here is the hex dump with the Ethernet header removed:
```
45 00 00 3c f2 d9 40 00 40 06 49 e0 7f 00 00 01
7f 00 00 01 da 48 1f 40 d3 13 28 21 00 00 00 00
a0 02 ff d7 fe 30 00 00 02 04 ff d7 04 02 08 0a
e4 09 db fc 00 00 00 00 01 03 03 07
```

From this hex dump, we will extract the following information:
- Version
- Internet Header Length (IHL)
- DSCP
- ECN
- Total Length
- Identification
- Flags
- Fragment Offset
- Time To Live
- Protocol
- Header Checksum
- Source IP Address
- Destination IP Address

All of these fields together make up an IPv4 packet header. We can use the following IPv4 header diagram to find the value of these fields in the hex dump:
![[IPv4 Header Structure Diagram.png]]
[Image source](https://nmap.org/book/tcpip-ref.html)

### Version and IHL
The diagram above indicates that the first byte in the IPv4 header contains the values of the **version** and **IHL** fields. The value of this byte in the hex dump is `45`. Because this byte contains the value of two fields of the IPv4 header, we first need to convert it to binary. 0x45 converted to binary is 1000101. I'll add a leading 0 as padding for a total of 8 bits. The value becomes 01000101. The first 4 bits, 0100, is the value of the version field, and the last 4 bits, 0101, is the value of the IHL field. 

In decimal, the value of the version field is 4, and the value of the IHL field is 5. For IPv4, the value of the version field is always 4. According to [Wikipedia](https://en.wikipedia.org/wiki/Internet_Protocol_version_4#IHL):
> The IHL field contains the size of the IPv4 header; it has 4 bits that specify the number of 32-bit words in the header. The minimum value for this field is 5, which indicates a length of 5 × 32 bits = 160 bits = 20 bytes.

Now that we know how many bytes the IPv4 header is, we can identify which part of this hex dump is the header, and which part is the payload. Starting from the first byte of the IPv4 header, count until the 20th byte:
```
45 00 00 3c f2 d9 40 00 40 06 49 e0 7f 00 00 01
7f 00 00 01
```

This should be the IPv4 packet header, and the bytes after it should be the payload. 

### DSCP and ECN (previously TOS)
The next byte should contain the values of the **Differentiated Services Code Point (DSCP)** and **Explicit Congestion Notification (ECN)** fields. In the diagram above, it says this is the **Type of Service (TOS)** field. This was the original definition of this field, and it has since been changed. In the hex dump, value of these bytes are 0.

### Total Length
The third and fourth byte are the **total length** field. The value of this field represents the entire packet size in bytes, including the header and payload. In the hex dump, these bytes are `00 3c`. 0x3C in decimal is 60. This means the total length of this packet is 60 bytes. If you want, you can confirm this by counting all the bytes in the hex dump.

### Identification
The next two bytes are the **identification** field. This field is used to uniquely identify a group of fragments of an IPv4 packet, so that they can be properly reassembled upon receival. Their values are `f2 d9`. 0xF2D9 is 62169 in decimal.

### Flags and Fragment Offset
The following two bytes include the **flags** and **fragment offset** fields. The bytes in the hex dump are `40 00`. 0x40 in binary is 1000000. Add a leading 0 to make it 8 bits for the value of 01000000. The first 3 bits make up the flags field. 

Here is the meaning of each bit, in order:
- Reserved: 0
- Don't Fragment (DF): 1
- More Fragment: 0

For this IPv4 packet, only the DF flag is set. The fragment offset field has a value of 0.

### Time To Live (TTL)
The next byte is the **Time To Live (TTL)** field. The hexadecimal value of the byte in the hex dump is `40`, or 64 in decimal. 

### Protocol
The byte after that is the **protocol** field, which identifies the protocol that's encapsulated in the payload. The value in the hex dump is `06`, or 6 in decimal. A value of 6 for this field means the payload contains a TCP packet. 

### Checksum
The next two bytes are the **checksum** field which is used to make sure no errors occurred during the transmission of the packet. In the hex dump, the bytes are `49 e0`. The value of this field is 0x49E0.

### Source and Destination Address
The next four bytes is the **source address**. The bytes in the hex dump are `7f 00 00 01`. 0x7F to decimal is 127, therefore the source IP address is 127.0.0.1. The next 4 bytes are the destination IP address, and the value is the same.

The rest of the hex dump is the IPv4 packet's payload. In this case, it's a TCP packet.

## TCP Packet Header
Removing the IPv4 header, here's whats left of the hex dump:
```
da 48 1f 40 d3 13 28 21 00 00 00 00 a0 02 ff d7
fe 30 00 00 02 04 ff d7 04 02 08 0a e4 09 db fc 
00 00 00 00 01 03 03 07
```

These bytes make up a single TCP packet. We will find the following information from these bytes:
- Source port
- Destination port
- Sequence Number
- Acknowledgement Number
- Data Offset
- Reserved
- Flags
- Window Size
- Checksum
- Urgent Pointer
- Options

I'll use the following TCP header structure diagram to decode these bytes:
![[TCP Header Structure Diagram.png]]
[Image source](https://nmap.org/book/tcpip-ref.html)

### Source Port
The first two bytes represent the **source port**. Their values are `da 48`. 0xDA48 is 55880 in decimal. When a client initiates a TCP or UDP connection to a server, it is assigned a temporary, ephemeral, port number.

### Destination Port
The following two bytes contain the **destination port**. The bytes are `1f 40`. Converted to decimal, 0x1F40 is 8000. This is the port that the HTTP server was listening to, and it's the port that we connected to with Netcat.

### Sequence Number
The next 4 bytes is the **sequence number**. This number is used to keep track of every byte sent from a host. It allows the receiving end to reassemble bytes in the same order in which they were sent.

In the hex dump, the bytes are `d3 13 28 21`. 0xD3132821 is 3541248033 in decimal. 

### Acknowledgement Number
The next 4 bytes make up the **acknowledgement number**. This is similar to the sequence number in that it enables reliable data transfer. In the hex dump, the bytes are `00 00 00 00`. They have a value of 0, because this is the first packet in the TCP connection from the client to the server.

### Data Offset and Reserved
The byte after that contains the values for the **data offset** and **reserved** fields. In the hex dump, its value is `a0`. Since this byte represents the values of two different flags, we must first convert it to binary. 0xA0 in binary is 10100000.

The first 4 bits, 1010, is the offset field. Its decimal value is 10. Like the IHL field in the IPv4 header, the data offset field specifies the number of 32-bit words in the TCP header. This means we can multiply this number by 32 to get the length (in bits) of the TCP header:

10 × 32 = 320 / 8 = 40 bytes.

This calculation tells us that the TCP header is 40 bytes. If you count the number of bytes in the hex dump for this TCP packet, you'll notice that it's exactly 40. Therefore, this TCP packet contains no payload.

The value of the reserved field is 0.

### Flags
The next byte is the **flags** field. This field is used to provide information about the connection. In our hex dump, the byte is `02`. This is 10 in binary or 00000010 with padding. Let's line this number up to the following TCP flags table:
```
+-------------------------------+
| 0 | 0 | 0 | 0 | 0 | 0 | 1 | 0 |
+-------------------------------+
| C | E | U | A | P | R | S | F |
| W | C | R | C | S | S | Y | I |
| R | E | G | K | H | T | N | N |
+-------------------------------+
```

The table indicates that the SYN flag is set. A TCP packet with the SYN flag set tells the server that the client wants to establish a connection.

### Window Size
The next two bytes are the **window size** of the TCP packet. This field tells the server how many bytes it can send the client before it must wait for a response. 

The two bytes in the hex dump are `ff d7`, or 65495 in decimal. 

### Checksum
The following two bytes is the **checksum** field. This number is used to detect any errors that may have occurred during the transmission process. 

In our hex dump, the bytes are `fe 30`, which can be written as 0xFE30. 

### Urgent Pointer
The two bytes after that is the **urgent pointer** field. The value of the bytes in the hex dump are`00 00` or 0 in decimal.

### Options
Now for the most confusing TCP header field, the **options** field. Remember that the value of the data offset field indicates the  TCP packet contains no payload. Therefore, the rest of the bytes in the hex dump make up the options field. Here they are:
```
02 04 ff d7 04 02 08 0a e4 09 db fc 00 00 00 00 
01 03 03 07
```

What do these bytes mean? Before we start to analyze these bytes, it's important to understand that the TCP header options field itself is actually made up of, you guessed it, options. These options may have up to three fields: Option-Kind, Option-Length, and Option-Data. The Option-Kind and Option-Length fields are each 1 byte long, while the Option-Data field has a variable length. Perhaps the most important of these fields is the Option-Kind field. To quote [Wikipedia](https://en.wikipedia.org/wiki/Transmission_Control_Protocol):
> The Option-Kind field indicates the type of option and is the only field that is not optional. Depending on Option-Kind value, the next two fields may be set.

To review:
- The TCP header options field is made up of options.
- Each option can have up to three fields:
	- Option-Kind (1 byte)
	- Option-Length (1 byte)
	- Option-Data (variable)
- The Option-Kind field is mandatory.
- Depending on the value of the Option-Kind field, the next two fields may or may not be set.

I'll use the following table to decode the options field on this TCP header:
![[TCP Header Options Field Table.png]]
[Source](https://en.wikipedia.org/wiki/Transmission_Control_Protocol)

Now let's take a look at the first byte, which is the Option-Kind field for the first option. It has a value of `02`. As you can see in the table above, a value of 2 is for the maximum segment size option. A maximum segment size option includes the Option-Length and Option-Data fields. Therefore, we know that the next field is the Option-Length field. It has a value of `04` which means that this option is made up of 4 bytes. Therefore, the next 2 bytes are the Option-Data field for this option. They have a value of `ff d7`. 0xFFD7 converted to decimal is 65495. This option tells the server that the TCP client is willing to receive 65495 bytes in a single segment.

Moving on, here are the rest of the bytes that we have not yet decoded:
```
04 02 08 0a e4 09 db fc 00 00 00 00 01 03 03 07
```

The first byte is the Option-Kind field for the second option, and has a value of `04`. A value of 4 indicates that [selective acknowledgement](https://en.wikipedia.org/wiki/Transmission_Control_Protocol#Selective_acknowledgments) is permitted for this TCP packet. The following byte is the Option-Length field for this option, and it has a value of `02`. This indicates that the total length of this option is 2 bytes (including the Option-Kind and Option-Length fields). Therefore, the next byte marks the beginning of a new option.

The rest of the bytes are:
```
08 0a e4 09 db fc 00 00 00 00 01 03 03 07
```

The first byte is the Option-Kind field with a value of `08`, or 8 in decimal. 8 means this option is a [TCP timestamp](https://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_timestamps). The next byte `0a` is the Option-Length field for this option, and indicates that the total length of this option is 10 bytes. Therefore the next 8 bytes are the Option-Data field for this option. The first 4 bytes, `e4 09 db fc` (3825851388 in decimal) is the sender timestamp value. The next 4 bytes is the echo reply timestamp. This is the first packet in the transmission, which is why the value of the echo reply timestamp is 0. 

Finishing up, we have the following bytes:
```
01 03 03 07
```

The first byte is the Option-Kind field with a value of `01`. A value of 1 means "no operation", and it's only used as padding. This option does not have an Option-Length or Option-Data field, therefore the next byte is another Option-Kind field. It has a value of `03`. A value of 3 for the Option-Kind field is for [window scaling](https://en.wikipedia.org/wiki/Transmission_Control_Protocol#Window_scaling). The next byte is the Option-Length field for this option, and has a value of `03`, or 3 bytes. This indicates that the following byte is the Option-Data field for this option, with a value of `07`, or 7 in decimal. 

If there were any more bytes in this TCP packet, it would be application data.

## Decoded Packet
We have now successfully decoded the entire first packet. Here's what we found:
- Position in hex dump (byte offset):  40
- Length (in bytes): 74
- Ethernet frame header
	- Destination MAC Address: 00:00:00:00:00:00
	- Source MAC Address: 00:00:00:00:00:00
	- EtherType: 0x0800 (IPv4)
- IPv4 header
	- Version: 4 (IPv4)
	- Internet Header Length (IHL): 5 (20 bytes)
	- DSCP: 0
	- ECN: 0
	- Total Length: 60 bytes
	- Identification: 62169
	- Flags: Don't Fragment (DF)
	- Fragment Offset: 0
	- Time To Live: 64
	- Protocol: 6 (TCP)
	- Header Checksum: 0x49E0
	- Source IP Address: 127.0.0.1
	- Destination IP Address: 127.0.0.1
- TCP header
	- Source port: 55880
	- Destination port: 8000
	- Sequence Number: 3541248033
	- Acknowledgement Number: 0
	- Data Offset: 10 (40 bytes)
	- Reserved: 0
	- Flags: SYN
	- Window Size: 65495 bytes
	- Checksum: 0xFE30
	- Urgent Pointer: 0
	- Options
		- Maximum Segment Size: 65495 bytes
		- Selective Acknowledgement (SACK) permitted
		- Timestamps
			- Sender timestamp: 3825851388
			- Echo reply timestamp: 0
		- No Operation (NOP)
		- Window scale: 7

## HTTP Response Packets
Now that we know how to decode an entire packet from start to finish, I would like to finish this post by showing you how to decode the HTTP response. For the sake of keeping this post relatively short, I will not be going through the entire process of decoding every single packet. I have already showed you how to decode the first packet, so you can do this on your own if you wish. Instead, I have identified which packets in the original capture contain the HTTP response.

From the original capture file, packets number 8 and 10 contain the HTTP response to the original HTTP GET request that we made to the server. Remember that we requested the "password" file, so these packets should contain the contents of that file. 

In the hex dump of the original capture file, packet 8 starts at byte offset 654, and is 266 bytes long. Use the following command to copy the bytes of packet 8 from the original capture into its own file:
```
dd if=capture of=capture_packet8 bs=1 skip=654 count=266 iflag=skip_bytes,count_bytes
```

Here is the hex dump of packet 8:
```
00 00 00 00 00 00 00 00 00 00 00 00 08 00 45 00
00 fc 55 68 40 00 40 06 e6 91 7f 00 00 01 7f 00
00 01 1f 40 da 48 bc 97 ee 22 d3 13 28 3a 80 18
02 00 fe f0 00 00 01 01 08 0a e4 09 f0 1b e4 09
f0 1a 48 54 54 50 2f 31 2e 30 20 32 30 30 20 4f
4b 0d 0a 53 65 72 76 65 72 3a 20 53 69 6d 70 6c
65 48 54 54 50 2f 30 2e 36 20 50 79 74 68 6f 6e
2f 33 2e 31 30 2e 36 0d 0a 44 61 74 65 3a 20 4d
6f 6e 2c 20 32 30 20 4d 61 72 20 32 30 32 33 20
30 34 3a 30 38 3a 35 34 20 47 4d 54 0d 0a 43 6f
6e 74 65 6e 74 2d 74 79 70 65 3a 20 61 70 70 6c
69 63 61 74 69 6f 6e 2f 6f 63 74 65 74 2d 73 74
72 65 61 6d 0d 0a 43 6f 6e 74 65 6e 74 2d 4c 65
6e 67 74 68 3a 20 31 33 0d 0a 4c 61 73 74 2d 4d
6f 64 69 66 69 65 64 3a 20 53 75 6e 2c 20 31 39
20 4d 61 72 20 32 30 32 33 20 31 33 3a 31 36 3a
33 34 20 47 4d 54 0d 0a 0d 0a
```

Packet 10 starts at byte offset 1018, and is 79 bytes long. Use this command to copy packet 10 into its own file:
```
dd if=capture of=capture_packet10 bs=1 skip=1018 count=79 iflag=skip_bytes,count_bytes
```

Here is the hex dump of packet 10:
```
00 00 00 00 00 00 00 00 00 00 00 00 08 00 45 00
00 41 55 69 40 00 40 06 e7 4b 7f 00 00 01 7f 00
00 01 1f 40 da 48 bc 97 ee ea d3 13 28 3a 80 18
02 00 fe 35 00 00 01 01 08 0a e4 09 f0 1b e4 09
f0 1b 6a 41 38 32 36 57 35 41 42 25 64 64 0a
```

You may also download packet 8 [here](https://drive.google.com/file/d/1Yhb5yepD1vncEbcXZB_UegXiM_Kqt_OS/view?usp=share_link), and packet 10 [here](https://drive.google.com/file/d/1Y6gIN1CCohX4DJGdTZAphKE2JVOIiaav/view?usp=share_link). 

Starting with packet 8, I will copy only the application data into its own file:
```
dd if=capture_packet8 of=http_response bs=1 skip=66 count=200 iflag=skip_bytes,count_bytes
```

Now I will do the same for packet 10, appending the data to the file created in the previous command:
```
dd if=capture_packet10 bs=1 skip=66 count=13 iflag=skip_bytes,count_bytes >> http_response
```

The following is the hex dump of the new "http_response" file:
```
48 54 54 50 2f 31 2e 30 20 32 30 30 20 4f 4b 0d
0a 53 65 72 76 65 72 3a 20 53 69 6d 70 6c 65 48
54 54 50 2f 30 2e 36 20 50 79 74 68 6f 6e 2f 33
2e 31 30 2e 36 0d 0a 44 61 74 65 3a 20 4d 6f 6e
2c 20 32 30 20 4d 61 72 20 32 30 32 33 20 30 34
3a 30 38 3a 35 34 20 47 4d 54 0d 0a 43 6f 6e 74
65 6e 74 2d 74 79 70 65 3a 20 61 70 70 6c 69 63
61 74 69 6f 6e 2f 6f 63 74 65 74 2d 73 74 72 65
61 6d 0d 0a 43 6f 6e 74 65 6e 74 2d 4c 65 6e 67
74 68 3a 20 31 33 0d 0a 4c 61 73 74 2d 4d 6f 64
69 66 69 65 64 3a 20 53 75 6e 2c 20 31 39 20 4d
61 72 20 32 30 32 33 20 31 33 3a 31 36 3a 33 34
20 47 4d 54 0d 0a 0d 0a 6a 41 38 32 36 57 35 41
42 25 64 64 0a
```

This hex dump is the entire HTTP response. You can download it [here](https://drive.google.com/file/d/1jmGZg-rr_bPmzuqUIj2QWUu0xI3WoZQi/view?usp=sharing). Let's use the following command to look at the HTTP response:
```
strings -w http_response
```

You should see the following output:
```
HTTP/1.0 200 OK
Server: SimpleHTTP/0.6 Python/3.10.6
Date: Mon, 20 Mar 2023 04:08:54 GMT
Content-type: application/octet-stream
Content-Length: 13
Last-Modified: Sun, 19 Mar 2023 13:16:34 GMT

jA826W5AB%dd

```

That's it! Now you know how to decode captured network packet bytes into something you can actually read and understand.