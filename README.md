# DumpNParse
DumpNParse is a tool designed to dump and parse LSASS using a single file. It is a combination of [@slyd0g's](https://github.com/slyd0g) [C# LSASS Dumper](https://github.com/slyd0g/C-Sharp-Out-Minidump) and [@cube0x0's](https://github.com/cube0x0) [C# LSASS Parser](https://github.com/cube0x0/MiniDump), so they deserve all credit for this creation. Thank you both!

Simply compile the exe, drop it into a folder which you have write access to, and execute! The program will write the dump to the current folder, parse it, and delete the dump once complete.

Tested and Confirmed Working on:
* Windows 10 20H2 (10.0.19042)
* Windows Server 2019 (10.0.17763)

![alt text](https://i.imgur.com/5Ek6IkQ.gif)
