# PacketAnalyzer
Linux daemon to capture and analyze network packets

## Dependencies
Requires [libcap](https://www.tcpdump.org/)

## Usage
Compile
```
make
```

The analyzer will start capturing packets in the application folder, in the file log.txt

Display available interfaces an select one to analyze
```
sudo ./analyzer init
```

Start the analyzer in an specific interface 
```
sudo ./analyzer start [interface]
```

Stop the analyzer
```
sudo ./analyzer stop
```