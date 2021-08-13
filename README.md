# loopback

# Installation
## CentOS
```shell
$ yum install libpcap-devel
$ yum install cmake
$ git clone https://github.com/skyno486/loopback.git 
$ cmake CMakeLists.txt
$ make
```
# Getting Started

## Multicast to Unicast
> ./loopback -input udp://{수신받을 멀티캐스트주소}?adapter={수신받을 네트워크 장치 IP} -output udp://{유니캐스트 주소}?adapter={송신할 네트워크 장치IP}

```shell
$ ./loopback -input udp://239.0.0.3:30000?adapter=192.168.1.156 -output udp://10.7.23.33:8888?adapter=127.0.0.1
```


## Network Loopback

> ./loopback -i {수신할 NIC} -o {송신할 NIC}
```shell
$ ./loopback -i eno1 -o lo
```
## Pcap Sender 1

> ./loopback -pcap {PCAP 경로} -o {송신할 NIC}
```shell
./loopback -pcap /root/sample.pcap -o eth1
```

## Pcap Sender 2

> ./loopback -pcap {PCAP 경로} -filter udp://{멀티캐스트 주소} -o {송신할 NIC}
```shell
./loopback -pcap /root/sample.pcap -filter udp://239.0.0.3:34000 -o eth1
```

## Pcap Sender 3

> ./loopback -pcap {PCAP 경로} -filter udp://{필터할 멀티캐스트주소} -o {송신할 NIC} -output udp://{멀티캐스트주소}
```shell
./loopback -pcap /root/sample.pcap -filter udp://239.0.0.3:34000 -o eth1 -output udp://239.0.0.3:30000
```
