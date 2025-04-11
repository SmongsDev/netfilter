## required environment

### iptable
```
sudo iptables -F
sudo iptables -A OUTPUT -j NFQUEUE --queue-num 0
sudo iptables -A INPUT -j NFQUEUE --queue-num 0
```

### gcc
```
gcc -o netfilter netfilter.c -lnetfilter_queue
```


### excute
```
sudo ./netfilter.c <host>
```
