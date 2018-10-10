# TCP-EAR

EAD, originally named TCP-EAR (note that this congestion control algorithm is different from [EAR](https://dl.acm.org/citation.cfm?id=3107002) in APNet'17), is developed based on the Linux kernel 4.9.25. Files modified/added:
- ```include/uapi/linux/inet_diag.h```
- ```net/ipv4/tcp_ear.c```
- ```net/ipv4/Kconfig```
- ```net/ipv4/Makefile``` 

## Build the kernel with the patched source
### Configure kernel building option
```
$ sudo make nconfig
```
Note: Need to set tcp-ear option as M or Y
### Clean up before rebuilding
```
$ sudo make-kpkg clean
```
### Compile and build new packages (--verbose for more info)
```
$ sudo time fakeroot make-kpkg --initrd --append-to-version=-SUFFIX kernel-image kernel-headers -j 6
```
Note: Need to replace the SUFFIX with customized name, e.g., -ear
### Install kernel 
```
$ sudo dpkg -i linux-*.deb
```
### List all kernels
```
$ sudo dpkg -l | grep linux-image 
```
### Update grub
```
$ sudo update-grub
```
### Change the "default" kernel in /etc/default/grub then reboot
```
$ sudo reboot
```

## Run the kernel
### Enable TCP-EAR
```
$ sudo sysctl -w net.ipv4.tcp_congestion_control=ear
$ sudo sysctl -w net.ipv4.tcp_ecn=1
$ sudo tc qdisc replace dev ETHn root fq
```
### Reset TCP-EAR parameters
```
$ sudo modinfo tcp_ear
$ sudo modprobe -rf tcp_ear
$ sudo modprobe tcp_ear parameter=value
```
Note: Show module info; Remove old module; Insert new module with customized parameters
