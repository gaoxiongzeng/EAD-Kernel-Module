# TCP-EAR

TCP-EAR is developed based on the Linux kernel 4.9.25. Files modified/added: <br />
-include/uapi/linux/inet_diag.h <br />
-net/ipv4/tcp_ear.c <br />
-net/ipv4/Kconfig <br />
-net/ipv4/Makefile 

## Building the kernel with the patched source
### Config kernel building option
$sudo make nconfig / sudo make menuconfig <br />
Note: Need to set tcp-ear option as M or Y
### Clean up before rebuilding
$sudo make-kpkg clean
### Compiling and building new packages (--verbose for more info)
$sudo time fakeroot make-kpkg --initrd --append-to-version=-SUFFIX kernel-image kernel-headers -j 6 <br />
Note: Need to replace the SUFFIX with customized name, e.g., -ear
### Install kernel 
$sudo dpkg -i linux-*.deb
### List all kernels
$sudo dpkg -l | grep linux-image 
### Update grub or grub2
$sudo update-grub / sudo update-grub2
### Change the "default" kernel in /etc/default/grub then reboot
$sudo reboot

## Running the kernel
### Enable TCP-EAR
$sudo sysctl -w net.ipv4.tcp_congestion_control=ear <br />
$sudo sysctl -w net.ipv4.tcp_ecn=1
### Reset TCP-EAR parameters
$sudo modinfo tcp_ear <br />
$sudo modprobe -rf tcp_ear <br />
$sudo modprobe tcp_ear parameter=value <br />
Note: Show module info; Remove old module; Insert new module with customized parameters
