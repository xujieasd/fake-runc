## FAKE RUNC (runc 山寨版)

### 目前基本具备的功能

- UTS isolation
- IPC isolation
- PID isolation
- NETWORK isolation
- MOUNT isolation

### How to run fake-runc

1. setup a rootfs

```
$ sudo su
$ mkdir /tmp/ubuntu
$ cd /tmp/ubuntu/
$ docker export $(docker create ubuntu:14.04) > ubuntu.tar
$ mkdir rootfs
$ tar -C rootfs -xf ubuntu.tar
```

> you can also build up your own fake rootfs
```
$ sudo su
$ mkdir /tmp/ubuntu
$ cd /tmp/ubuntu/
$ mkdir rootfs
$ cd rootfs
$ cp /bin . -rf
$ cp /lib . -rf
$ cp /lib64 . -rf
$ cp /usr . -rf
$ cp /sbin . -rf
$ cp /etc . -rf
$ mkdir ./dev
$ mkdir ./proc
```

2. pull code and make fake-runc

```
$ cd to your project folder
$ git clone ssh://git@gitlab.cloud.enndata.cn:10885/xujieasd/fake-runc.git
$ make
```

3. run container

```
$ sudo ./fake-runc
```

> if run fake-runc failed at pivot root step, maybe because you have shared mount points  
> run "grep -iP '/ /\s' /proc/$$/mountinfo" to see if there is shared info  
> run "unshare -m" to unshare mounts namespace, or pivot will not work  

e.g
```
root@dai-Precision-Tower-3620:/home/dai/go/src/fake-runc# ./fake-runc 
this is parent, host name is:dai-Precision-Tower-3620
device enn0 already exists; can't create bridge with the same name
this is parent, child pid is:14658, parent pid id is:14652
this is child container, pid is:1, parent id is:0
container host name is:MyContainer
path: /tmp/ubuntu/rootfs/proc
path: /tmp/ubuntu/rootfs/sys
path: /tmp/ubuntu/rootfs/dev/mqueue
path: /tmp/ubuntu/rootfs/dev
path: /tmp/ubuntu/rootfs/dev/pts
path: /tmp/ubuntu/rootfs/dev/shm
putold path: /tmp/ubuntu/rootfs/putold
root@MyContainer:/# 

```

then you can run cmd like ps,top,mount,ip to see what happens