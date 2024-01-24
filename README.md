<h1>Investigating With Splunk</h1>


<h2>Description</h2>

In this lab we'll be using Splunk to investigate a website that has been defaced. We'll be looking at what and how to search for IOCs.


<h2>Utilities Used</h2>

- <b>Splunk</b>
- <b>OSINT</b>

<h2>Environments Used</h2>

- <b>Ubuntu 22.04 LTS</b>

## Program Walk-through

There are many ways to investigate a security incident, we'll be using the Cyber Kill Chain model and try to trace the attacker's steps. The model includes 7 stages:

### Reconnaissance
First we have to think like the attacker, how would they begin to gather information so they're able to exploit any vulnerabilities they find? The website in question is ` imreallynotbatman.com`, let's start by figuring out the IP addresses and systems/tools being used, the http stream will make this easier for us:
```
index=botsv1 imreallynotbatman.com sourcetype=stream:http
```

<img src= "https://i.imgur.com/IlskdNk.png">

This results in over 22k events of which 17k are from 1 IP address `40.80.148.42`, so let's focus our search on it to see if we can find anything more suspicious. Fields such as `URI` and `POST Requests` can reveal vital information in cases like this:

```
index=botsv1 imreallynotbatman.com sourcetype="stream:http" src_ip="40.80.148.42"
```
<img src= "https://i.imgur.com/HKZhlHM.png">

Immediatley we can see a couple of red flags such as `/windows/win.ini` which is commonly used in directory traversal tactics. Thankfully, our client has Suricata installed, so we can view its logs to see if any alert was triggered and validate our suspicions:

```
index=botsv1 imreallynotbatman.com src=40.80.148.42 sourcetype=suricata
```
<img src= "https://i.imgur.com/kMiYWHl.png">

Sure enough, multiple alerts have been triggered. Upon inspecting them, it appears the attacker is using Acunetix which is a web vulnerability scanner.
<br>

<img src= "https://i.ibb.co/1f9MdnK/cve.png">

<h1> </h1>

### Exploitation
Now that we've confirmed the attacker was scanning the website, let's take a look at how they tried to exploit it. The `URL` field contains multiple entries regarding Joomla's CMS admin signin page:
<br>

<img src= "https://i.imgur.com/aNcdj9r.png">

To further validate our suspicions let's create a table of the POST requests sent to the admin page while showing the source and destination IP address as well as the time to get a clearer picture:
```
index=botsv1 imreallynotbatman.com sourcetype=stream:http http_method=POST uri="/joomla/administrator/index.php" | table _time uri src_ip dest_ip form_data
```
<img src= "https://i.imgur.com/s2EGRqA.png">

As we can see, the attacker has used the other IP address found in our first search query to make multiple attempts at logging in with the username `admin`. Additionally, the timestamps reveal the attacker was using an automated tool to brute force their way in.
<br>


#### Using Regex to Extract Passwords and Usernames
Splunk has a function called `Rex` that can do regular experession. If you type it in the search bar it'll show you some suggestions on how you can use it. In our case we want to extract the credentials:
```
index=botsv1 imreallynotbatman.com sourcetype=stream:http http_method=POST form_data=*username*passwd* | rex field=form_data "passwd=(?<creds>\w+)"  | table _time src_ip uri creds
```
<img src= "https://i.imgur.com/KMwvX11.png">

Next let's try to find out what tools the attacker used to start this communication. Simply adding  `http_user_agent` to the query should accomplish this:
```
index=botsv1 imreallynotbatman.com sourcetype=stream:http http_method=POST form_data=*username*passwd* | rex field=form_data "passwd=(?<creds>\w+)"  | table _time src_ip uri creds http_user_agent
```
<img src= "https://i.imgur.com/lipaEWU.png">

It appears the attacker brute-forced the credentials with Python and once they found the correct password, proceeded to login normally through the Mozzila browser.


<h1> </h1>


### Installation
When an attacker exploits a system they usually try to install a backdoor for presistence. In this phase we'll look for any malicious applications that might've been installed on the compromised server:
```
index=botsv1 dest_ip="192.168.250.70" sourcetype=stream:http *.exe
```
<img src= "https://i.imgur.com/4zPNNsM.png">
<br>

Looking at the interesting fields on the left, there's a new one called `part_filename{}` that contains 2 entries `3791.exe` and `agent.php`. If we dig further into them we can see that they've been uploaded from the same IP address the attacker used:
<br>

<img src= "https://i.imgur.com/CyphOV6.png">
<br>

Next we must know if this file was executed on the server. We can utlize Sysmon and look up `Eventcode=1` which stands for process creation:
```
index=botsv1 "3791.exe" EventCode=1
```
<img src= "https://i.imgur.com/n9H7M3I.png">
<br>

Sysmon also captures a file's hash value. We can utlize OSINT such as VirusTotal to see if the file is indeed malicous and what it does:
<br>

<img src= "https://i.imgur.com/7SkijNq.png">
<br>




<h1> </h1>

### Actions on Objectives
Now that we know the file has been executed on the compromised server, it's time to figure out the attacker's objective. One way to do this, is to look at the outgoing traffic from the server, because usally it's the client/browser that initiate communication with a webserver:
```
index=botsv1 src=192.168.250.70 sourcetype=suricata
```
<img src= "https://i.imgur.com/u5MRJoj.png">
<br>

The same IP addresses show up again with a large amount of traffic going to them. Let's focus on 1 of those IP addresses to see what's included in that traffic:
```
index=botsv1 src=192.168.250.70 dest_ip=23.22.63.114 sourcetype=suricata 
```
<img src= "https://i.imgur.com/6Ll3pcd.png">
<br>

This results in 3 files in `url` field. The jpg 1 looks interesting so let's create a table to see where it originated from:
```
index=botsv1 url="/poisonivy-is-coming-for-you-batman.jpeg" dest_ip="192.168.250.70" | table _time src dest_ip http.hostname url
```
<img src= "https://i.imgur.com/Y9fBB7Z.png">
<br>


<h1> </h1>

### Command & Control
The attacker uploaded a file from their host into the victim's server before defacing it, we can use that to figure out their FQDN. Fortigate's logs will make this easier for us:
```
index=botsv1 sourcetype=fortigate_utm"poisonivy-is-coming-for-you-batman.jpeg
```





<h1> </h1>

Delivery
Weaponization





