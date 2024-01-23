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

This results in over 22k events of which 17k are from 1 IP address `40.80.148.42`, so let's focus ours search on it to see if we can find anything more suspicious. Fields such as `URI_path` and `POST Requests` can reveal vital information in cases like this:

```
index=botsv1 imreallynotbatman.com sourcetype="stream:http" src_ip="40.80.148.42"
```
<img src= "https://i.imgur.com/vOusn4M.png">

Immediatley we can see a few things that stand out to us such as `/windows/win.ini` which is commonly used in directory traversal tactics. Thankfully, our client has Suricata installed, so we can view its logs to see if any alert was triggered and validate our suspicions:

```
index=botsv1 imreallynotbatman.com src=40.80.148.42 sourcetype=suricata
```


<h1> </h1>
Weaponization
Delivery
Exploitation
Installation
Command & Control
Actions on Objectives



