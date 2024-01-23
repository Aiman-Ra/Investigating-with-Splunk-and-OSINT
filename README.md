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
Now that we've confirmed the attacker was scanning the website, let's take a look at how they tried to exploit it. The `URL` field contains multiple entries regarding Joomla CMS admin signin page.
<br>

<img src= "https://i.imgur.com/aNcdj9r.png">

To further validate our suspicions let's create a table of the POST requests sent to the admin page while showing the source and destination IP address as well as the time to get a clearer picture:
```
index=botsv1 imreallynotbatman.com sourcetype=stream:http http_method=POST uri="/joomla/administrator/index.php" | table _time uri src_ip dest_ip form_data
```
<img src= "https://i.imgur.com/s2EGRqA.png">

As we can see, the attacker has used the other IP address found in our first search query to make multiple attempts at logging in with the username `admin`. Additionally, the time stamps reveal the attacker was using an automated tool to brute force their way in.


<h1> </h1>


Weaponization
Delivery
Installation
Command & Control
Actions on Objectives



