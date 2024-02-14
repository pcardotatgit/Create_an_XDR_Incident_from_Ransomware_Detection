# Create an XDR Incident from Ransomware Detection into a windows machine

This script doesn't block ransomwares but it detects result of ransomware activities and send an alert into an alert Webex Room.

The principle is very simple. It is very difficult to anticipate new ransomwares, What they will be and what they will exactly execute within an infected system.

But we already know at 100 % what the result of their activities.

The goal of ransomwares is to encrypt every documents contained into an hard drive or into a shared folder. 
And encrypted files will be mainly office documents ( users documents ).

Based on that fact, the idea is to setup an honeypot workstation and expose this one in order to let it be infected if it is discovered.  And store into a monitored directory into this honeypot some documents and check constantly if something modify them.

And if ever these files are modified, then instantly send an alert. 

Check if one of these files is modified and send an alert in order to warn the Security Team. Then  let the team to trigger additionnal Investigation to confirm the ransomware attack.

This is exactly what does this script. It is based on the watchdog python library. 

This library is absolutely awesome for our goal and for the application efficiency.

Actually thanks to watchdog, we can run permanently in the application in the background. It consume very few cpu resources. Then it will be able to react in real time if any change happens into a monitored directory and it's subdirectories.

So the assumption is as the application is installed into an honeypot. So the monitored files are not supposed to change at all. And if they change, then we are sure at 100 % that we face to a malicious activity.

## Pre requisit

You must have a webex bot and an alert webex room that will receive the alerts.

## Installation

This script requires the following python modules

- watchdog
- requests
- crayons

Edit the **config.py** file and set the correct values to the **webex_bot_token** and **webex_room_id**.

Set the **src_path** variable to indicate the root path of the directory tree you want to monitor.

By default the application will monitor every files contained into the monitored directory tree. But you filter some file types like office documents and event a specific file to monitor. Modify the **file_types** for this.

You are ready to go

## Run and test the application

Run the application :

    python 1-monitor_files_into_monitored_directory.py
    
Then go to the monitored directory and do operations on stored file.  Create , delete, rename edit modify and save. All thes operations will trigger an alert into Webex.

## Convert the python script to a windows executable

This script disearves to be converted into an exe.  That could be very handy for installing it quickly into windows machines you want to use as honeypots. And make the application start at boot.

The application is very light in terms of CPU consumption, which make it an application to run into a production user's windows machine, as a Real Time ransomware detector.

Here is very quickly instruction for converting the python script into an exe.

IN CONSTRUCTION

## What next ? - connect this script to XDR

A relevant next step to this project is to connect it to XDR Automation.

- Add indepth Investigation action in order to understan indepth what the ransomware does into the system
- Create a documented incident into xdr
- Trigger some response actions like critical host isolations and preventive snapshots of critical systems
