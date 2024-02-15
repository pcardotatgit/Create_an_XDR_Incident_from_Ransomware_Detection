'''
    monitor files into a monitored directory and it's subdirectories and alert if any changes occur on files
    - File creation
    - File deletion
    - File modification / renaming
    - File move
'''
# pip install watchdog
# pip install requests
# pip install crayons
import watchdog.events
import watchdog.observers
import time
from send_alert_to_webex_room import send_alert
from create_XDR_incident import go_for_incident
from crayons import *
import socket
#import config as conf
import sys

src_path = r"C:/Users/patrick/Documents/Office_Documents" # ex : C://Users/jdoe/watched_directory or ./watched_directory
file_types=['*.*'] #   ex : ['*.txt','*.jpg','*.docx']
# here under if you ever want the script to send Webex alerts
ACCESS_TOKEN=""
ROOM_ID=""

targets=[
  {
    "type": "endpoint",
    "observables": [
      {
        "value": "DESKTOP-U034FK0",
        "type": "hostname"
      },
      {
        "value": "10.0.0.2",
        "type": "ip"
      },
      {
        "value": "00:E1:6D:26:24:E9",
        "type": "mac_address"
      }
    ],
    "observed_time": {
      "start_time": "2023-09-09T13:31:02.000Z",
      "end_time": "2023-09-09T13:31:02.000Z"
    }
  }
]    
    
def get_targets():
    target_list=[]
    objet={"value": socket.gethostname()}
    target_list.append(objet)    
    return(target_list) 
    
def create_json_observables(ip_list,ip_target): 
    observables=[]
    relationships=[]
    observable_item={'type':'hostname','value':ip_target[0]["value"]}
    observables.append(observable_item)     
    for item in ip_list:   
        observable_item={'type':'file_name','value':item}
        observables.append(observable_item)
        relationship_item={
          "origin": "XDR Demo Detection",
          "origin_uri": "https://localhost:4000/",
          "relation": "Connected_To",
          "source": {
            "value":item,
            "type":"file_name" 
          },
          "related": {
            "value":ip_target[0]["value"], # in our demo we only have one target
            "type":"hostname"          
          }
        }
        relationships.append(relationship_item)
    print('observables : ',green(observables,bold=True))  
    print('relationships : ',green(relationships,bold=True))
    return observables,relationships    
    
class Handler(watchdog.events.PatternMatchingEventHandler):
    def __init__(self):
        # Set the patterns for PatternMatchingEventHandler
        watchdog.events.PatternMatchingEventHandler.__init__(self, patterns=file_types,ignore_directories=True, case_sensitive=False)
 
    def on_created(self, event):
        print("Watchdog received created event - % s." % event.src_path)
        # Event is created, you can process it now
 
    def on_modified(self, event):
        print("Watchdog received modified event - % s." % event.src_path)
        #send_alert(ACCESS_TOKEN,ROOM_ID)
        ip_list=[]
        ip_list.append('php-cgi.exe')      
        target_list=get_targets()
        title='Ransomware infection on honeypot by '
        observables_objects,observable_relationships=create_json_observables(ip_list,target_list)        
        go_for_incident(observables_objects,targets,observable_relationships,title)
        # Event is modified, you can process it now
        
    def on_deleted(self, event):
        print("Watchdog received deleted event - % s." % event.src_path)
        # Event is modified, you can process it now
   
 
if __name__ == "__main__":
    event_handler = Handler()
    observer = watchdog.observers.Observer()
    observer.schedule(event_handler, path=src_path, recursive=True)
    observer.start()
    print()
    print(green(f"ACTIVE RANSOMWARE MONITORING STARTED ON DIRECTORY : {src_path}",bold=True))
    print()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
