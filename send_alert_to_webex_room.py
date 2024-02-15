'''
    send alert to webex alert room
'''
import requests
import sys, os
from crayons import *
import json
import socket

ROOM_ID=""
ACCESS_TOKEN=""
URL = 'https://webexapis.com/v1/messages'
alert_message="Ransomware activity had been detected on honeypot"

def read_targets():
    target_list=[]
    objet={"title": socket.gethostname(),"value": socket.gethostname()}
    target_list.append(objet)    
    return(target_list)
    
def read_observables(file):
    with open(file,'r') as file:
        text_content=file.read();
    list=text_content.split('\n')
    observable_list=[]
    for item in list:
        ip=item.split(';')[0]
        objet={"title": ip,"value": ip}
        observable_list.append(objet)  
    return(observable_list)    
    
    
def load_card_and_send_it(cards_content,ACCESS_TOKEN,ROOM_ID):
    print()
    print('BOT_ACCESS_TOKEN : ',ACCESS_TOKEN)
    print('ALERT ROOM ID : ',ROOM_ID)
    print()
    headers = {'Authorization': 'Bearer ' + ACCESS_TOKEN,
               'Content-type': 'application/json;charset=utf-8'}
    print(cyan(cards_content))
    attachment={
    "roomId": ROOM_ID,
    "markdown": "!  RANSOMWARE ALERT !",
    "attachments": cards_content
    }
    response = requests.post(URL, json=attachment,headers=headers)
    if response.status_code == 200:
        # Great your message was posted!
        #message_id = response.json['id']
        #message_text = response.json['text']
        print("New message created")
        #print(message_text)
        print("====================")
        print(response)
    else:
        # Oops something went wrong...  Better do something about it.
        print(response.status_code, response.text)

def create_card_content(alert_message):
    targets=read_targets()
    cards_content=[
        {
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {    
                "type": "AdaptiveCard",
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "version": "1.3",
                "backgroundImage": {
                    "url": "https://i.postimg.cc/vBxnRp06/sky2.jpg",
                    "verticalAlignment": "Center"
                },             
                "id": "title",
                "body": [
                    {
                        "type": "TextBlock",
                        "text": "! RANSOMWARE ALERT !",
                        "color": "Attention",
                        "weight": "Bolder",
                        "size": "ExtraLarge",                        
                        "horizontalAlignment": "Center"
                    },
                    {
                        "type": "Container",
                        "items": [
                            {
                                "type": "TextBlock",
                                "text": alert_message,
                                "wrap": True,
                                "color": "Attention",
                                "horizontalAlignment": "Center"
                            }
                        ]
                    }                   
                ],
                "actions": [
                    {
                        "type": "Action.ShowCard",
                        "title": "Targeted Systems",
                        "card": {
                            "type": "AdaptiveCard",
                            "body": [
                                {
                                    "type": "TextBlock",
                                    "text": "Select Systems to isolate",
                                    "color": "Warning",
                                    "size": "Medium",
                                    "wrap": True
                                },
                                {
                                    "type": "Input.ChoiceSet",
                                    "id": "systems",
                                    "style": "expanded",
                                    "isMultiSelect": True,
                                    "choices": targets
                                },
                                {
                                    "type": "TextBlock",
                                    "text": "Isolate in ? :",
                                    "color": "Warning",
                                    "size": "Medium",
                                    "wrap": True
                                },                               
                                {
                                    "type": "Input.ChoiceSet",
                                    "id": "isolation_points", 
                                    "isMultiSelect": True,
                                    "style": "compact",
                                    "choices": [
                                        {
                                            "title": "Isolate in ISE",
                                            "value": "ISE"
                                        },
                                        {
                                            "title": "Isolate in Secure Endpoint",
                                            "value": "CSE"
                                        },
                                        {
                                            "title": "Block in Firewalls",
                                            "value": "FW"
                                        }
                                    ],
                                    "placeholder": "Isolate in ? :"
                                }
                            ],
                            "actions": [
                                {
                                    "type": "Action.Submit",
                                    "title": "Isolate Selected Systems",
                                    "data": {
                                        "systems_to_isolate": "Targeted Systems"
                                    }
                                }
                            ],
                            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json"
                        }
                    },
                    {
                        "type": "Action.ShowCard",
                        "title": "INVESTIGATE",
                        "card": {
                            "type": "AdaptiveCard",
                            "body": [
                                {
                                    "type": "TextBlock",
                                    "text": "INVESTIGATE",
                                    "color": "Warning",
                                    "size": "Medium",
                                    "wrap": True
                                }                             
                            ],
                            "actions": [
                                {
                                    "type": "Action.Submit",
                                    "title": "Start Investigation",
                                    "horizontalAlignment": "Center",
                                    "data": {
                                        "objects_to_block": "Suspicious observables"
                                    }
                                }
                            ],
                            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json"
                        }
                    }                
                ]          
            }
        }
    ]    
    return(cards_content)
        
#if __name__=="__main__":
def send_alert(ACCESS_TOKEN,ROOM_ID):
    card_content=create_card_content(alert_message)
    load_card_and_send_it(card_content,ACCESS_TOKEN,ROOM_ID)