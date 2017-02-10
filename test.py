#!/usr/bin/env python

import requests
import json

payload = [{
        'byteSize': 4096,
        'destination': '192.168.0.2',
        'destinationPort': 80,
        'source': '192.168.0.1',
        'sourcePort': 34567,
        'flags': 20,
        'lastTimeStampSecs':1364302870,
        'startTimeStampSecs':1364302800,
        'packetCount': 45,
        'protocol': 6
    }, {
        'byteSize': 48000,
        'destination': '192.168.0.1',
        'destinationPort': 34567,
        'source': '192.168.0.2',
        'sourcePort': 80,
        'flags': 20,
        'lastTimeStampSecs':1364302870,
        'startTimeStampSecs':1364302800,
        'packetCount': 45,
        'protocol': 6
    }, {
        'byteSize': 4096,
        'destination': '192.168.0.3',
        'destinationPort': 443,
        'source': '192.168.0.4',
        'sourcePort': 60000,
        'flags': 20,
        'lastTimeStampSecs':1364302870,
        'startTimeStampSecs':1364302800,
        'packetCount': 45,
        'protocol': 6
    }, {
        'byteSize': 48000,
        'destination': '192.168.0.4',
        'destinationPort': 60000,
        'source': '192.168.0.3',
        'sourcePort': 443,
        'flags': 20,
        'lastTimeStampSecs':1364302870,
        'startTimeStampSecs':1364302800,
        'packetCount': 45,
        'protocol': 6
    }]
    
headers = {'content-type': 'application/json'}

response = requests.put('http://localhost:8080/flow/', data=json.dumps(payload), headers=headers)

print response.text