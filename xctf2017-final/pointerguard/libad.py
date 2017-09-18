import requests
import json
import logging

'''
token = "NxArhGPKLMmen9Y9QPePHSBbFqQPiqnU"
team_login_url = "http://172.16.201.8"  # secret="ZeGZsrb73kT2Wa1w"
problem_port = [20001, 20002, 20003, 20004]
pcap_path = "/home/xctf/packages/"
problem_machine_username = "xctf"  # get from team_login_url : ip,skey,token
each_problem_machine = ["172.16.2.101", "172.16.2.102", "172.16.2.103", "172.16.2.104"]
nat_ip = "172.16.0.2"  # gateway 172.16.0.254
'''

token = "25s6cRXSQeBHJD9fd84a6QnJuzbJBwhE7yjfS6vkFyjfqMU3nTxgjJGNGFAZ1j9brcZ7GYRHrzX"
targets_ip = ['172.16.1.101', '172.16.16.101', '172.16.3.101', '172.16.4.101', '172.16.5.101',
              '172.16.6.101', '172.16.7.101', '172.16.8.101', '172.16.9.101', '172.16.10.101', '172.16.11.101', '172.16.12.101',
              '172.16.13.101', '172.16.14.101', '172.16.15.101']

problem1_targets = [(ip, 20001) for ip in targets_ip]
problem2_targets = [(ip, 20002) for ip in targets_ip]
problem3_targets = [(ip, 20003) for ip in targets_ip]
problem4_targets = [(ip, 20004) for ip in targets_ip]


def check(flag):
    return True

import os
def submit_flag(flag):
    ee=os.popen('curl http://172.16.200.6:9000/submit_flag/ -d "flag='+flag+'&token='+token+'"')
    print ee.read()
    data = {"flag": flag, "token": token}
    headers = {'Content-type': 'application/json', 'charset': 'utf-8', 'Accept': 'text/plain'}
    #if check(flag):
    #    r = requests.post("http://172.16.200.6:9000/submit_flag", data=data,headers=headers)
    #    print r.content

