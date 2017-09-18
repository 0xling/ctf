import requests
import json
import threadpool
import logging
import os
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
targets_ip = ['172.16.0.1', '172.16.0.3', '172.16.0.4', '172.16.0.5', '172.16.0.6', '172.16.0.7',
              '172.16.0.8', '172.16.0.9', '172.16.0.10', '172.16.0.11', '172.16.0.12', '172.16.0.13', '172.16.0.14',
              '172.16.0.15', '172.16.0.16']
problem1_targets = [(ip, 20001) for ip in targets_ip]
problem2_targets = [(ip, 20002) for ip in targets_ip]
problem3_targets = [(ip, 20003) for ip in targets_ip]
problem4_targets = [(ip, 20004) for ip in targets_ip]


def check(flag):
    return True


def submit_flag(flag):
    ee=os.popen('curl http://172.16.200.6:9000/submit_flag/ -d "flag='+flag+'&token='+token+'"')
    print ee.read()
    data = {"flag": flag, "token": token}
    headers = {'Content-type': 'application/json', 'charset': 'utf-8', 'Accept': 'text/plain'}
    if check(flag):
        r = requests.post("http://172.16.200.6:9000/submit_flag", data=data,headers=headers)
        print r.content

if __name__ == '__main__':
    submit_flag('qdzQvMaAsCySfstTderuk85MqC4YdqK2nEjQU7sKuZssTY7DJcTHEEEzFxWt')
