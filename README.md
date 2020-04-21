# net

**#Network Exploitation Tool** 
1. Packet Crafting and Dissecting
2. Sending and Sniffing Raw Packets
3. Attacks for Manipulating Network
<br>

**#How To Install for Developers**
```
1. git clone https://github.com/Rohan131293/net.git
2. sudo apt install python-pip 
3. sudo pip install virtualenv
4. cd net/virtEnv 
5. python -m virtualenv virtEnv2.7
6. source virtEnv2.7/bin/activate
7. pip install -r requirements.txt
8. cd ..
9. pip install -e .
10. python

Note: For python3 follow the similar steps. 
```

**#Creating distributable pip package**
```
python setup.py develop -u
python setup.py sdist
```

**#To get out of virtual environment**
```
deactivate
```
