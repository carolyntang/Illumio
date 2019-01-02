# Illumio
Coding Challenge, PCE team

# Language Used
Python 2.7

# Files included
1. Firewall.py: a python file contains functions to solve the challenge
2. input.csv: a csv file contains a list of firewall rules to test the code in Firewall.py

# How to test the solution
1. download both files on your laptop or computer and make sure they are on the same directory or folder
2. open terminal on your laptop 
3. cd to the directory where contains both files
4. type "python Firewall.py" in the terminal to run the Firewall.py file
To change or modify the input rules, just simply open the input.csv file and add more rules in the list
To test more requests than the given ones in the pdf file, open the Firewall.py file and add fw.accept_packet calls in the end of the file

# Coding/Design decisions made
1. I divided all the rules into four categories based on their protocol types and directions
2. I also used four sorted hash maps to store those four categories: port range as the key, and the ip range as the value 
3. The port range will be checked first, then the ip addresses since the number of ports are less than the number of possible ip addresses
4. When a new request is evaluated by calling accept_packet function, the ip address are converted into int for comparison 
5. Multiple helper functions are created to make the program more modularized
6. Bit shift is used in the code

# Improvement for the future
1. If I have more time, I will used are more sophisticated data structure to store the set of rules

# More info
1. In my opinion, this is a very interesting problem to solve and work on, I would like to know how the Illumio engineers will solve the problem, what kind of design decisions you will make. Moreover, what kind of network plug-ins or security APIs you would use to implement the firewall.

# Teams interested
Rank #1. Platform team: I am interested in learning how to build software with open source. I am currently working on a project with an open source community. In addition, I think the projects are very interesting and I would like to work on solving those problems.

Rank #2. Data team: I am interested in the data-driven projects and I have some experiences working on data analysis projects. 
