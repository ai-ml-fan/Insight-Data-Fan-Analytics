# Insight-Data-Fan-Analytics
My submission for Insight Data Engineering Test March 30th,2017(03/30/2017)
# Table of Contents
1. [Project Summary](README.md#challenge-summary)
2. [Details of Implementation](README.md#details-of-implementation)
3. [Usage](README.md#usage-summary)
4. [Structure of Program](README.md#structure-of-program)
5. [Feature 1](README.md#feature-1)
6. [Feature 2](README.md#feature-2)
7. [Feature 3](README.md#feature-3)
8. [Feature 4](README.md#feature-4)
9. [Other Features](README.md#other-features)
10. [Repo directory structure](README.md#repo-directory-structure)
11. [Additional Tests](README.md#additional-tests)



# Challenge Summary

The challenge was to picture as a backend engineer for a NASA fan website that generates a large amount of Internet traffic data.  The challenge is to perform basic analytics on the server log file, provide useful metrics, and implement basic security measures. 
The document below elaborates on the features as well as details specific to the implementation as well as any assumptions.

# Details of Implementation

### Program Details :
Program Name : process_log.py
Program Type: Python source

Input Arguments : The python file accepts the path of the input log file as an argument although this is not manadatory.
By default, the code will use ./input/log.txt as input..
Output Arguments : The python file accepts as arguments, the names of the 4 output files that will be created by the program.
The files will be generated as follows:
- the first output will list the 10 most active hosts, 
- the second output file will contain the 10 top busiest 1-hour periods,
- the thirs file lists the 10 most requested resource, as determined by number of requests and size of the resource and 
- lastly the last file lists the log entries flagged as likely threats that should be blocked

The code does not require any mandatory parameters. One or more parameters can be provided as long as they are in order.(the arguments are recognized by position..)

Assumptions : The program does not create directories. It is assumed that the path of the output files exist and execution environment, has the appropriate privileges to write the output to the directories.

### Usage : 

process_log.py followed by one or more arguments in order as shown,

process_log.py [inputfile hostsfile hoursfile resourcesfile blockedfile]
Eg:  ./src/process_log.py ./log_input/log.txt ./log_output/hosts.txt ./log_output/hours.txt ./log_output/resources.txt ./log_output/blocked.txt
Arg  0 ./src/process_log.py

Arg  1 ./log_input/log.txt

Arg  2 ./log_output/hosts.txt

Arg  3 ./log_output/hours.txt

Arg  4 ./log_output/resources.txt

Arg  5 ./log_output/blocked.txt


### Structure of program

The program builds a Dictionary of dictionaries, which are basically Counters for hosts, timestamps and resources. 
Each line is tokenized to identify host, timestamp, resource, size of resource etc. 
The Counters are increased to reflect the new tokens.
For eg., the resource counter will increase the size of the resource requested to reflect the size of data of the last line. 

As the file is analysed, the program outputs the top 10 hosts with most requests. 

The implemented features are described below: 

### Feature 1: 
Lists the top 10 most active host/IP addresses that have accessed the site. 
As the input file is analysed, the program outputs the top 10 hosts with most requests. 

### Feature 2: 

Lists the 10 resources that consume the most bandwidth on the site.
As the input file is analysed, the program outputs the top ten resources sorted by the total requests and the size of data.

### Feature 3:
List the top 10 busiest (or most frequently visited) 60-minute periods 

### Feature 4: 
Detect patterns of three failed login attempts from the same IP address over 20 seconds so that all further attempts to the site can be blocked for 5 minutes. Log those possible security breaches.


### Other Features and optional features
Other enhancements that should be considered,
-    a: Read from streaming log. 
-    b. Added support for multiple input logs. Currently it is possible to add arguments and use the same file to read several input log files.
-    c. Can be extended to take additional arguments for criteria such as all logs in the directory, all logs for the week/month/year etc
-    d. Security : One enhancement for the website is to consider using login/authentication.  Then Push notifications to users when new material is available
-    e. Business Proposition: For top used resources, Consider creating login/authentication. Get email/user ids and  identify  value/premium    option for top users
-   d: Fraud Detection: Look at top valid requests to detect patterns and look for DDOS or DOS style attacks. The most easily executed type of DoS attack is one that is launched from a single origin. In this attack, a single machine somewhere on the Internet issues a barrage of network requests against a targeted victim machine. The requests themselves can take a variety of forms – for example, an  attack might use  HTTP requests against a web server. DDOS is an attack that floods the input channels and from several different sources making it difficult to detect. An authentication for particularly large requests should help mitigate this possibility.

### Repository Directory Structure

### Additional Tests
