# Insight-Data-Fan-Analytics
My submission for Insight Data Engineering Test March 30th,2017(03/30/2017)
# Table of Contents
1. [Project Summary](README.md#challenge-summary)
2. [Details of Implementation](README.md#details-of-implementation)
3. [Download Data](README.md#download-data)
4. [Description of Data](README.md#description-of-data)
5. [Writing clean, scalable, and well-tested code](README.md#writing-clean-scalable-and-well-tested-code)
6. [Repo directory structure](README.md#repo-directory-structure)
7. [Testing your directory structure and output format](README.md#testing-your-directory-structure-and-output-format)
8. [Instructions to submit your solution](README.md#instructions-to-submit-your-solution)
9. [FAQ](README.md#faq)


# Challenge Summary

The challenge was to picture as a backend engineer for a NASA fan website that generates a large amount of Internet traffic data.  The challenge is to perform basic analytics on the server log file, provide useful metrics, and implement basic security measures. 
The document below elaborates on the features as well as details specific to the implementation as well as any assumptions.
The implemented features are described below: 

### Feature 1: 
List the top 10 most active host/IP addresses that have accessed the site.

### Feature 2: 
Identify the 10 resources that consume the most bandwidth on the site

### Feature 3:
List the top 10 busiest (or most frequently visited) 60-minute periods 

### Feature 4: 
Detect patterns of three failed login attempts from the same IP address over 20 seconds so that all further attempts to the site can be blocked for 5 minutes. Log those possible security breaches.


### Other considerations and optional features
It's critical that these features don't take too long to run. For example, if it took too long to detect three failed login attempts, further traffic from the same IP address couldn’t be blocked immediately, and that would present a security breach.
This dataset is inspired by real NASA web traffic, which is very similar to server logs from e-commerce and other sites. Monitoring web traffic and providing these analytics is a real business need, but it’s not the only thing you can do with the data. Feel free to implement additional features that you think might be useful.
