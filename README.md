# Hybrid system for phishing website detection
#### Video Demo:  <URL HERE>
#### Description:
This project is a web app that utilizes third-party libraries to analyse URL to find out whether it resembles any malicious patterns. 

The app offers 3 components:

Component 1: URl analysis
- async JS function implemented that sends input url to Google Safe Brousing API 

Component 2: DOM analysis
- if entered URL is not bleaklisted by Google Safe Brousing API a series of DOM elements analysis is performed to determine a phisnhing score and make a decision whether the website is malicious (threshold is adjustable in app.py)

Component 3: Heuristics
- if entered URL is not bleaklisted by Google Safe Brousing API a series of DOM elements analysis is performed alongside requests made to third-party resources to retrieve domain specific information to determine a phisnhing score and make a decision whether the website is malicious (threshold is adjustable in app.py)

Average running time for Components 2 and 3 are about 10 seconds. When information retrieval or processing was not sucessful - the check fails and is treated as phishing pattern just in case. 

Author can be reached via email dima.shutenko@knu.ua or dima.shutenko.official@gmail.com