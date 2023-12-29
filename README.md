# Totally Insecure Web Application Project (TIWAP)

![Forks](https://img.shields.io/github/forks/tombstoneghost/TIWAP?style=for-the-badge)
![Stars](https://img.shields.io/github/stars/tombstoneghost/TIWAP?style=for-the-badge)
![OpenIssues](https://img.shields.io/github/issues/tombstoneghost/TIWAP?style=for-the-badge)
![ClosedIssues](https://img.shields.io/github/issues-closed/tombstoneghost/TIWAP?style=for-the-badge)
![Languages](https://img.shields.io/github/languages/count/tombstoneghost/TIWAP?style=for-the-badge)
![License](https://img.shields.io/github/license/tombstoneghost/TIWAP?style=for-the-badge)



TIWAP is a web security testing lab made using Flask for budding security enthusiasts to learn about various web 
vulnerabilities. Inspired by DVWA, the contributors have tried their best to regenerate various web vulnerabilities

The application is solely made for educational purpose and to learn web hacking in a legal environment. 

Read more about it [here](https://singh-simardeepsingh99.medium.com/tiwap-3a8b70043ce9)

## Disclaimer

We highly recommend installing the lab on a Virtual Machine instead of a live web server (Internal or External).

We do not take responsibility for the way in which anyone uses this application (TIWAP). 
The application has been made for educational purpose only and should not be used maliciously. 
If your web servers are compromised due to installation of this application, 
it is not our responsibility, it is the responsibility of the person/s who uploaded and installed it.


## Setup and Installation
To keep the installation and setup easy, we have configured everything for you. All you need is Docker on your system.

Once you are done with docker installation, run the following commands. 

> git clone https://github.com/tombstoneghost/TIWAP <br/>
> cd TIWAP <br/>
> docker-compose up

<strong>Note: It works only on Linux as of now and windows compatibility is work under progress </strong>

Once the lab is started, you can log in using the default credentials.<br/>
Username: `admin` <br/>
Password: `admin`

## Tech Stack

Front-End: HTML, CSS and JavaScript <br/>
Back-End: Python - Flask <br/>
Databases: SQLite3 and MongoDB

## Vulnerabilities

Currently, we have 22 vulnerabilities in the lab. All listed below:

- SQL Injection
- Blind SQL Injection
- NoSQL Injection
- Command Injection
- Business Logic Flaw
- Sensitive Data Exposure
- XML External Entities
- Security Misconfiguration
- Reflected XSS
- Stored XSS
- DOM Based XSS
- HTML Injection
- Improper Certificate Validation
- Hardcoded Credentials
- Insecure File Upload
- Brute Force
- Directory Traversal
- Cross-Site Request Forgery (CSRF)
- Server-Side Request Forgery (SSRF)
- Server-Side Template Injection (SSTI)
- JWT Token
- Insecure Deserialization

Each vulnerability is having 3 difficulty levels, namely Low, Medium and Hard. 
These levels can be set from the settings page.


## Bugs and Issues

If you find any bugs or issues with the project, kindly raise the same on the below link.

https://github.com/tombstoneghost/TIWAP/issues

## Contributors

1. Simardeep Singh - [LinkedIn](https://www.linkedin.com/in/simardeepsingh99/) | [Twitter](https://twitter.com/simardeep99)
2. Yash Giri -  [LinkedIn](https://www.linkedin.com/in/yashgiri/)
3. Sakshi Aggarwal - [LinkedIn](https://www.linkedin.com/in/s4ksh1/) | [Twitter](https://twitter.com/s4ksh1)
4. Xavier Llauca - [GitHub](https://github.com/xllauca)

### Want to be a contributor? 

1. Star this repository
2. Fork this repository
3. Clone the forked repository
4. Navigate to the project directory
5. Create a new branch with your name
6. Make changes
7. Stage your changes and commit
8. Push your local changes to remote
9. Create a Pull Request
10. Congratulations! You did it. 

## License 

This project is under the MIT License - Click [here](https://github.com/tombstoneghost/TIWAP/blob/master/LICENSE) for details.

<strong>Happy Hacking! :)</strong>

