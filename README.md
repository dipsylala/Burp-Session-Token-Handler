# Burp Session-Token Handler extension

Originally from https://www.twelvesec.com/2017/05/05/authorization-token-manipulation/
Updated to be a little more SOLID.

Retrieves a 'token' value from JSON response and uses that in ensuing x-access-token requests

See the instructions at twelvesec or https://www.gracefulsecurity.com/burp-macros-re-authentication/ for how to integrate it into your session checking

## Configuration
![Session Handling Rules](images/1.SessionHandlingRules.png)

![Session Handling Rules Editor](images/2.SessionHandlingRulesEditor.png)

![Session Handling Action Editor](images/3.SessionHandlingActionEdiitor-1.png)

![Session Handling Action Editor](images/4.SessionHandlingActionEdiitor-2.png)