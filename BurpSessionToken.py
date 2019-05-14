import json
import datetime
from java.io import PrintWriter
from burp import IBurpExtender, IBurpExtenderCallbacks, ISessionHandlingAction


class BurpExtender(IBurpExtender, ISessionHandlingAction):

    AUTHORIZE_JSON_TOKEN = "token"
    AUTHORIZE_HEADER = "x-access-token"

    _helpers = None  # type: IExtensionHelpers
    _callbacks = None  # type: IBurpExtenderCallbacks
    stdout = None  # type: PrintWriter

    # Based in part on https://www.twelvesec.com/2017/05/05/authorization-token-manipulation/
    NAME = "Burp Session Token Handler"
     
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName(self.NAME) 
        self._callbacks.registerSessionHandlingAction(self)    
        self.stdout = PrintWriter(self._callbacks.getStdout(), True)
        self.stdout.println(self.NAME + "\n")
        self.stdout.println('Registered: {:%Y-%m-%d %H:%M:%S}'.format(datetime.datetime.now()))
        self.stdout.println("-----------------------------------------------------------------\n\n")
        return
    
    def getActionName(self):
        return self.NAME
    
    def performAction(self, current_request, macro_items):

        request_info = self._helpers.analyzeRequest(current_request)
        bearer_token = self.extractTokenFromResponse(macro_items)

        if "" == bearer_token:
            self.stdout.println("Issue retrieving bearer token")
            return

        req_headers = request_info.getHeaders()
        req_body = current_request.getRequest()[request_info.getBodyOffset():]

        self.removeTokenFromHeaders(req_headers, self.AUTHORIZE_HEADER)

        req_headers.add(self.AUTHORIZE_HEADER + ": " + bearer_token)
        
        self.stdout.println('Header Checked:  {:%Y-%m-%d %H:%M:%S}'.format(datetime.datetime.now()))
        self.stdout.println("-----------------------------------------------------------------")
        self.stdout.println("Added new header - " + self.AUTHORIZE_HEADER + ": " + bearer_token)
        self.stdout.println("-----------------------------------------------------------------")                

        # Build request with bypass headers        
        message = self._helpers.buildHttpMessage(req_headers, req_body)

        # Update Request with New Header        
        current_request.setRequest(message)

    def removeTokenFromHeaders(self, req_headers, authorize_header):
        # Remove the x-access-token header if it exists
        # Don't escape in case something's broken and 2 auth headers exist
        for head in req_headers:
            if authorize_header in head:
                auth_header_to_delete = head
                try:
                    req_headers.remove(auth_header_to_delete)
                    self.stdout.println("Token header removed")
                except:
                    pass

    def extractTokenFromResponse(self, macro_items):

        # Extract the token from the macro response
        macro_response_info = self._helpers.analyzeResponse(macro_items[0].getResponse())
        macro_msg = macro_items[0].getResponse()
        resp_body = macro_msg[macro_response_info.getBodyOffset():]
        macro_body_string = self._helpers.bytesToString(resp_body)

        # At this point we have the body as a string
        # Convert to json if we need to and extract the token value
        json_response = json.loads(macro_body_string)
        if self.AUTHORIZE_JSON_TOKEN in json_response:
            bearer = json_response[self.AUTHORIZE_JSON_TOKEN]
        else:
            self.stdout.println("Response did not contain " + self.AUTHORIZE_JSON_TOKEN)
            bearer = ""
        return bearer
