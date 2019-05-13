import json
import datetime
from java.io import PrintWriter
from burp import IBurpExtender, IBurpExtenderCallbacks, ISessionHandlingAction
 
class BurpExtender(IBurpExtender, ISessionHandlingAction):
 
    # Based in part on https://www.twelvesec.com/2017/05/05/authorization-token-manipulation/
    NAME = "Burp Session Token Handler"
     
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName(self.NAME) 
        self._callbacks.registerSessionHandlingAction(self)    
        self.stdout = PrintWriter(self._callbacks.getStdout(), True)
        self.stdout.println(self.NAME + "\n")
        self.stdout.println('starting at time : {:%Y-%m-%d %H:%M:%S}'.format(datetime.datetime.now()))
        self.stdout.println("-----------------------------------------------------------------\n\n")
        return
    
    def getActionName(self):
        return self.NAME
    
    def performAction(self, currentRequest, macroItems):

        request_info = self._helpers.analyzeRequest(currentRequest)
        
        #Extract the token from the macro response
        macro_response_info = self._helpers.analyzeResponse(macroItems[0].getResponse())
        
        macro_msg = macroItems[0].getResponse()
        resp_body = macro_msg[macro_response_info.getBodyOffset():]
        macro_body_string = self._helpers.bytesToString(resp_body)

        # At this point we have the body as a string
        # Convert to json if we need to and extract the token value
        bearer_token = json.loads(macro_body_string)
        bearer = bearer_token["token"]

        req_headers = request_info.getHeaders()
        req_body = currentRequest.getRequest()[request_info.getBodyOffset():]
        resp_headers = macro_response_info.getHeaders()  

        auth_to_delete = ''

        # Remove the x-access-token header if it exists
        for head in req_headers:
            if 'x-access-token' in head:
                auth_to_delete = head
                break
        try:
            req_headers.remove(auth_to_delete)
            self.stdout.println("Token header removed")            
        except:
            pass

        req_headers.add('x-access-token: ' + bearer)
        
        self.stdout.println('Header Checked at time :  {:%Y-%m-%d %H:%M:%S}'.format(datetime.datetime.now()))        
        self.stdout.println("-----------------------------------------------------------------"        )
        self.stdout.println("Adding new header - x-access-token: " + bearer) 
        self.stdout.println("-----------------------------------------------------------------")                
        self.stdout.println("Geting authorized..done\n\n")                
        
        # Build request with bypass headers        
        message = self._helpers.buildHttpMessage(req_headers, req_body)

        # Update Request with New Header        
        currentRequest.setRequest(message)
        return