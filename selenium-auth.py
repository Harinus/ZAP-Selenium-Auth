# The sendingRequest and responseReceived functions will be called for all requests/responses sent/received by ZAP, 
# including automated tools (e.g. active scanner, fuzzer, ...)

# Note that new HttpSender scripts will initially be disabled
# Right click the script in the Scripts tree and select "enable"  

# 'initiator' is the component the initiated the request:
# 		1	PROXY_INITIATOR
# 		2	ACTIVE_SCANNER_INITIATOR
# 		3	SPIDER_INITIATOR
# 		4	FUZZER_INITIATOR
# 		5	AUTHENTICATION_INITIATOR
# 		6	MANUAL_REQUEST_INITIATOR
# 		7	CHECK_FOR_UPDATES_INITIATOR
# 		8	BEAN_SHELL_INITIATOR
# 		9	ACCESS_CONTROL_SCANNER_INITIATOR
# For the latest list of values see the HttpSender class:
# https://github.com/zaproxy/zaproxy/blob/master/src/org/parosproxy/paros/network/HttpSender.java
# 'helper' just has one method at the moment: helper.getHttpSender() which returns the HttpSender 
# instance used to send the request.
#
# New requests can be made like this:
# msg2 = msg.cloneAll() // msg2 can then be safely changed as required without affecting msg
# helper.getHttpSender().sendAndReceive(msg2, false);
# print('msg2 response=' + str(msg2.getResponseHeader().getStatusCode()))

def sendingRequest(msg, initiator, helper):
	#print ('sendingRequest called for url=' + msg.getRequestHeader().getURI().toString())
	pass

def regparser(logoutIndicators, msg):
	import re
	msgstring = ""
	rexstring = ""
	
	for indicatorDict in logoutIndicators:
		matches = []
		if "STATUS" in indicatorDict:
			regex = re.compile(indicatorDict["STATUS"])
			matches.append(re.search(regex, str(msg.getResponseHeader().getStatusCode())))
		if "HEADER" in indicatorDict:
			regex = re.compile(indicatorDict["HEADER"])
			matches.append(re.search(regex, msg.getResponseHeader().toString()))
		if "BODY" in indicatorDict:
			regex = re.compile(indicatorDict["BODY"])
			matches.append(re.search(regex, msg.getResponseBody().toString()))
		if all(None != s for s in matches):
			return True
	return False

def responseReceived(msg, initiator, helper): 
	#print('responseReceived called for url=' + msg.getRequestHeader().getURI().toString())
		
	if initiator == 2 or initiator == 3 or initiator == 4 or initiator == 6:	
		
		logoutIndicators = []
		logoutIndicators.append({'STATUS':'401'})
		logoutIndicators.append({'STATUS':'302', 'HEADER':'Location.*login'})
		logoutIndicators.append({'STATUS':'200', 'BODY':'Please login'})
		
		#print logoutIndicators
 
		if  regparser(logoutIndicators, msg) is True:
			print "AUTHENTICATION REQUIRED! Your initiator is: " + str(initiator) + " URL: " + msg.getRequestHeader().getURI().toString()
			
			import os
			import org.parosproxy.paros.control.Control
			import org.zaproxy.zap.extension.httpsessions.ExtensionHttpSessions
			import org.zaproxy.zap.extension.httpsessions.HttpSessionsSite
			
			zapsessions = org.parosproxy.paros.control.Control.getSingleton().getExtensionLoader().getExtension(org.zaproxy.zap.extension.httpsessions.ExtensionHttpSessions.NAME)
			sessionSite = zapsessions.getHttpSessionsSite(msg.getRequestHeader().getURI().getHost() + ":" + str(msg.getRequestHeader().getHostPort()), False)

			if sessionSite.getHttpSession("Auth-Selenium") is not None:
				sessionSite.createEmptySession("Re-Auth-Selenium " + str(sessionSite.getNextSessionId()))
			else:
				sessionSite.createEmptySession("Auth-Selenium")
			
			import subprocess as sub
			selenese = sub.Popen("java -jar C:\Users\*\Desktop\Selenium_Custom.b1f2cf5.jar --strict-exit-code --proxy localhost:8080 --screenshot-on-fail C:\Users\*\Desktop\screehns --set-speed 2000 --cli-args /private-window --cli-args about:blank C:\Users\*\Desktop\WebGoat.html", stdout=sub.PIPE)
			#Get Port from config!
			#Lib Folder
			#Test Case by naming
			output = selenese.communicate()[0]
			returns = selenese.returncode

			if returns != 0:	
				print "AUTHENTICATION FAILURE!"
				print output
			else:
				print "Auth-SUCCESS"
			
		else: 
			pass
			#print "rcv-ignore"

	else:
		pass
		#print "via-proxy " + str(msg.getResponseHeader().getStatusCode())
