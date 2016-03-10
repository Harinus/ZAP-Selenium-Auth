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
# helper.getHttpSender().sendAndReceive(msg2, false)
# print 'msg2 response=' + str(msg2.getResponseHeader().getStatusCode())

def sendingRequest(msg, initiator, helper):
	#print 'sendingRequest called for url=' + msg.getRequestHeader().getURI().toString()
	pass

def regparser(logoutIndicators, msg):
	import re

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
		if "HEADER/i" in indicatorDict:
			regex = re.compile(indicatorDict["HEADER/i"],re.IGNORECASE)
			matches.append(re.search(regex, msg.getResponseHeader().toString()))
		if "BODY/i" in indicatorDict:
			regex = re.compile(indicatorDict["BODY/i"],re.IGNORECASE)
			matches.append(re.search(regex, msg.getResponseBody().toString()))
		if all(None != s for s in matches):
			return True
	return False

def responseReceived(msg, initiator, helper):
	#print 'responseReceived called for url=' + msg.getRequestHeader().getURI().toString()

	if msg.isInScope():
		
		if initiator == 2 or initiator == 3 or initiator == 4 or initiator == 6:		
			logoutIndicators = []
			
			#########################################################################
			
			import os
			import org.parosproxy.paros.model.Model as sess
			sfil = sess.getSingleton().getSession().getFileName()
			if sfil != "":

				divider = '/'
				import platform
				if 'Windows' in platform.platform():
					divider  = '\\'	

				patth = sfil.rpartition(divider)[0]
				basename = sfil.split(divider)[-1].split(".session")[0]
	
				import re
				if not os.path.isfile(patth + divider + basename + ".json"):
					print "SAVE AUTHENTICATION SETTINGS! OR DISABLE AUTH SCCRIPT"
					return
				f = open(patth + divider + basename + ".json", 'r')
				text = f.read()
				results = re.findall('{.*?}', text)
	
				for result in results:
					try:
						eval("logoutIndicators.append(" + result + ")")
					except SyntaxError:
						print "The JSON is invalid! Please check your input!"
				
				loginTestcase = patth + divider + basename + ".html" 
				loginVerificationRequest = patth + divider + basename + ".raw"
			else:
				print "Save session first!"
				return

			#########################################################################
			 
			errorScreens = divider.join(loginTestcase.split(divider)[0:-1]) + divider + "errorScreens"		
	
			if  regparser(logoutIndicators, msg) is True:
				print "Current request appears to be logged out"
				verifyMsg = sendVerificationMessage(loginVerificationRequest, helper, msg)
				
				if  verifyMsg is None or regparser(logoutIndicators, verifyMsg) is True:

					if os.path.isfile(loginTestcase):
						authenticate(msg, initiator, helper, loginTestcase, errorScreens)
					else:
						print "Login Testcase is invalid"
				else:
					pass
					print "Session is still valid!"
			else: 
				pass
				#print "rcv-ignore authenticated"
		else:
			pass
			#print "via-proxy " + str(msg.getResponseHeader().getStatusCode())
	else:
		pass
		#print "msg out of scope"

def sendVerificationMessage(verifyMsgPath, helper, msg):
	import org.parosproxy.paros.network.HttpMessage
	import org.parosproxy.paros.network.HttpRequestHeader
	import os.path

	verifyMsg = org.parosproxy.paros.network.HttpMessage()

	f = open(verifyMsgPath, 'r')		
	verifyMsg.setRequestHeader(org.parosproxy.paros.network.HttpRequestHeader(str(f.read())))		
	if resendMessageWithSession(verifyMsg, helper, getZAPsessionSite(msg).getActiveSession()) is False:
		print "Auth required"
		return None
	
	
	return verifyMsg
		
def authenticate(msg, initiator, helper, loginTestcase, errorScreens):
	print "AUTHENTICATION REQUIRED! Your initiator is: " + str(initiator) + " URL: " + msg.getRequestHeader().getURI().toString()

	sessionSite = getZAPsessionSite(msg)
	seleniumSession = "Auth-Selenium"
	
	import org.zaproxy.zap.extension.script.ScriptVars as vars
	if vars.getGlobalVar("auth_running") == "True":
		print "Another authentication is running... waiting..."
		import time
		mustend = time.time() + 30
		while time.time() < mustend:
			try:
				time.sleep(1)
			except:
				print "Script was interruped, stop processing current message"
				return
			if vars.getGlobalVar("auth_running") != "True":
				resendMessageWithSession(msg, helper, sessionSite.getHttpSession(seleniumSession))
				return
		print "Authentication timeout exceeded, discard message"
	else:
		#do auth
		vars.setGlobalVar("auth_running", "True") 

		if sessionSite.getHttpSession(seleniumSession) is not None:
			seleniumSession = "Re-Auth-Selenium " + str(sessionSite.getNextSessionId())
		sessionSite.createEmptySession(seleniumSession)

		firefoxBinary = 'FirefoxPortableDeveloper/linux/firefox'
		import platform
		if 'Windows' in platform.platform():
			firefoxBinary  = 'FirefoxPortable\FirefoxPortable.exe'		

		import subprocess as sub
		#selenese = sub.Popen("java -jar selenese-runner-2.5.0.jar --strict-exit-code --proxy "+ str(getZAPproxy()) +" --no-proxy *.mozilla.com --screenshot-on-fail \"" + errorScreens + "\" --set-speed 100 --cli-args /private-window --cli-args about:blank \"" + loginTestcase + "\" --firefox " + firefoxBinary, stdout=sub.PIPE)
		selenese = sub.Popen(["java", "-jar", "selenese-runner-2.5.0.jar", "--strict-exit-code", "--proxy", str(getZAPproxy()), "--no-proxy", "*.mozilla.com", "--screenshot-on-fail", errorScreens, "--set-speed", "100", "--cli-args", "-private-window", "--cli-args", "about:blank", loginTestcase, "--firefox", firefoxBinary], stdout=sub.PIPE)

		output = selenese.communicate()[0]
		returns = selenese.returncode
		
		vars.setGlobalVar("auth_running", "False") 
		
		if returns != 0:	
			print "AUTHENTICATION FAILURE!"
			print output
		else:
			print "Auth-SUCCESS"
			resendMessageWithSession(msg, helper, sessionSite.getHttpSession(seleniumSession))

def resendMessageWithSession(msg, helper, httpSession):
	if (httpSession is not None and httpSession.getTokenValuesCount() > 0):
		import org.zaproxy.zap.session.CookieBasedSessionManagementHelper as sessionmgmt
		sessionmgmt.processMessageToMatchSession(msg, httpSession)
		helper.getHttpSender().sendAndReceive(msg, True);
		#print 'Re-Send-Authenticated=' + str(msg.getResponseHeader().getStatusCode())
	else:
		print "There is no active session or the token is empty"
		return False
	
def getZAPsessionSite(msg):
	import org.parosproxy.paros.control.Control
	import org.zaproxy.zap.extension.httpsessions.ExtensionHttpSessions
	import org.zaproxy.zap.extension.httpsessions.HttpSessionsSite
		
	zapsessions = org.parosproxy.paros.control.Control.getSingleton().getExtensionLoader().getExtension(org.zaproxy.zap.extension.httpsessions.ExtensionHttpSessions.NAME)
	return zapsessions.getHttpSessionsSite(msg.getRequestHeader().getURI().getHost() + ":" + str(msg.getRequestHeader().getHostPort()), False)	

def getZAPproxy():
	import org.parosproxy.paros.model.Model
	proxyConfig = org.parosproxy.paros.model.Model.getSingleton().getOptionsParam().getProxyParam();
	return str(proxyConfig.getProxyIp()) + ":" + str(proxyConfig.getProxyPort())
