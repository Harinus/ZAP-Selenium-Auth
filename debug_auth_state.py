import org.zaproxy.zap.extension.script.ScriptVars as vars
vars.setGlobalVar("auth_running", "init")
print "reset: " + str(vars.getGlobalVar("auth_running"))
