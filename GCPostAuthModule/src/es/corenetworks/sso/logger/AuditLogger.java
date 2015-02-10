/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package es.corenetworks.sso.logger;

import com.iplanet.sso.SSOToken;
import com.sun.identity.log.LogRecord;
import com.sun.identity.log.Logger;
import com.sun.identity.security.AdminTokenAction;
import java.text.SimpleDateFormat;
import java.util.Calendar;

/**
 *
 * @author haizea
 */
public class AuditLogger {
    public static boolean DEBUG = false;
    
    private static final AuditLogger instance = new AuditLogger();
    private static final SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMdd - HH:mm:ss");
    
    private AuditLogger(){}
    
    public static AuditLogger getInstance(){
        return instance;
    }
    
    private SSOToken getLoggingSSOToken() {
        SSOToken token = getLoggingInternalSSOToken();
        if (DEBUG)
            debugLogMessage(getClass(), "getLoggingSSOToken()", "Token: "+token);
        return token;
    }

    private SSOToken getLoggingInternalSSOToken() {
        if (DEBUG)
            debugLogMessage(getClass(), "getLoggingInternalSSOToken()", "Starting...");
        SSOToken ssoToken = null;
        try {
            AdminTokenAction ata = AdminTokenAction.getInstance();
            ssoToken = (SSOToken) ata.run();
        } catch (Throwable thr) {
            debugLogError(getClass(), "getLoggingInternalSSOToken()", thr + " : " + thr.getMessage());
        }
        return ssoToken;
    }
    
    public void logAccess(Class clazz, String method, String message) {
        logAccess(clazz, method, message, getLoggingSSOToken(), getLoggingSSOToken());
    }
    
    public void logAccess(Class clazz, String method, String message, SSOToken userSSOToken) {
        logAccess(clazz, method, message, userSSOToken, getLoggingSSOToken());
    }

    public void logAccess(Class clazz, String method, String message, SSOToken userSSOToken, SSOToken loggingSSOToken) {
        log(clazz, method, message, userSSOToken, loggingSSOToken, "access");
    }
    
    public void logError(Class clazz, String method, String message) {
        logError(clazz, method, message, getLoggingSSOToken(), getLoggingSSOToken());
    }
    
    public void logError(Class clazz, String method, String message, SSOToken userSSOToken) {
        logError(clazz, method, message, userSSOToken, getLoggingSSOToken());
    }

    public void logError(Class clazz, String method, String message, SSOToken userSSOToken, SSOToken loggingSSOToken) {
        log(clazz, method, message, userSSOToken, loggingSSOToken, "error");
    }
    
    public void log(Class clazz, String method, String message, SSOToken userSSOToken, SSOToken loggingSSOToken, String fileType) {
        String time = sdf.format(Calendar.getInstance().getTime());
        String logPrefix = time + " : " + getClass().getName() + "." + method + " : ";

        if (DEBUG)
            debugLogMessage(clazz, "log", logPrefix + message);

        try {
            Logger logger = (com.sun.identity.log.Logger) Logger.getLogger("amAuthentication."+fileType);
            if (DEBUG)
                debugLogMessage(getClass(), "log", logPrefix + "Log file: " + logger.getCurrentFile());

            LogRecord record = new LogRecord(java.util.logging.Level.INFO, message, userSSOToken);
            logger.log(record, loggingSSOToken);
        } catch (Throwable thr) {
            debugLogError(getClass(), "log", thr+" -> "+thr.getMessage());
        }
    }

    public void debugLogError(Class clazz, String method, String message) {
        String time = sdf.format(Calendar.getInstance().getTime());
        String logPrefix = time + " : " + clazz.getName() + "." + method + " : ERROR : ";
        String logMessage = logPrefix + message;

        System.out.println(logMessage);
    }

    public void debugLogMessage(Class clazz, String method, String message) {
        String time = sdf.format(Calendar.getInstance().getTime());
        String logPrefix = time + " : " + clazz.getName() + "." + method + " : ";
        String logMessage = logPrefix + message;

        System.out.println(logMessage);
    }
}
