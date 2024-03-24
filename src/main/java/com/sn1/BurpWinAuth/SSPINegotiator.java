package com.sn1.BurpWinAuth;

import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.logging.Logging;

import static burp.api.montoya.http.handler.RequestToBeSentAction.continueWith;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import waffle.windows.auth.IWindowsSecurityContext;
import waffle.windows.auth.impl.WindowsSecurityContextImpl;

public class SSPINegotiator implements HttpHandler {
    private Map<String, String> hostCannonicalMap;
    private SettingsGUI settings;
    private Logging logging;

    public SSPINegotiator(SettingsGUI s, Logging logging) {
        hostCannonicalMap = new HashMap<>();
        this.settings = s;
        this.logging = logging;
    }

    public String cannonicalizeHost(String host) throws UnknownHostException {
        String ret = hostCannonicalMap.get(host);
        if (ret != null && ret.length() != 0) {
            return ret;
        }
        InetAddress in = InetAddress.getByName(host);
        ret = in.getCanonicalHostName();
        hostCannonicalMap.put(host, ret);
        return ret;
    }

    public String WinAuth(String targetName) throws UnknownHostException {
        IWindowsSecurityContext clientContext;
        String spn = settings.getSPNoverride();
        
        if (spn == null || spn.length() == 0) {
            spn = "HTTP/" + targetName;
            if (settings.isCanonicalize()) {
                spn = "HTTP/" + cannonicalizeHost(targetName);
            }
        }
        logging.logToOutput("WinAuthLogger: Using SPN:" + spn);
        clientContext = WindowsSecurityContextImpl.getCurrent("Negotiate", spn);
        byte[] rawToken = clientContext.getToken();
        byte[] encodedBytes = Base64.getEncoder().encode(rawToken);
        return new String(encodedBytes);
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent original_request) {
        if (!settings.isEnabled()) {
            //logging.logToOutput("WinAuthLogger: Not enabled");
            return continueWith(original_request);
        }

        HttpRequest updatedHttpRequestToBeSent = original_request;
        boolean hasHeader = original_request.hasHeader("Authorization");
        if (hasHeader && !settings.isReplaceExisting()) {
            logging.logToOutput("WinAuthLogger: Authorization header found. Replace existing:" + settings.isReplaceExisting());
            return continueWith(original_request);
        }

        String host = original_request.httpService().host();
        try {
            String token = WinAuth(host);
            if (hasHeader) {
                updatedHttpRequestToBeSent = updatedHttpRequestToBeSent.withUpdatedHeader("Authorization","Negotiate " + token);
            } else {
                updatedHttpRequestToBeSent = updatedHttpRequestToBeSent.withAddedHeader("Authorization","Negotiate " + token);
            }
            //logging.logToOutput("WinAuthLogger: Injecting header: " + token);
            return continueWith(updatedHttpRequestToBeSent);
        } catch (UnknownHostException e) {
            logging.logToOutput("WinAuthLogger: Unknown host exception for " + host + " : " + e);
            return continueWith(original_request);
        }
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived httpResponseReceived) {
        return ResponseReceivedAction.continueWith(httpResponseReceived);
    }
}