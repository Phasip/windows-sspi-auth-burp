package com.sn1.BurpWinAuth;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

public class SSPINegotiatorPlugin implements BurpExtension {

    MontoyaApi api;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("Windows SSPI Auth");
        api.logging().logToOutput("Loaded the Windows SSPI auth plugin");
        SettingsGUI s = new SettingsGUI(this);
        SSPINegotiator negotiator = new SSPINegotiator(s, api.logging());

        api.userInterface().registerSuiteTab("WinSSPIAuth", s.constructSettingsTab());
        api.http().registerHttpHandler(negotiator);
    }

    
}
