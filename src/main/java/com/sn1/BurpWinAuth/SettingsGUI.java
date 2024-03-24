package com.sn1.BurpWinAuth;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.GridLayout;

import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.border.EmptyBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import burp.api.montoya.persistence.PersistedObject;

class SettingsGUI {
    private final SSPINegotiatorPlugin plugin;
    private JCheckBox canonicalize = new JCheckBox();
    private JCheckBox replaceExisting = new JCheckBox();
    private JCheckBox enabled = new JCheckBox();
    private JTextField SPNoverride = new JTextField();

    SettingsGUI(SSPINegotiatorPlugin plugin) {
        this.plugin = plugin;
        load();
    }

    public boolean isReplaceExisting() {
        return replaceExisting.isSelected();
    }
    public boolean isEnabled() {
        return enabled.isSelected();
    }

    public boolean isCanonicalize() {
        return canonicalize.isSelected();
    }

    public String getSPNoverride() {
        return SPNoverride.getText();
    }

    private void load() {
        PersistedObject myExtensionData = this.plugin.api.persistence().extensionData();
        Boolean is_enabled = myExtensionData.getBoolean("enabled");
        Boolean is_canonicalize = myExtensionData.getBoolean("canonicalize");
        String spnOverride = myExtensionData.getString("SPNoverride");
        Boolean is_replaceExisting = myExtensionData.getBoolean("replaceExisting");
        
        //                                                        defaults
        enabled.setSelected(is_enabled == null                  ? false  : is_enabled);
        canonicalize.setSelected(is_canonicalize == null        ? true   : is_canonicalize);
        replaceExisting.setSelected(is_replaceExisting == null  ? false  : is_replaceExisting);
        SPNoverride.setText(spnOverride == null                 ? ""     : spnOverride);
    }

    private void save() {
        PersistedObject myExtensionData = this.plugin.api.persistence().extensionData();
        myExtensionData.setBoolean("enabled", isEnabled());
        myExtensionData.setBoolean("canonicalize", isCanonicalize());
        myExtensionData.setBoolean("replaceExisting", isReplaceExisting());
        myExtensionData.setString("SPNoverride", getSPNoverride());
    }

    Component constructSettingsTab() {
        /* TODO: This way of layouting feels ancient, probably exists a better way */
        JPanel p = new JPanel();
        p.setBorder( new EmptyBorder(20, 20, 20, 20) );
        p.setLayout(new GridLayout(4, 2));
        
        p.add(new JLabel("Enabled:"));
        p.add(enabled);
        p.add(new JLabel("Canonicalize SPN (recommended):"));
        p.add(canonicalize);
        p.add(new JLabel("Do not ignore requests with existing authorization headers, instead replace the header:"));
        p.add(replaceExisting);
        p.add(new JLabel("Force SPN override (if used, remember to start with HTTP/):"));
        p.add(SPNoverride);

        enabled.addActionListener(e -> {
            save();
        });
        replaceExisting.addActionListener(e -> {
            save();
        });
        canonicalize.addActionListener(e -> {
            save();
        });
        
        // TODO: Burp is quite bad at performance, why should I care more. Anyway, saving for every letter change should have very low impact here.
        SPNoverride.getDocument().addDocumentListener(new DocumentListener() {
            @Override
                public void insertUpdate(DocumentEvent e) {
                    save();
                }

                @Override
                public void removeUpdate(DocumentEvent e) {
                    save();
                }

                @Override
                public void changedUpdate(DocumentEvent e) {
                    save();
                }
        });
        JPanel outer = new JPanel();
        outer.setLayout(new BorderLayout());
        outer.add(p, BorderLayout.NORTH);
        return outer;
    }
}