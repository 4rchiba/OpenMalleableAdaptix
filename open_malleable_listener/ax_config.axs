/// OpenMalleable HTTP listener

function ListenerUI(mode_create)
{
    // MAIN SETTINGS
    let labelHost = form.create_label("Host & port (Bind):");
    let comboHostBind = form.create_combo();
    comboHostBind.setEnabled(mode_create);
    comboHostBind.clear();
    let addrs = ax.interfaces();
    for (let item of addrs) { comboHostBind.addItem(item); }
    let spinPortBind = form.create_spin();
    spinPortBind.setRange(1, 65535);
    spinPortBind.setValue(443);
    spinPortBind.setEnabled(mode_create);

    let labelCallback = form.create_label("Callback addresses:");
    let textCallback = form.create_list();
    textCallback.setButtonsEnabled(true);
    textCallback.addItem("address:port");

    let labelEncryptKey = form.create_label("Encryption key:");
    let textlineEncryptKey = form.create_textline(ax.random_string(32, "hex"));
    textlineEncryptKey.setEnabled(mode_create);
    let buttonEncryptKey = form.create_button("Generate");
    buttonEncryptKey.setEnabled(mode_create);

    form.connect(buttonEncryptKey, "clicked", function() { textlineEncryptKey.setText( ax.random_string(32, "hex") ); });

    // MALLEABLE PROFILE
    let labelProfile = form.create_label("Malleable Profile:");
    let profileSelector = form.create_selector_file();
    profileSelector.setPlaceholder("Select a .profile file");
    profileSelector.setEnabled(mode_create);

    // SSL
    let certSelector = form.create_selector_file();
    certSelector.setPlaceholder("SSL Certificate (optional, auto-generate if empty)");
    let keySelector = form.create_selector_file();
    keySelector.setPlaceholder("SSL Key (optional, auto-generate if empty)");
    let layout_group = form.create_vlayout();
    layout_group.addWidget(certSelector);
    layout_group.addWidget(keySelector);
    let panel_group = form.create_panel();
    panel_group.setLayout(layout_group);
    let ssl_group = form.create_groupbox("Use SSL (HTTPS)", true);
    ssl_group.setPanel(panel_group);
    ssl_group.setChecked(false);

    // HTTP Headers
    let checkTrust = form.create_check("Trust X-Forwarded-For");

    let labelHostHeader = form.create_label("Host Headers:");
    let textHostHeader = form.create_list();
    textHostHeader.setButtonsEnabled(true);

    let layoutMain = form.create_gridlayout();
    layoutMain.addWidget(labelHost,          0, 0, 1, 1);
    layoutMain.addWidget(comboHostBind,      0, 1, 1, 1);
    layoutMain.addWidget(spinPortBind,       0, 2, 1, 1);
    layoutMain.addWidget(labelCallback,      1, 0, 1, 1);
    layoutMain.addWidget(textCallback,       1, 1, 1, 2);
    layoutMain.addWidget(labelEncryptKey,    2, 0, 1, 1);
    layoutMain.addWidget(textlineEncryptKey, 2, 1, 1, 1);
    layoutMain.addWidget(buttonEncryptKey,   2, 2, 1, 1);
    layoutMain.addWidget(labelProfile,       3, 0, 1, 1);
    layoutMain.addWidget(profileSelector,    3, 1, 1, 2);
    layoutMain.addWidget(ssl_group,          4, 0, 1, 3);

    let panelMain = form.create_panel();
    panelMain.setLayout(layoutMain);

    // Headers tab
    let layoutHeaders = form.create_gridlayout();
    layoutHeaders.addWidget(checkTrust,      0, 0, 1, 2);
    layoutHeaders.addWidget(labelHostHeader, 1, 0, 1, 1);
    layoutHeaders.addWidget(textHostHeader,  1, 1, 1, 1);

    let panelHeaders = form.create_panel();
    panelHeaders.setLayout(layoutHeaders);

    // Error page
    let textError = form.create_textmulti("<!DOCTYPE html>\n<html>\n<head>\n<title>ERROR 404 - Nothing Found</title>\n</head>\n<body>\n<h1 class=\"cover-heading\">ERROR 404 - PAGE NOT FOUND</h1>\n</div>\n</div>\n</div>\n</body>\n</html>");

    let layoutError = form.create_gridlayout();
    layoutError.addWidget(textError, 0, 0, 1, 1);

    let panelError = form.create_panel();
    panelError.setLayout(layoutError);

    // Tabs
    let tabs = form.create_tabs();
    tabs.addTab(panelMain, "Main settings");
    tabs.addTab(panelHeaders, "HTTP Headers");
    tabs.addTab(panelError, "Page Error");

    let layout = form.create_hlayout();
    layout.addWidget(tabs);

    let container = form.create_container();
    container.put("host_bind",          comboHostBind);
    container.put("port_bind",          spinPortBind);
    container.put("callback_addresses", textCallback);
    container.put("encrypt_key",        textlineEncryptKey);
    container.put("malleable_profile",  profileSelector);
    container.put("ssl",                ssl_group);
    container.put("ssl_cert",           certSelector);
    container.put("ssl_key",            keySelector);
    container.put("x-forwarded-for",    checkTrust);
    container.put("host_header",        textHostHeader);
    container.put("page-error",         textError);

    let panel = form.create_panel();
    panel.setLayout(layout);

    return {
        ui_panel: panel,
        ui_container: container,
        ui_height: 650,
        ui_width: 750
    }
}
