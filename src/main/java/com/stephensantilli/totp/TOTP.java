package com.stephensantilli.totp;

import java.util.ArrayList;
import java.util.List;

import javax.swing.SwingUtilities;
import javax.swing.Timer;

import com.stephensantilli.totp.ui.CodeItem;
import com.stephensantilli.totp.ui.CodeTable;
import com.stephensantilli.totp.ui.Entry;
import com.stephensantilli.totp.ui.TOTPPane;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.extension.Extension;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.sessions.ActionResult;
import burp.api.montoya.http.sessions.SessionHandlingAction;
import burp.api.montoya.http.sessions.SessionHandlingActionData;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.persistence.PersistedList;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.ui.settings.SettingsPanelBuilder;
import burp.api.montoya.ui.settings.SettingsPanelPersistence;
import burp.api.montoya.ui.settings.SettingsPanelSetting;
import burp.api.montoya.ui.settings.SettingsPanelWithData;
import burp.api.montoya.utilities.ByteUtils;

public class TOTP
        implements BurpExtension, ExtensionUnloadingHandler, CodeListener, HttpHandler, SessionHandlingAction {

    public static final int DEFAULT_DIGITS = 6, DEFAULT_DURATION = 30;

    public static final String PERSISTENCE_SETTING = "Save TOTPs to project file",
            REGEX_SETTING = "Use regex when matching TOTPs",
            DEBUG_SETTING = "Enable verbose logging",
            METHOD_SETTING = "Replacement method (requires extension reload)",
            METHOD_ALL_OPT = "Monitor all requests",
            METHOD_SESSION_OPT = "Session handling rules only (Ignores tool options below)",
            TARGET_TOOL_SETTING = "Replace in Target",
            SCANNER_TOOL_SETTING = "Replace in Scanner",
            REPEATER_TOOL_SETTING = "Replace in Repeater",
            INTRUDER_TOOL_SETTING = "Replace in Intruder",
            SEQUENCER_TOOL_SETTING = "Replace in Sequencer",
            AI_TOOL_SETTING = "Replace in AI",
            EXTENSION_TOOL_SETTING = "Replace in Extensions",
            PROXY_TOOL_SETTING = "Replace in Proxy";

    public static MontoyaApi api;

    public static SettingsPanelWithData settings;

    private ArrayList<Code> codes;

    private TOTPPane totpPane;

    private Timer timer;

    public ArrayList<Code> getCodes() {

        return codes;

    }

    @Override
    public void initialize(MontoyaApi montoyaApi) {

        TOTP.api = montoyaApi;

        Logging log = api.logging();
        UserInterface ui = api.userInterface();
        Extension ext = api.extension();

        log.logToOutput("Initializing TOTP...");

        this.codes = new ArrayList<>();
        this.totpPane = new TOTPPane(this);

        TOTP.settings = SettingsPanelBuilder.settingsPanel()
                .withPersistence(SettingsPanelPersistence.USER_SETTINGS)
                .withTitle("TOTP")
                .withDescription("Change your settings for the TOTP extension.")
                .withKeywords("TOTP", "extension", "authenticator", "time-based", "one-time", "password", "code",
                        "one time", "2fa", "mfa", "two factor")
                .withSettings(SettingsPanelSetting.booleanSetting(PERSISTENCE_SETTING, true))
                .withSettings(SettingsPanelSetting.booleanSetting(REGEX_SETTING, false))
                .withSettings(SettingsPanelSetting.booleanSetting(DEBUG_SETTING, false))
                .withSettings(SettingsPanelSetting.listSetting(METHOD_SETTING,
                        List.of(METHOD_ALL_OPT, METHOD_SESSION_OPT), METHOD_ALL_OPT))
                .withSettings(SettingsPanelSetting.booleanSetting(TARGET_TOOL_SETTING, false))
                .withSettings(SettingsPanelSetting.booleanSetting(SCANNER_TOOL_SETTING, true))
                .withSettings(SettingsPanelSetting.booleanSetting(REPEATER_TOOL_SETTING, false))
                .withSettings(SettingsPanelSetting.booleanSetting(INTRUDER_TOOL_SETTING, false))
                .withSettings(SettingsPanelSetting.booleanSetting(SEQUENCER_TOOL_SETTING, false))
                .withSettings(SettingsPanelSetting.booleanSetting(AI_TOOL_SETTING, false))
                .withSettings(SettingsPanelSetting.booleanSetting(EXTENSION_TOOL_SETTING, false))
                .withSettings(SettingsPanelSetting.booleanSetting(PROXY_TOOL_SETTING, false))
                .build();

        ext.setName("TOTP");
        ext.registerUnloadingHandler(this);

        ui.registerSettingsPanel(settings);

        if (settings.getString(METHOD_SETTING).equals(METHOD_ALL_OPT)) {

            api.http().registerHttpHandler(this);
            logOutput("Registered HTTP handler...", true);

        } else {

            api.http().registerSessionHandlingAction(this);
            logOutput("Registered session handler...", true);

        }

        PersistedObject data = api.persistence().extensionData();

        if (data.getStringList("names") == null)
            data.setStringList("names", PersistedList.persistedStringList());

        if (!settings.getBoolean(PERSISTENCE_SETTING))
            clearSaved();

        this.timer = new Timer(100, l -> {

            totpPane.getCodeTable().updateCodes();

        });

        timer.setRepeats(true);

        loadCodes();

        ui.registerSuiteTab("TOTP", totpPane);

        log.logToOutput("TOTP Initialized!");

    }

    public static void logOutput(String message, boolean debugOnly) {

        if (settings.getBoolean(DEBUG_SETTING))
            api.logging().logToOutput(message);

    }

    public static void logError(String message, boolean debugOnly) {

        if (settings.getBoolean(DEBUG_SETTING))
            api.logging().logToError(message);

    }

    public void clearSaved() {

        PersistedObject data = api.persistence().extensionData();

        data.setStringList("names", PersistedList.persistedStringList());

    }

    public void loadCodes() {

        if (!settings.getBoolean(PERSISTENCE_SETTING))
            return;

        logOutput("Loading saved codes...", true);

        PersistedObject data = api.persistence().extensionData();

        PersistedList<String> codeNames = data.getStringList("names");

        for (String name : codeNames) {

            logOutput("Loading code, \"" + name + "\"...", false);

            try {

                loadCode(name);

            } catch (Exception e) {

                TOTP.logError("e", false);

            }

        }

        SwingUtilities.invokeLater(() -> {

            totpPane.getCodeTable().checkMatch();

        });

    }

    public void saveAll() {

        for (Code code : codes) {

            saveCode(code);

        }

    }

    public void loadCode(String name) throws Exception {

        PersistedObject data = api.persistence().extensionData();

        String crypto, secret, regex;
        int digits, duration;
        boolean enabled;

        secret = data.getString(name + "_secret");
        crypto = data.getString(name + "_crypto");
        regex = data.getString(name + "_regex");
        digits = data.getInteger(name + "_digits");
        duration = data.getInteger(name + "_duration");
        enabled = data.getBoolean(name + "_enabled");

        if (secret == null || crypto == null || regex == null || digits == 0 || duration == 0)
            throw new Exception(
                    "Unable to load \"" + name + "\" from storage."
                            + "\nSecret=" + secret
                            + "\nCrypto=" + crypto
                            + "\nRegex=" + regex
                            + "\nDigits=" + digits
                            + "\nDuration:" + duration
                            + "\nEnabled=" + enabled);

        try {

            addCode(new Code(name, secret, regex, digits, duration, crypto, enabled), false);

        } catch (Exception e) {
            throw new Exception(
                    "Unable to load \"" + name + "\" from storage."
                            + "\nSecret=" + secret
                            + "\nCrypto=" + crypto
                            + "\nRegex=" + regex
                            + "\nDigits=" + digits
                            + "\nDuration:" + duration
                            + "\nEnabled=" + enabled
                            + "\n" + e.getMessage());
        }

    }

    public void saveCode(Code code) {

        if (!settings.getBoolean(PERSISTENCE_SETTING))
            return;

        PersistedObject data = api.persistence().extensionData();

        String name = code.getName();

        data.setString(name + "_secret", code.getBase32Secret());
        data.setString(name + "_crypto", code.getCrypto());
        data.setString(name + "_regex", code.getMatch());
        data.setInteger(name + "_digits", code.getDigits());
        data.setInteger(name + "_duration", code.getDuration());
        data.setBoolean(name + "_enabled", code.isEnabled());

        PersistedList<String> names = data.getStringList("names");

        if (!names.contains(name))
            names.add(name);

        data.setStringList("names", names);

        logOutput("Saved \"" + name + "\" to project store.", false);

    }

    public void addCode(Code code, boolean save) throws Exception {

        for (Code comp : codes) {

            if (comp.getName().equals(code.getName()))
                throw new Exception(
                        "Unable to add \"" + code.getName() + "\". There is already a code with that name!");

        }

        Entry entryPane = totpPane.getEntryPane();
        CodeTable codeTable = totpPane.getCodeTable();

        // This will throw if the secret is invalid.
        code.generateCode();

        codes.add(code);
        codeTable.addCode(code);
        entryPane.resetEntry();

        timer.start();

        if (save)
            saveCode(code);

    }

    @Override
    public void removeCode(CodeItem codeItem) {

        CodeTable codeTable = totpPane.getCodeTable();

        Code code = codeItem.getCode();
        this.codes.remove(code);

        codeTable.removeCode(codeItem);

        if (codes.size() == 0)
            timer.stop();

        PersistedObject data = api.persistence().extensionData();

        String name = code.getName();

        data.setString(name + "_secret", null);
        data.setString(name + "_crypto", null);
        data.setString(name + "_regex", null);
        data.setInteger(name + "_digits", 0);
        data.setInteger(name + "_duration", 0);

        PersistedList<String> names = data.getStringList("names");
        names.remove(name);

        data.setStringList("names", names);

        logOutput("Removed \"" + name + "\" from project store.", false);

    }

    @Override
    public void matchUpdate(Code code, String match) {

        String name = code.getName();

        logOutput("Updating regex for \"" + name + "\" to \"" + match + "\"...", true);

        code.setMatch(match);

        if (settings.getBoolean(PERSISTENCE_SETTING)) {

            PersistedObject data = api.persistence().extensionData();

            data.setString(name + "_regex", match);

        }

        totpPane.getCodeTable().checkMatch();

        logOutput("Updated regex for \"" + name + "\".", true);

    }

    @Override
    public void extensionUnloaded() {

        PersistedObject data = api.persistence().extensionData();

        timer.stop();

        logOutput("Unloading TOTP...", false);

        if (!settings.getBoolean(PERSISTENCE_SETTING)) {

            logOutput("Saving turned off, clearing data store...", false);
            clearSaved();

        } else if (codes.size() != data.getStringList("names").size()) {

            logOutput("Mismatch with data store, re-saving all codes...", false);
            clearSaved();
            saveAll();

        }

        logOutput("TOTP unloading finished. Goodbye!", false);

    }

    @Override
    public void setEnabled(Code code, boolean enabled) {

        code.setEnabled(enabled);

        PersistedObject data = api.persistence().extensionData();

        data.setBoolean(code.getName() + "_enabled", enabled);

    }

    private List<ToolType> getScope() {

        ArrayList<ToolType> tools = new ArrayList<>();

        if (settings.getBoolean(TARGET_TOOL_SETTING))
            tools.add(ToolType.TARGET);

        if (settings.getBoolean(SCANNER_TOOL_SETTING)) {
            tools.add(ToolType.SCANNER);
            tools.add(ToolType.RECORDED_LOGIN_REPLAYER);
        }

        if (settings.getBoolean(REPEATER_TOOL_SETTING))
            tools.add(ToolType.REPEATER);

        if (settings.getBoolean(INTRUDER_TOOL_SETTING))
            tools.add(ToolType.INTRUDER);

        if (settings.getBoolean(SEQUENCER_TOOL_SETTING))
            tools.add(ToolType.SEQUENCER);

        if (settings.getBoolean(AI_TOOL_SETTING))
            tools.add(ToolType.BURP_AI);

        if (settings.getBoolean(EXTENSION_TOOL_SETTING))
            tools.add(ToolType.EXTENSIONS);

        if (settings.getBoolean(PROXY_TOOL_SETTING))
            tools.add(ToolType.PROXY);

        return tools;

    }

    @Override
    public String name() {
        return "Insert TOTP into request";
    }

    @Override
    public ActionResult performAction(SessionHandlingActionData actionData) {

        HttpRequest newReq = matchAndReplace(actionData.request());

        if (newReq != null)
            return ActionResult.actionResult(newReq);
        else
            return ActionResult.actionResult(actionData.request());

    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {

        if (!getScope().contains(requestToBeSent.toolSource().toolType()))
            return RequestToBeSentAction.continueWith(requestToBeSent);

        HttpRequest newReq = matchAndReplace(requestToBeSent);

        if (newReq != null)
            return RequestToBeSentAction.continueWith(newReq);
        else
            return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {

        return ResponseReceivedAction.continueWith(responseReceived);

    }

    private HttpRequest matchAndReplace(HttpRequest req) {

        ByteUtils byteUtils = api.utilities().byteUtils();

        boolean useRegex = TOTP.settings.getBoolean(TOTP.REGEX_SETTING);

        String content = byteUtils.convertToString(req.toByteArray().getBytes());

        logOutput("Called to replace in request " + req.method() + " " + req.pathWithoutQuery() + "...", true);

        HttpRequest newReq = null;

        for (int i = 0; i < codes.size(); i++) {

            Code c = codes.get(i);

            if (!c.isEnabled())
                continue;

            logOutput("[" + c.getName() + "]: Searching for match to \"" + c.getMatch() + "\"...", true);

            String match = c.getMatch();
            String newContent = content;

            if (useRegex)
                newContent = content.replaceAll(match, c.generateCode());
            else
                newContent = content.replace(match, c.generateCode());

            if (!newContent.equals(content)) {

                logOutput("[" + c.getName() + "]: Replaced content matching \"" + c.getMatch() + "\" for request "
                        + req.method() + " " + req.pathWithoutQuery() + "...", false);

                byte[] bytes = byteUtils.convertFromString(newContent);

                newReq = HttpRequest.httpRequest(req.httpService(),
                        ByteArray.byteArray(bytes));

                // This updates Content-Length so that the request doesn't fail when
                // match.length() != c.generateCode().length()
                newReq = newReq.withBody(newReq.body());

            }

        }

        return newReq;

    }

}