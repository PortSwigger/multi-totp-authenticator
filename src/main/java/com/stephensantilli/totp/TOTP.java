package com.stephensantilli.totp;

import java.awt.Component;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.SwingUtilities;
import javax.swing.Timer;

import com.stephensantilli.totp.ui.CodeItem;
import com.stephensantilli.totp.ui.CodeTable;
import com.stephensantilli.totp.ui.Entry;
import com.stephensantilli.totp.ui.ScopeDialog;
import com.stephensantilli.totp.ui.TOTPPane;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Range;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.extension.Extension;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.sessions.ActionResult;
import burp.api.montoya.http.sessions.SessionHandlingAction;
import burp.api.montoya.http.sessions.SessionHandlingActionData;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.persistence.PersistedList;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse.SelectionContext;
import burp.api.montoya.ui.settings.SettingsPanelBuilder;
import burp.api.montoya.ui.settings.SettingsPanelPersistence;
import burp.api.montoya.ui.settings.SettingsPanelSetting;
import burp.api.montoya.ui.settings.SettingsPanelWithData;
import burp.api.montoya.utilities.ByteUtils;

public class TOTP
        implements BurpExtension, ExtensionUnloadingHandler, CodeListener, HttpHandler, SessionHandlingAction,
        ContextMenuItemsProvider {

    public static final int DEFAULT_DIGITS = 6, DEFAULT_DURATION = 30;

    public static final int ALL_URLS = 0, SUITE_SCOPE = 1, CUSTOM_SCOPE = 2;

    public static final String PERSISTENCE_SETTING = "Save TOTPs to project file",
            REGEX_SETTING = "Use regex when matching TOTPs",
            DEBUG_SETTING = "Enable verbose logging",
            SCOPE_OPTION_KEY = "_USE_SUITE_SCOPE",
            PREFIXES_KEY = "_PREFIX_LIST",
            TOOLS_KEY = "_TOOLS_LIST",
            INCLUDE_SUBDOMAINS_SUFFIX = "_include_subdomains",
            IS_ENABLED_SUFFIX = "_is_enabled";

    public static MontoyaApi api;

    public static SettingsPanelWithData settings;

    public static void logOutput(String message, boolean debugOnly) {

        if (settings.getBoolean(DEBUG_SETTING))
            api.logging().logToOutput(message);

    }

    public static void logError(String message, boolean debugOnly) {

        if (settings.getBoolean(DEBUG_SETTING))
            api.logging().logToError(message);

    }

    private ArrayList<Code> codes;

    private TOTPPane totpPane;

    private Timer timer;

    private Scope scope;

    private ScopeDialog scopeDialog;

    private JDialog scopeDialogWrapper;

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

        ext.setName("TOTP");

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
                .build();

        ui.registerSettingsPanel(settings);
        logOutput("Registered settings panel.", true);

        ui.registerContextMenuItemsProvider(this);
        logOutput("Registered context menu.", true);

        ext.registerUnloadingHandler(this);
        logOutput("Registered unloading handler.", true);

        api.http().registerHttpHandler(this);
        logOutput("Registered HTTP handler.", true);

        api.http().registerSessionHandlingAction(this);
        logOutput("Registered session handling action.", true);

        PersistedObject data = api.persistence().extensionData();

        if (data.getStringList("names") == null)
            data.setStringList("names", PersistedList.persistedStringList());

        if (!settings.getBoolean(PERSISTENCE_SETTING))
            clearSaved();

        this.timer = new Timer(100, l -> {

            totpPane.getCodeTable().updateCodes();

        });

        timer.setRepeats(true);

        loadScope();
        loadCodes();

        ui.registerSuiteTab("TOTP", totpPane);

        log.logToOutput("TOTP Initialized!");

    }

    public void clearSaved() {

        PersistedObject data = api.persistence().extensionData();

        data.setStringList("names", PersistedList.persistedStringList());

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

        logOutput("Added \"" + code.getName() + "\" to the project.", false);

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

        data.deleteString(name + "_secret");
        data.deleteString(name + "_crypto");
        data.deleteString(name + "_regex");
        data.deleteInteger(name + "_digits");
        data.deleteInteger(name + "_duration");

        PersistedList<String> names = data.getStringList("names");
        names.remove(name);

        data.setStringList("names", names);

        logOutput("Removed \"" + name + "\" from the project.", false);

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

        totpPane.getCodeTable().highlightMatches();

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

        if (scopeDialogWrapper != null)
            scopeDialogWrapper.dispose();

        logOutput("TOTP unloading finished. Goodbye!", false);

    }

    @Override
    public void setEnabled(Code code, boolean enabled) {

        code.setEnabled(enabled);

        PersistedObject data = api.persistence().extensionData();

        data.setBoolean(code.getName() + "_enabled", enabled);

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

        ToolType tool = requestToBeSent.toolSource().toolType();

        if (tool.equals(ToolType.RECORDED_LOGIN_REPLAYER))
            tool = ToolType.SCANNER;

        if (!scope.getTools().contains(tool))
            return RequestToBeSentAction.continueWith(requestToBeSent);

        if (!scope.requestInURLScope(requestToBeSent))
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

    @Override
    public void addScope(ScopeItem item) throws Exception {

        scope.addItem(item);

        PersistedObject data = api.persistence().extensionData();

        PersistedList<String> prefixes = data.getStringList(PREFIXES_KEY);
        String prefix = item.getPrefix();

        if (prefixes.contains(prefix))
            throw new Exception("That URL is already in scope!");

        prefixes.add(prefix);

        data.setStringList(PREFIXES_KEY, prefixes);

        data.setBoolean(prefix + INCLUDE_SUBDOMAINS_SUFFIX, item.getIncludeSubdomains());
        data.setBoolean(prefix + IS_ENABLED_SUFFIX, item.isEnabled());

        if (scopeDialog != null)
            scopeDialog.addScope(item);

        logOutput("Added \"" + prefix + "\" to the scope.", true);

    }

    @Override
    public void removeScope(int index) throws Exception {

        PersistedObject data = api.persistence().extensionData();

        PersistedList<String> prefixes = data.getStringList(PREFIXES_KEY);
        String prefix = prefixes.get(index);

        prefixes.remove(prefix);

        data.setStringList(PREFIXES_KEY, prefixes);

        data.deleteBoolean(prefix + IS_ENABLED_SUFFIX);
        data.deleteBoolean(prefix + INCLUDE_SUBDOMAINS_SUFFIX);

        scope.removePrefix(index);

        if (scopeDialog != null)
            scopeDialog.removeScope(index);

        logOutput("Removed \"" + prefix + "\" from the scope.", true);

    }

    @Override
    public void setTool(ToolType tool, boolean enabled) {

        PersistedObject data = api.persistence().extensionData();

        PersistedList<String> tools = data.getStringList(TOOLS_KEY);

        if (enabled) {

            scope.addTool(tool);

            if (!tools.contains(tool.toString()))
                tools.add(tool.toString());

        } else {

            scope.removeTool(tool);

            tools.remove(tool.toString());

        }

        logOutput((enabled ? "Enabled" : "Disabled") + " " + tool.toolName() + ".", true);

    }

    @Override
    public void setScopeOption(ScopeOption scopeOption) {

        PersistedObject data = api.persistence().extensionData();

        scope.setSuiteScope(scopeOption);

        data.setInteger(SCOPE_OPTION_KEY, scopeOption.getValue());

        logOutput("Scope option set to " + scopeOption.name() + "!", true);

    }

    @Override
    public void openScopeDialog() throws Exception {

        logOutput("Opening scope dialog...", true);

        this.scopeDialog = new ScopeDialog(this);
        this.scopeDialogWrapper = new JDialog((JFrame) SwingUtilities.getWindowAncestor(totpPane.getEntryPane()),
                "Scope Configuration",
                false);

        scopeDialogWrapper.setContentPane(scopeDialog);
        scopeDialogWrapper.setLocationRelativeTo(totpPane.getEntryPane());

        scopeDialog.setPrefixes(scope.getPrefixes(), scope.getScopeOption());
        scopeDialog.setTools(scope.getTools());

        scopeDialogWrapper.pack();
        scopeDialogWrapper.setMinimumSize(scopeDialogWrapper.getSize());
        scopeDialogWrapper.setVisible(true);

        logOutput("Scope dialog opened!", true);

    }

    @Override
    public void closeScopeDialog() {

        scopeDialogWrapper.dispose();
        scopeDialog = null;

        logOutput("Scope dialog closed!", true);

    }

    @Override
    public void setItemPrefix(String prefix, int index) throws Exception {

        ScopeItem item = scope.getPrefixes().get(index);

        item.setPrefix(prefix);

        logOutput("Prefix set to \"" + item.getPrefix() + "\"!", true);

    }

    @Override
    public void setItemEnabled(boolean enabled, int index) throws Exception {

        ScopeItem item = scope.getPrefixes().get(index);

        item.setEnabled(enabled);

        logOutput((enabled ? "Enabled" : "Disabled") + " \"" + item.getPrefix() + "\"!", true);

    }

    @Override
    public void setItemIncludeSubdomains(boolean includeSubdomains, int index) throws Exception {

        ScopeItem item = scope.getPrefixes().get(index);

        item.setIncludeSubdomains(includeSubdomains);

        logOutput((includeSubdomains ? "Enabled" : "Disabled") + " include subdomains for \"" + item.getPrefix() + "!",
                true);

    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {

        logOutput("Menu item provider called at event type: " + event.invocationType(), true);

        switch (event.invocationType()) {
            case INTRUDER_ATTACK_RESULTS:
            case MESSAGE_VIEWER_RESPONSE:
            case PROXY_HISTORY:
            case SCANNER_RESULTS:
            case SEARCH_RESULTS:
            case SITE_MAP_TABLE:
            case SITE_MAP_TREE:
            case MESSAGE_VIEWER_REQUEST:
            default:
                return null;
            case INTRUDER_PAYLOAD_POSITIONS:
            case MESSAGE_EDITOR_REQUEST:
            case MESSAGE_EDITOR_RESPONSE:
            case PROXY_INTERCEPT:

                JMenu codeMenu = new JMenu("Insert code"),
                        placeholderMenu = new JMenu("Insert placeholder");

                for (Code code : codes) {

                    JMenuItem insertCode = new JMenuItem(code.getName());
                    insertCode.addActionListener(l -> {

                        contextMenuInsert(event, code, false);

                    });

                    codeMenu.add(insertCode);

                    JMenuItem insertPlaceholder = new JMenuItem(code.getName());
                    insertPlaceholder.addActionListener(l -> {

                        contextMenuInsert(event, code, true);

                    });

                    placeholderMenu.add(insertPlaceholder);

                }

                return List.of(codeMenu, placeholderMenu);

        }

    }

    private HttpRequest insertIntoRequest(HttpRequest req, String insert, int start, int end) {

        ByteArray msg = req.toByteArray();

        ByteArray newMsg = msg.subArray(0, start)
                .withAppended(insert);

        if (end < msg.length())
            newMsg = newMsg.withAppended(msg.subArray(end, msg.length()));

        return HttpRequest.httpRequest(newMsg).withService(req.httpService());

    }

    private HttpResponse insertIntoResponse(HttpResponse res, String insert, int start, int end) {

        ByteArray msg = res.toByteArray();

        ByteArray newMsg = msg.subArray(0, start)
                .withAppended(insert);

        if (end < msg.length())
            newMsg = newMsg.withAppended(msg.subArray(end, msg.length()));

        return HttpResponse.httpResponse(newMsg);

    }

    private void contextMenuInsert(ContextMenuEvent event, Code code, boolean placeholder) {

        if (event.messageEditorRequestResponse().isPresent()) {

            MessageEditorHttpRequestResponse editor = event.messageEditorRequestResponse().get();
            SelectionContext context = editor.selectionContext();
            HttpRequestResponse rr = editor.requestResponse();

            int caret = editor.caretPosition();
            int start = caret, end = caret;
            String insert = placeholder ? code.getMatch() : code.generateCode();

            Optional<Range> sel = editor.selectionOffsets();

            // If user has a selection
            if (sel.isPresent()) {

                start = sel.get().startIndexInclusive();
                end = sel.get().endIndexExclusive();

            }

            if (context.equals(SelectionContext.REQUEST))
                editor.setRequest(insertIntoRequest(rr.request(), insert, start, end));
            else if (context.equals(SelectionContext.RESPONSE))
                editor.setResponse(insertIntoResponse(rr.response(), insert, start, end));

        } else
            logOutput("Called to insert code but there is no message editor!", true);

    }

    private void loadScope() {

        if (!settings.getBoolean(PERSISTENCE_SETTING))
            return;

        this.scope = new Scope();

        logOutput("Loading saved scope...", true);

        PersistedObject data = api.persistence().extensionData();

        try {

            ScopeOption suiteScope = ScopeOption.valueOf(data.getInteger(SCOPE_OPTION_KEY));
            scope.setSuiteScope(suiteScope);

        } catch (Exception e) {

            logError(e.getMessage(), false);
            e.printStackTrace();

        }

        PersistedList<String> prefixes = data.getStringList(PREFIXES_KEY);

        if (prefixes == null)
            data.setStringList(PREFIXES_KEY, PersistedList.persistedStringList());
        else {

            for (String item : prefixes) {

                logOutput("Loading prefix, \"" + item + "\"...", false);

                try {

                    boolean includeSubdomains = data.getBoolean(item + INCLUDE_SUBDOMAINS_SUFFIX);
                    boolean enabled = data.getBoolean(item + IS_ENABLED_SUFFIX);

                    scope.addItem(new ScopeItem(item, includeSubdomains, enabled));

                    logOutput("Added prefix, \"" + item + "\".", false);

                } catch (Exception e) {

                    TOTP.logError(e.getMessage(), false);

                }

            }

        }

        PersistedList<String> tools = data.getStringList(TOOLS_KEY);

        if (tools == null)
            data.setStringList(TOOLS_KEY, PersistedList.persistedStringList());
        else {

            for (String item : tools) {

                logOutput("Adding \"" + item + "\" to scope...", true);

                try {

                    ToolType tool = ToolType.valueOf(item);

                    scope.getTools().add(tool);

                    logOutput("Added \"" + tool + "\" to scope.", true);

                } catch (Exception e) {

                    TOTP.logError(e.getMessage(), false);

                }

            }

        }

        logOutput("Saved scope loaded!", true);

    }

    private void loadCodes() {

        if (!settings.getBoolean(PERSISTENCE_SETTING))
            return;

        logOutput("Loading saved codes...", true);

        PersistedObject data = api.persistence().extensionData();

        PersistedList<String> codeNames = data.getStringList("names");

        for (String name : codeNames) {

            logOutput("Loading code, \"" + name + "\"...", false);

            try {

                loadCode(name);

                logOutput("Added code, \"" + name + "\".", false);

            } catch (Exception e) {

                TOTP.logError(e.getMessage(), false);

            }

        }

        SwingUtilities.invokeLater(() -> {

            totpPane.getCodeTable().highlightMatches();

        });

        logOutput("Saved codes loaded!", true);

    }

    private HttpRequest matchAndReplace(HttpRequest req) {

        logOutput("Called to replace in request " + req.method() + " " + req.pathWithoutQuery() + "...", true);

        ByteUtils byteUtils = api.utilities().byteUtils();

        boolean useRegex = TOTP.settings.getBoolean(TOTP.REGEX_SETTING);

        String content = byteUtils.convertToString(req.toByteArray().getBytes());

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

                byte[] bytes = byteUtils.convertFromString(newContent);

                newReq = HttpRequest.httpRequest(req.httpService(),
                        ByteArray.byteArray(bytes));

                // This updates Content-Length so that the request doesn't fail when
                // match.length() != c.generateCode().length()
                newReq = newReq.withBody(newReq.body());

                logOutput("[" + c.getName() + "]: Replaced content matching \"" + c.getMatch() + "\" for request "
                        + req.method() + " " + req.pathWithoutQuery() + "...", false);

            }

        }

        return newReq;

    }

}