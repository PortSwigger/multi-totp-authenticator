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
import burp.api.montoya.http.message.HttpMessage;
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

/**
 * The main class for TOTP.
 */
public class TOTP
        implements BurpExtension, ExtensionUnloadingHandler, UIListener, HttpHandler, SessionHandlingAction,
        ContextMenuItemsProvider {

    public static final int DEFAULT_DIGITS = 6, DEFAULT_DURATION = 30;

    public static final String PERSISTENCE_SETTING = "Save TOTPs to project file",
            MATCH_SETTING = "Use regex when matching TOTPs",
            DEBUG_SETTING = "Enable verbose logging";

    public static final String SCOPE_OPTION_KEY = "_SCOPE_OPTION",
            PREFIXES_KEY = "_PREFIX_LIST",
            TOOLS_KEY = "_TOOLS_LIST";

    public static final String NAMES_KEY = "_NAMES",
            SECRET_KEY_SUFFIX = "_secret",
            CRYPTO_KEY_SUFFIX = "_crypto",
            MATCH_KEY_SUFFIX = "_regex",
            DIGITS_KEY_SUFFIX = "_digits",
            DURATION_KEY_SUFFIX = "_duration",
            ENABLED_KEY_SUFFIX = "_enabled";

    /**
     * Combined with a prefix from {@link #PREFIXES_KEY}, the key used to store
     * whether or not this prefix has "Include subdomains?" enabled.
     */
    public static final String PREFIX_INCLUDE_SUBDOMAINS_SUFFIX = "_include_subdomains";

    /**
     * Combined with a prefix from {@link #PREFIXES_KEY}, the key used to store
     * whether or not this prefix is enabled.
     */
    public static final String PREFIX_ENABLED_SUFFIX = "_is_enabled";

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
                .withSettings(SettingsPanelSetting.booleanSetting(MATCH_SETTING, false))
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

        if (!settings.getBoolean(PERSISTENCE_SETTING))
            clearCodeStorage();

        this.timer = new Timer(100, l -> {

            totpPane.getCodeTable().updateCodes();

        });

        timer.setRepeats(true);

        loadScope();
        loadCodes();

        ui.registerSuiteTab("TOTP", totpPane);

        log.logToOutput("TOTP Initialized!");

    }

    @Override
    public void extensionUnloaded() {

        logOutput("Unloading TOTP...", false);

        timer.stop();

        PersistedObject data = api.persistence().extensionData();

        if (!settings.getBoolean(PERSISTENCE_SETTING)) {

            logOutput("Saving turned off, clearing codes from data store...", false);
            clearCodeStorage();

            // If user enables saving after adding codes...or something went really wrong.
        } else if (data.getStringList(NAMES_KEY) == null || data.getStringList(NAMES_KEY).size() < codes.size()) {

            logOutput("Mismatch with data store. Re-saving all codes.", false);

            for (Code code : codes) {

                saveCode(code);

            }

        }

        if (scopeDialogWrapper != null)
            scopeDialogWrapper.dispose();

        logOutput("TOTP unloading finished. Goodbye!", false);

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
    public void removeCodeItem(CodeItem codeItem) {

        CodeTable codeTable = totpPane.getCodeTable();

        Code code = codeItem.getCode();

        this.codes.remove(code);
        codeTable.removeCode(codeItem);

        if (codes.size() == 0)
            timer.stop();

        String name = code.getName();

        PersistedObject data = api.persistence().extensionData();

        data.deleteString(name + SECRET_KEY_SUFFIX);
        data.deleteString(name + CRYPTO_KEY_SUFFIX);
        data.deleteString(name + MATCH_KEY_SUFFIX);
        data.deleteInteger(name + DIGITS_KEY_SUFFIX);
        data.deleteInteger(name + DURATION_KEY_SUFFIX);
        data.deleteBoolean(name + ENABLED_KEY_SUFFIX);

        PersistedList<String> names = data.getStringList(NAMES_KEY);

        if (names != null) {

            names.remove(name);

            data.setStringList(NAMES_KEY, names);

        }

        logOutput("Removed \"" + name + "\" from the project.", false);

    }

    @Override
    public void matchUpdate(Code code, String match) {

        String name = code.getName();

        logOutput("Updating regex for \"" + name + "\" to \"" + match + "\"...", true);

        code.setMatch(match);

        if (settings.getBoolean(PERSISTENCE_SETTING)) {

            PersistedObject data = api.persistence().extensionData();

            data.setString(name + MATCH_KEY_SUFFIX, match);

        }

        totpPane.getCodeTable().highlightMatches();

        logOutput("Updated regex for \"" + name + "\".", true);

    }

    @Override
    public void setCodeEnabled(Code code, boolean enabled) {

        code.setEnabled(enabled);

        if (settings.getBoolean(PERSISTENCE_SETTING)) {

            PersistedObject data = api.persistence().extensionData();

            data.setBoolean(code.getName() + ENABLED_KEY_SUFFIX, enabled);

        }

    }

    @Override
    public void addScopeItem(ScopeItem item) throws Exception {

        scope.addItem(item);

        PersistedObject data = api.persistence().extensionData();

        PersistedList<String> prefixes = data.getStringList(PREFIXES_KEY);
        String prefix = item.getPrefix();

        if (prefixes.contains(prefix))
            throw new Exception("That URL is already in scope!");

        prefixes.add(prefix);

        data.setStringList(PREFIXES_KEY, prefixes);

        data.setBoolean(prefix + PREFIX_INCLUDE_SUBDOMAINS_SUFFIX, item.getIncludeSubdomains());
        data.setBoolean(prefix + PREFIX_ENABLED_SUFFIX, item.isEnabled());

        if (scopeDialog != null)
            scopeDialog.addScope(item);

        logOutput("Added \"" + prefix + "\" to the scope.", true);

    }

    @Override
    public void removeScopeItem(int index) throws IndexOutOfBoundsException {

        PersistedObject data = api.persistence().extensionData();

        PersistedList<String> prefixes = data.getStringList(PREFIXES_KEY);

        // Heavily relies on the prefixes not getting mismatched
        String prefix = prefixes.get(index);

        prefixes.remove(prefix);

        data.setStringList(PREFIXES_KEY, prefixes);

        data.deleteBoolean(prefix + PREFIX_ENABLED_SUFFIX);
        data.deleteBoolean(prefix + PREFIX_INCLUDE_SUBDOMAINS_SUFFIX);

        scope.removePrefix(index);

        if (scopeDialog != null)
            scopeDialog.removeScope(index);

        logOutput("Removed \"" + prefix + "\" from the scope.", true);

    }

    @Override
    public void setTool(ToolType tool, boolean enabled) {

        PersistedObject data = api.persistence().extensionData();

        PersistedList<String> tools = data.getStringList(TOOLS_KEY);

        if (tools == null)
            tools = PersistedList.persistedStringList();

        if (enabled) {

            scope.addTool(tool);

            if (!tools.contains(tool.name()))
                tools.add(tool.name());

        } else {

            scope.removeTool(tool);

            tools.remove(tool.name());

        }

        data.setStringList(TOOLS_KEY, tools);

        logOutput("Set " + tool.toolName() + " to " + (enabled ? "enabled" : "disabled") + ".", true);

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
        scopeDialogWrapper = null;
        scopeDialog = null;

        logOutput("Scope dialog closed!", true);

    }

    @Override
    public void setItemPrefix(String prefix, int index) throws Exception, IndexOutOfBoundsException {

        ScopeItem item = scope.getPrefixes().get(index);

        if (scope.getPrefixes().contains(new ScopeItem(prefix, false, false)))
            throw new Exception("There is already a scope item with that prefix!");

        PersistedObject data = api.persistence().extensionData();
        PersistedList<String> prefixes = data.getStringList(PREFIXES_KEY);

        prefixes.set(index, prefix);
        data.setStringList(PREFIXES_KEY, prefixes);

        String oldPrefix = item.getPrefix();
        data.deleteBoolean(oldPrefix + PREFIX_ENABLED_SUFFIX);
        data.deleteBoolean(oldPrefix + PREFIX_INCLUDE_SUBDOMAINS_SUFFIX);

        item.setPrefix(prefix);

        data.setBoolean(prefix + PREFIX_ENABLED_SUFFIX, item.isEnabled());
        data.setBoolean(prefix + PREFIX_INCLUDE_SUBDOMAINS_SUFFIX, item.getIncludeSubdomains());

        logOutput("Prefix set to \"" + item.getPrefix() + "\"!", true);

    }

    @Override
    public void setItemEnabled(boolean enabled, int index) throws IndexOutOfBoundsException {

        ScopeItem item = scope.getPrefixes().get(index);

        PersistedObject data = api.persistence().extensionData();
        data.setBoolean(item.getPrefix() + PREFIX_ENABLED_SUFFIX, enabled);

        item.setEnabled(enabled);

        logOutput((enabled ? "Enabled" : "Disabled") + " \"" + item.getPrefix() + "\"!", true);

    }

    @Override
    public void setItemIncludeSubdomains(boolean includeSubdomains, int index) throws IndexOutOfBoundsException {

        ScopeItem item = scope.getPrefixes().get(index);

        PersistedObject data = api.persistence().extensionData();
        data.setBoolean(item.getPrefix() + PREFIX_INCLUDE_SUBDOMAINS_SUFFIX, includeSubdomains);

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

                logOutput("Menu items provided!", true);

                return List.of(codeMenu, placeholderMenu);

        }

    }

    /**
     * Loads a code from the data store.
     * 
     * @param name The name of a saved {@link Code}.
     * @throws Exception If the code is unable to be retrieved from the data store.
     */
    private void loadCode(String name) throws Exception {

        PersistedObject data = api.persistence().extensionData();

        String crypto = null, secret = null, regex = null;
        int digits = 0, duration = 0;
        boolean enabled = false;

        try {

            secret = data.getString(name + SECRET_KEY_SUFFIX);
            crypto = data.getString(name + CRYPTO_KEY_SUFFIX);
            regex = data.getString(name + MATCH_KEY_SUFFIX);
            digits = data.getInteger(name + DIGITS_KEY_SUFFIX);
            duration = data.getInteger(name + DURATION_KEY_SUFFIX);
            enabled = data.getBoolean(name + ENABLED_KEY_SUFFIX);

            // The ints will throw if null
            if (secret == null || crypto == null || regex == null)
                throw new Exception("Invalid values.");

            // Add code without saving it again
            addCode(new Code(name, secret, regex, digits, duration, crypto, enabled), false);

        } catch (Exception e) {

            throw new Exception("Unable to load \"" + name + "\" from storage."
                    + "\nMessage: " + e.getMessage()
                    + "\nSecret: " + secret
                    + "\nCrypto: " + crypto
                    + "\nRegex: " + regex
                    + "\nDigits: " + digits
                    + "\nDuration: " + duration
                    + "\nEnabled: " + enabled);

        }

    }

    /**
     * Clears the scope configuration and all associated data from the project
     * storage.
     */
    @SuppressWarnings("unused")
    private void clearScopeStorage() {

        logOutput("Clearing scope from storage...", false);

        PersistedObject data = api.persistence().extensionData();

        PersistedList<String> prefixes = data.getStringList(PREFIXES_KEY);

        if (prefixes != null) {

            for (String prefix : prefixes) {

                data.deleteBoolean(prefix + PREFIX_INCLUDE_SUBDOMAINS_SUFFIX);
                data.deleteBoolean(prefix + PREFIX_ENABLED_SUFFIX);

            }

        }

        data.deleteStringList(PREFIXES_KEY);
        data.deleteInteger(SCOPE_OPTION_KEY);
        data.deleteStringList(TOOLS_KEY);

        logOutput("Scope cleared from storage!", false);

    }

    /**
     * Clears the secrets and all associated data of all TOTPs in the project
     * storage.
     */
    private void clearCodeStorage() {

        logOutput("Clearing codes from storage...", false);

        PersistedObject data = api.persistence().extensionData();

        PersistedList<String> names = data.getStringList(NAMES_KEY);

        if (names != null) {

            for (String name : names) {

                data.deleteString(name + SECRET_KEY_SUFFIX);
                data.deleteString(name + CRYPTO_KEY_SUFFIX);
                data.deleteString(name + MATCH_KEY_SUFFIX);
                data.deleteInteger(name + DIGITS_KEY_SUFFIX);
                data.deleteInteger(name + DURATION_KEY_SUFFIX);
                data.deleteBoolean(name + ENABLED_KEY_SUFFIX);

            }

        }

        data.deleteStringList(NAMES_KEY);

        logOutput("Codes cleared from storage!", false);

    }

    /**
     * Saves a code to the data store if persistence is enabled.
     * 
     * @param code The code that should be saved.
     */
    private void saveCode(Code code) {

        if (!settings.getBoolean(PERSISTENCE_SETTING))
            return;

        PersistedObject data = api.persistence().extensionData();

        String name = code.getName();

        data.setString(name + SECRET_KEY_SUFFIX, code.getBase32Secret());
        data.setString(name + CRYPTO_KEY_SUFFIX, code.getCrypto());
        data.setString(name + MATCH_KEY_SUFFIX, code.getMatch());
        data.setInteger(name + DIGITS_KEY_SUFFIX, code.getDigits());
        data.setInteger(name + DURATION_KEY_SUFFIX, code.getDuration());
        data.setBoolean(name + ENABLED_KEY_SUFFIX, code.isEnabled());

        PersistedList<String> names = data.getStringList(NAMES_KEY);

        if (names == null)
            names = PersistedList.persistedStringList();

        if (!names.contains(name))
            names.add(name);

        data.setStringList(NAMES_KEY, names);

        logOutput("Saved \"" + name + "\" to project store.", false);

    }

    /**
     * Inserts a string into an {@link HttpRequest} or {@link HttpResponse},
     * overwriting only the defined range. If {@code start == end}, {@code insert}
     * will not overwrite anything.
     * 
     * @param msg    The message to modify
     * @param insert The string that will be inserted
     * @param start  The inclusive start of the range to overwrite
     * @param end    The exclusive end of the range to overwrite
     * @return A new {@link HttpRequest} or {@link HttpResponse} with the insertion
     *         made.
     * @throws Exception If {@code msg} is not
     */
    private HttpMessage insertIntoMessage(HttpMessage msg, String insert, int start, int end) throws Exception {

        ByteArray bytes = msg.toByteArray();

        ByteArray newMsg = bytes.subArray(0, start)
                .withAppended(insert);

        if (end < bytes.length())
            newMsg = newMsg.withAppended(bytes.subArray(end, bytes.length()));

        if (msg instanceof HttpRequest)
            return HttpRequest.httpRequest(newMsg).withService(((HttpRequest) msg).httpService());
        else if (msg instanceof HttpResponse)
            return HttpResponse.httpResponse(newMsg);
        else
            throw new Exception("You can only insert into a request or response!");

    }

    /**
     * Handles a context menu insertion action from the user. Inserts the given TOTP
     * code or match string at the caret position of the user in the message editor.
     * If there is a selection, the selection is overwritten with the code or match
     * string.
     * 
     * @param event       The {@link ContextMenuEvent} generated
     * @param code        The {@link Code} selected
     * @param placeholder If {@code false}, {@link Code#generateCode()} will be
     *                    inserted. If {@code true}, {@link Code#getMatch()} will be
     *                    inserted.
     */
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

            try {

                if (context.equals(SelectionContext.REQUEST))
                    editor.setRequest((HttpRequest) insertIntoMessage(rr.request(), insert, start, end));
                else if (context.equals(SelectionContext.RESPONSE))
                    editor.setResponse((HttpResponse) insertIntoMessage(rr.response(), insert, start, end));

            } catch (Exception e) {

                logError(e.getMessage(), false);

            }

        } else
            logOutput("Called to insert code but there is no message editor!", true);

    }

    /**
     * Loads in the scope the user has saved to the project file. If there is no
     * pre-existing saved list of tools, the default tools will be used.
     */
    private void loadScope() {

        this.scope = new Scope();

        logOutput("Loading saved scope...", false);

        PersistedObject data = api.persistence().extensionData();

        try {

            // If there isn't a user-configured option, ALL_URLS is already set by default.
            // No need to store it until the user makes a change.
            if (data.getInteger(SCOPE_OPTION_KEY) != null) {

                ScopeOption suiteScope = ScopeOption.valueOf(data.getInteger(SCOPE_OPTION_KEY));
                scope.setSuiteScope(suiteScope);

            }

        } catch (Exception e) {

            logError(e.getMessage(), false);

        }

        PersistedList<String> prefixes = data.getStringList(PREFIXES_KEY);

        if (prefixes == null)
            data.setStringList(PREFIXES_KEY, PersistedList.persistedStringList());
        else {

            for (String item : prefixes) {

                logOutput("Loading prefix, \"" + item + "\"...", true);

                try {

                    boolean includeSubdomains = data.getBoolean(item + PREFIX_INCLUDE_SUBDOMAINS_SUFFIX);
                    boolean enabled = data.getBoolean(item + PREFIX_ENABLED_SUFFIX);

                    scope.addItem(new ScopeItem(item, includeSubdomains, enabled));

                    logOutput("Loaded prefix, \"" + item + "\".", true);

                } catch (Exception e) {

                    TOTP.logError(e.getMessage(), false);

                }

            }

        }

        PersistedList<String> tools = data.getStringList(TOOLS_KEY);

        if (tools == null) {

            tools = PersistedList.persistedStringList();

            ArrayList<ToolType> defaultTools = new ArrayList<>();
            defaultTools.add(ToolType.TARGET);
            defaultTools.add(ToolType.SCANNER);
            defaultTools.add(ToolType.REPEATER);
            defaultTools.add(ToolType.INTRUDER);

            scope.setTools(defaultTools);

            data.setStringList(TOOLS_KEY, tools);

        } else {

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

        logOutput("Saved scope loaded!", false);

    }

    /**
     * Initializes the codes that a user has saved to the project file, if
     * persistence is enabled.
     */
    private void loadCodes() {

        if (!settings.getBoolean(PERSISTENCE_SETTING))
            return;

        logOutput("Loading saved codes...", false);

        PersistedObject data = api.persistence().extensionData();

        PersistedList<String> codeNames = data.getStringList(NAMES_KEY);

        if (codeNames == null) {

            logOutput("No saved codes to load!", false);
            data.setStringList(NAMES_KEY, PersistedList.persistedStringList());

            return;

        }

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

        logOutput("Saved codes loaded!", false);

    }

    /**
     * Takes a request and checks for matches to {@link Code#getMatch()} against all
     * codes in {@link #codes}. All occurrances of the match string of the first
     * code to have a match will be replaced with {@link Code#generateCode()}. Other
     * codes that also have matches will not be replaced.
     * 
     * @param req The {@link HttpRequest} to search for matches in
     * @return A new {@link HttpRequest} with matches replaced, or {@code null} if
     *         none were found.
     */
    private HttpRequest matchAndReplace(HttpRequest req) {

        logOutput("Called to replace in request " + req.method() + " " + req.pathWithoutQuery() + "...", true);

        ByteUtils byteUtils = api.utilities().byteUtils();

        boolean useRegex = TOTP.settings.getBoolean(TOTP.MATCH_SETTING);

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