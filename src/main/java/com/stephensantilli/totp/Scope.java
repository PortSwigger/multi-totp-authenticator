package com.stephensantilli.totp;

import java.util.ArrayList;

import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.message.requests.HttpRequest;

public class Scope {

    private ArrayList<ScopeItem> prefixes;

    private ArrayList<ToolType> tools;

    private ScopeOption scopeOption;

    public Scope() {
        this.prefixes = new ArrayList<>();
        this.tools = new ArrayList<>();
        this.scopeOption = ScopeOption.ALL_URLS;
    }

    public Scope(ArrayList<ScopeItem> prefixes, ArrayList<ToolType> tools, ScopeOption suiteScope) {

        this.prefixes = prefixes;
        this.tools = tools;
        this.scopeOption = suiteScope;

    }

    public ScopeOption getScopeOption() {
        return scopeOption;
    }

    public void setScopeOption(ScopeOption scopeOption) {
        this.scopeOption = scopeOption;
    }

    public void addTool(ToolType tool) {

        if (!tools.contains(tool))
            tools.add(tool);

    }

    public void removeTool(ToolType tool) {

        tools.remove(tool);

    }

    public void addItem(ScopeItem item) {

        prefixes.add(item);

    }

    public void removePrefix(int index) {

        prefixes.remove(index);

    }

    public boolean requestInURLScope(HttpRequest req) {

        if (scopeOption.equals(ScopeOption.ALL_URLS))
            return true;
        else if (scopeOption.equals(ScopeOption.SUITE_SCOPE))
            return req.isInScope();

        for (ScopeItem item : prefixes) {

            if (item.isEnabled() && item.isInScope(req.url()))
                return true;

        }

        return false;

    }

    public ArrayList<ScopeItem> getPrefixes() {
        return prefixes;
    }

    public void setPrefixes(ArrayList<ScopeItem> prefixes) {
        this.prefixes = prefixes;
    }

    public ArrayList<ToolType> getTools() {
        return tools;
    }

    public void setTools(ArrayList<ToolType> tools) {
        this.tools = tools;
    }

    public ScopeOption isSuiteScope() {
        return scopeOption;
    }

    public void setSuiteScope(ScopeOption suiteScope) {
        this.scopeOption = suiteScope;
    }

}
