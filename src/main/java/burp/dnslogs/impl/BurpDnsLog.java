package burp.dnslogs.impl;

import java.util.Map;
import java.util.List;
import java.util.Arrays;
import java.util.Iterator;
import java.io.PrintWriter;

import burp.IExtensionHelpers;
import burp.IBurpExtenderCallbacks;
import burp.IBurpCollaboratorInteraction;
import burp.IBurpCollaboratorClientContext;
import burp.dnslogs.DnslogInterface;

public class BurpDnsLog implements DnslogInterface {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    private IBurpCollaboratorClientContext burpCollaboratorClientContext;

    private String dnslogContent = "";
    private String randomDnsUrl;

    public BurpDnsLog(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        this.burpCollaboratorClientContext = callbacks.createBurpCollaboratorClientContext();

        this.init();
    }

    private void init() {
        // 通过burp组建获取临时dnslog域名
        String temporaryDomainName = this.burpCollaboratorClientContext.generatePayload(true);
        if (temporaryDomainName == null || temporaryDomainName.length() <= 0) {
            throw new RuntimeException(
                    String.format(
                            "%s 扩展-获取临时域名失败, 请检查本机是否可使用burp自带的dnslog客户端",
                            this.getExtensionName()));
        }
        this.randomDnsUrl = temporaryDomainName;
    }

    @Override
    public String getBodyContent() {
        List<IBurpCollaboratorInteraction> collaboratorInteractions =
                this.burpCollaboratorClientContext.fetchCollaboratorInteractionsFor(this.randomDnsUrl);
        if (collaboratorInteractions != null && !collaboratorInteractions.isEmpty()) {
            Iterator<IBurpCollaboratorInteraction> iterator = collaboratorInteractions.iterator();

            Map<String, String> properties = iterator.next().getProperties();
            if (properties.size() == 0) {
                return this.dnslogContent;
            }

            String content = null;
            for (String property : properties.keySet()) {
                String text = properties.get(property);
                if (property.equals("raw_query")) {
                    text = new String(this.helpers.base64Decode(text));
                }
                content += text + " ";
            }
            this.dnslogContent += content;
            return this.dnslogContent;
        }
        return this.dnslogContent;
    }

    @Override
    public String getAllContent() {
        return null;
    }

    @Override
    public String getExtensionName() {
        return "BurpDnsLog";
    }

    @Override
    public String getRandomDnsUrl() {
        return randomDnsUrl;
    }

    @Override
    public String getRandomPredomain() {
        return this.randomDnsUrl.substring(0, this.randomDnsUrl.indexOf("."));
    }
}
