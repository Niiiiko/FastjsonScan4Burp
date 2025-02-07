package burp;

import burp.bean.CustomBurpUrl;
import burp.bean.Issus;
import burp.extension.RemoteCmd;
import burp.ui.Tags;
import burp.utils.FindJsons;
import burp.utils.YamlReader;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.util.*;
import java.util.concurrent.CompletableFuture;

/**
 * @ClassName: FastjsonScan
 * @Auther: niko
 * @Date: 2025/1/16 17:07
 * @Description:
 */
public class FastjsonScan implements IBurpExtender,IExtensionStateListener,IScannerCheck,IContextMenuFactory{
    private IBurpExtenderCallbacks callbacks;
    public String name = "FastjsonScan";
    private IScanIssue iScanIssue;
    private PrintWriter printWriter;

    private IExtensionHelpers helpers;
    private Tags tags;
    private YamlReader yamlReader;
    private PrintWriter stdout;
    private PrintWriter stderr;
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {

        this.callbacks = callbacks;
        callbacks.setExtensionName("FastJsonScan");
        this.helpers = callbacks.getHelpers();
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);
        this.tags = new Tags(callbacks, name);
        this.yamlReader = YamlReader.getInstance(callbacks);
        stdout.println("success");

        callbacks.addSuiteTab(this.tags);
        callbacks.registerScannerCheck(this);
        callbacks.registerContextMenuFactory(this);
//        callbacks.registerHttpListener(this);


    }

    @Override
    public void extensionUnloaded() {

    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse iHttpRequestResponse) {
        List<IScanIssue> issues = new ArrayList<>();

        List<String> domainNameBlacklist = this.yamlReader.getStringList("scan.domainName.blacklist");
        List<String> domainNameWhitelist = this.yamlReader.getStringList("scan.domainName.whitelist");

        // 基础url解析
        CustomBurpUrl baseBurpUrl = new CustomBurpUrl(this.callbacks, iHttpRequestResponse);
        // 判断域名黑名单
        if (domainNameBlacklist != null && domainNameBlacklist.size() >= 1) {
            if (isMatchDomainName(baseBurpUrl.getRequestHost(), domainNameBlacklist)) {
                return null;
            }
        }

        // 判断域名白名单
        if (domainNameWhitelist != null && domainNameWhitelist.size() >= 1) {
            if (!isMatchDomainName(baseBurpUrl.getRequestHost(), domainNameWhitelist)) {
                return null;
            }
        }
        // 判断当前请求后缀,是否为url黑名单后缀
        if (this.isUrlBlackListSuffix(baseBurpUrl)) {
            return null;
        }
        // 判断当前站点问题数量是否超出了
        Integer issueNumber = this.yamlReader.getInteger("scan.issueNumber");
        if (issueNumber != 0) {
            Integer siteIssueNumber = this.getSiteIssueNumber(baseBurpUrl.getRequestDomainName());
            if (siteIssueNumber >= issueNumber) {
                this.tags.getScanQueueTagClass().add(
                        "",
                        this.helpers.analyzeRequest(iHttpRequestResponse).getMethod(),
                        baseBurpUrl.getHttpRequestUrl().toString(),
                        this.helpers.analyzeResponse(iHttpRequestResponse.getResponse()).getStatusCode() + "",
                        "the number of website problems has exceeded",
                        iHttpRequestResponse
                );
                return null;
            }
        }
        // 判断当前站点是否超出扫描数量了
        Integer siteScanNumber = this.yamlReader.getInteger("scan.siteScanNumber");
        if (siteScanNumber != 0) {
            Integer siteJsonNumber = this.getSiteJsonNumber(baseBurpUrl.getRequestDomainName());
            if (siteJsonNumber >= siteScanNumber) {
                this.tags.getScanQueueTagClass().add(
                        "",
                        this.helpers.analyzeRequest(iHttpRequestResponse).getMethod(),
                        baseBurpUrl.getHttpRequestUrl().toString(),
                        this.helpers.analyzeResponse(iHttpRequestResponse.getResponse()).getStatusCode() + "",
                        "the number of website scans exceeded",
                        iHttpRequestResponse
                );

                return null;
            }
        }
        // 避免迭代器为空报错
        List<Issus> tabIssues = scan(iHttpRequestResponse);
        if (tabIssues != null){
            for (Issus tabIssue:tabIssues){
                if (tabIssue.getPayload() !=null)
                    issues.add(tabIssue);
            }
        }
        return issues;
    }

    private List<Issus> scan(IHttpRequestResponse iHttpRequestResponse){
        FindJsons findJsons = new FindJsons(helpers, iHttpRequestResponse);
        String url = helpers.analyzeRequest(iHttpRequestResponse).getUrl().toString();
        String method = helpers.analyzeRequest(iHttpRequestResponse).getMethod();
        String statusCode = String.valueOf(helpers.analyzeResponse(iHttpRequestResponse.getResponse()).getStatusCode());
        List<String> payloads = this.yamlReader.getStringList("application.remoteCmdExtension.config.payloads");
        Iterator<String> payloadIterator = payloads.iterator();

        String key = null;
        RemoteCmd remoteCmd =null;
        remoteCmd = new RemoteCmd(callbacks,iHttpRequestResponse ,helpers);

        if (remoteCmd == null){
            return null;
        }

        int id;
        // 判断数据包中是否存在json，有则加入到tags中
        if (findJsons.isParamsJson().isFlag()){
            // 先添加任务
            id = this.tags.getScanQueueTagClass().add(
                    method,
                    method,
                    url,
                    statusCode,
                    "find json param.wait for testing.",
                    iHttpRequestResponse);
            key = findJsons.isParamsJson().getKey();
        }else if (findJsons.isContypeJson().isFlag()){
            // 先添加任务
            id = this.tags.getScanQueueTagClass().add(
                    method,
                    method,
                    url,
                    statusCode,
                    "find json body. wait for testing.",
                    iHttpRequestResponse);
        }else {
            return null;
        }
        // 循环调用dnslog，填入payload
        List<Issus> tabIssues  = remoteCmd.insertPayloads(payloadIterator, key);
        for (Issus tabIssue:tabIssues){
            switch (tabIssue.getState()){
                case SAVE:
                    this.tags.getScanQueueTagClass().save(id,
                            tabIssue.getPayload(),
                            tabIssue.getMethod(),
                            tabIssue.getUrl().toString(),
                            tabIssue.getStatus(),
                            tabIssue.getResult(),
                            tabIssue.getiHttpRequestResponse());
                    break;
                case ADD:
                    this.tags.getScanQueueTagClass().add(
                            tabIssue.getPayload(),
                            tabIssue.getMethod(),
                            tabIssue.getUrl().toString(),
                            tabIssue.getStatus(),
                            tabIssue.getResult(),
                            tabIssue.getiHttpRequestResponse());
                    break;
                case ERROR:
                case TIMEOUT:
                    break;
            }
        }
        return tabIssues;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse iHttpRequestResponse, IScannerInsertionPoint iScannerInsertionPoint) {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue iScanIssue, IScanIssue iScanIssue1) {
        return 0;
    }

    /**
     * 判断是否查找的到指定的域名
     *
     * @param domainName     需匹配的域名
     * @param domainNameList 待匹配的域名列表
     * @return
     */
    private static Boolean isMatchDomainName(String domainName, List<String> domainNameList) {
        domainName = domainName.trim();

        if (domainName.length() <= 0) {
            return false;
        }

        if (domainNameList == null || domainNameList.size() <= 0) {
            return false;
        }

        if (domainName.contains(":")) {
            domainName = domainName.substring(0, domainName.indexOf(":"));
        }

        String reverseDomainName = new StringBuffer(domainName).reverse().toString();

        for (String domainName2 : domainNameList) {
            domainName2 = domainName2.trim();

            if (domainName2.length() <= 0) {
                continue;
            }

            if (domainName2.contains(":")) {
                domainName2 = domainName2.substring(0, domainName2.indexOf(":"));
            }

            String reverseDomainName2 = new StringBuffer(domainName2).reverse().toString();

            if (domainName.equals(domainName2)) {
                return true;
            }

            if (reverseDomainName.contains(".") && reverseDomainName2.contains(".")) {
                List<String> splitDomainName = new ArrayList<String>(Arrays.asList(reverseDomainName.split("[.]")));

                List<String> splitDomainName2 = new ArrayList<String>(Arrays.asList(reverseDomainName2.split("[.]")));

                if (splitDomainName.size() <= 0 || splitDomainName2.size() <= 0) {
                    continue;
                }

                if (splitDomainName.size() < splitDomainName2.size()) {
                    for (int i = splitDomainName.size(); i < splitDomainName2.size(); i++) {
                        splitDomainName.add("*");
                    }
                }

                if (splitDomainName.size() > splitDomainName2.size()) {
                    for (int i = splitDomainName2.size(); i < splitDomainName.size(); i++) {
                        splitDomainName2.add("*");
                    }
                }

                int ii = 0;
                for (int i = 0; i < splitDomainName.size(); i++) {
                    if (splitDomainName2.get(i).equals("*")) {
                        ii = ii + 1;
                    } else if (splitDomainName.get(i).equals(splitDomainName2.get(i))) {
                        ii = ii + 1;
                    }
                }

                if (ii == splitDomainName.size()) {
                    return true;
                }
            }
        }
        return false;
    }
    /**
     * 判断是否url黑名单后缀
     * 大小写不区分
     * 是 = true, 否 = false
     *
     * @param burpUrl
     * @return
     */
    private boolean isUrlBlackListSuffix(CustomBurpUrl burpUrl) {
        if (!this.yamlReader.getBoolean("urlBlackListSuffix.config.isStart")) {
            return false;
        }

        String noParameterUrl = burpUrl.getHttpRequestUrl().toString().split("\\?")[0];
        String urlSuffix = noParameterUrl.substring(noParameterUrl.lastIndexOf(".") + 1);

        List<String> suffixList = this.yamlReader.getStringList("urlBlackListSuffix.suffixList");
        if (suffixList == null || suffixList.size() == 0) {
            return false;
        }

        for (String s : suffixList) {
            if (s.toLowerCase().equals(urlSuffix.toLowerCase())) {
                return true;
            }
        }

        return false;
    }
    /**
     * 网站问题数量
     *
     * @param domainName
     * @return
     */
    private Integer getSiteIssueNumber(String domainName) {
        Integer number = 0;

        String issueName = this.yamlReader.getString("application.cmdEchoExtension.config.issueName");
//        String issueName2 = this.yamlReader.getString("application.remoteCmdExtension.config.issueName");
        issueName = "fastjson rce";
        for (IScanIssue Issue : this.callbacks.getScanIssues(domainName)) {
            if (Issue.getIssueName().equals(issueName)) {
                number++;
            }
        }

        return number;
    }
    private Integer getSiteJsonNumber(String domain){
        Integer number = 0;
         for(IHttpRequestResponse iHttpRequestResponse :this.callbacks.getSiteMap(domain)){
             FindJsons findJsons = new FindJsons(helpers, iHttpRequestResponse);
             if (findJsons.isParamsJson().isFlag()||findJsons.isContypeJson().isFlag()){
                 number ++;
             }
         }
        return number;
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation iContextMenuInvocation) {
        List<JMenuItem> menuItems = new ArrayList<>();
        if (iContextMenuInvocation.getToolFlag() != IBurpExtenderCallbacks.TOOL_REPEATER){
            return menuItems;
        }
        JMenuItem jMenuItem = new JMenuItem("send to scan");
        jMenuItem.addActionListener(new ContextMenuActionListener(iContextMenuInvocation));
//        JMenuItem jMenuItem2 = new JMenuItem("specific scan");
//        jMenuItem.addActionListener(e -> scan(iContextMenuInvocation.getSelectedMessages()[0]));
        menuItems.add(jMenuItem);
//        menuItems.add(jMenuItem2);
        return menuItems;
    }

    private class ContextMenuActionListener implements ActionListener {
        IContextMenuInvocation invocation;
        public ContextMenuActionListener(IContextMenuInvocation invocation) {
            this.invocation = invocation;
        }
        @Override
        public void actionPerformed(ActionEvent actionEvent) {
            CompletableFuture.supplyAsync(() -> {
                scan(invocation.getSelectedMessages()[0]);
                return null;
            }).exceptionally(ex -> {
                ex.printStackTrace();
                return null;
            });
        }
    }
}
