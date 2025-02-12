package burp;

import burp.bean.CustomBurpUrl;
import burp.bean.Issus;
import burp.extension.ScanFactory;
import burp.extension.scan.BaseScan;
import burp.ui.Tags;
import burp.utils.FindJsons;
import burp.utils.YamlReader;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.lang.reflect.InvocationTargetException;
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

    }

    @Override
    public void extensionUnloaded() {

    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse iHttpRequestResponse) {
        // 判断是否开启插件
        if (!this.tags.getBaseSettingTagClass().isStart()) {
            return null;
        }
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
        // todo 避免迭代器为空报错
        List<Issus> tabIssues = null;
        try {
            tabIssues = scan(iHttpRequestResponse,"RemoteScan");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        List<Issus> tabIssues2 = null;
        try {
            tabIssues2 = scan(iHttpRequestResponse,"LocalScan");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        Set<Issus> mergedSet = new LinkedHashSet<>();
        mergedSet.addAll(tabIssues);
        mergedSet.addAll(tabIssues2);
        List<Issus> allIssues = new ArrayList<>(mergedSet);
        if (allIssues != null){
            for (Issus tabIssue:allIssues){
                if (tabIssue.getPayload() !=null)
                    issues.add(tabIssue);
            }
        }
        return issues;
    }
    /**
     * 探测依赖扫描模块
     *
     * @param iHttpRequestResponse
     * @param mode
     * @return
     */
    private List<Issus> scan(IHttpRequestResponse iHttpRequestResponse, String mode) throws ClassNotFoundException, InvocationTargetException, NoSuchMethodException, IllegalAccessException, InstantiationException {
        FindJsons findJsons = new FindJsons(helpers, iHttpRequestResponse);
        String url = helpers.analyzeRequest(iHttpRequestResponse).getUrl().toString();
        String method = helpers.analyzeRequest(iHttpRequestResponse).getMethod();
        String statusCode = String.valueOf(helpers.analyzeResponse(iHttpRequestResponse.getResponse()).getStatusCode());

        String key = null;
        BaseScan baseScan = null;
        baseScan = ScanFactory.createScan(mode, iHttpRequestResponse, helpers, callbacks);

        if (baseScan == null) {
            return null;
        }

        int id;
        // 判断数据包中是否存在json，有则加入到tags中
        if (findJsons.isParamsJson().isFlag()) {
            // 先添加任务
            id = this.tags.getScanQueueTagClass().add(
                    method,
                    method,
                    url,
                    statusCode,
                    "find json param.wait for testing.",
                    iHttpRequestResponse);
            key = findJsons.isParamsJson().getKey();
        } else if (findJsons.isContypeJson().isFlag()) {
            // 先添加任务
            id = this.tags.getScanQueueTagClass().add(
                    method,
                    method,
                    url,
                    statusCode,
                    "find json body. wait for testing.",
                    iHttpRequestResponse);
        } else {
            return null;
        }
        // 循环调用dnslog，填入payload
        List<Issus> tabIssues = baseScan.insertPayloads(key);
        for (Issus tabIssue:tabIssues){
            switch (tabIssue.getState()){
                case SAVE:
                    this.tags.getScanQueueTagClass().save(id,
                            tabIssue.getExtentsionMethod(),
                            tabIssue.getMethod(),
                            tabIssue.getUrl().toString(),
                            tabIssue.getStatus(),
                            tabIssue.getResult(),
                            tabIssue.getiHttpRequestResponse());
                    break;
                case ADD:
                    this.tags.getScanQueueTagClass().add(
                            tabIssue.getExtentsionMethod(),
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
        JMenuItem jMenuItem = new JMenuItem("RemoteScan");
        jMenuItem.addActionListener(new ContextMenuActionListener(iContextMenuInvocation,"RemoteScan"));
        JMenuItem jMenuItem2 = new JMenuItem("LocalScan");
        jMenuItem2.addActionListener(new ContextMenuActionListener(iContextMenuInvocation,"LocalScan"));
        JMenuItem jMenuItem3 = new JMenuItem("DetectScan");
        jMenuItem3.addActionListener(new ContextMenuActionListener(iContextMenuInvocation,"versionDetect"));
        JMenuItem jMenuItem4 = new JMenuItem("LibraryScan");
        jMenuItem4.addActionListener(new ContextMenuActionListener(iContextMenuInvocation,"libraryDetect"));
        menuItems.add(jMenuItem);
        menuItems.add(jMenuItem2);
        menuItems.add(jMenuItem3);
        menuItems.add(jMenuItem4);
        return menuItems;
    }

    private class ContextMenuActionListener implements ActionListener {
        IContextMenuInvocation invocation;
        String mode;
        public ContextMenuActionListener(IContextMenuInvocation invocation,String mode) {
            this.invocation = invocation;
            this.mode = mode;
        }
        @Override
        public void actionPerformed(ActionEvent actionEvent) {
            CompletableFuture.runAsync(() -> {
                try {
                    scan(invocation.getSelectedMessages()[0],mode);
                } catch (Exception ex) {
                    // 在Burp的报警窗口显示错误
                    callbacks.issueAlert("Scan failed: " + ex.getMessage());
                    callbacks.printError("Scan error: " + ex.toString());
                }
            });
//            if (mode.equals("RemoteScan")){
//                CompletableFuture.supplyAsync(() -> {
//                    try {
//                        scan(invocation.getSelectedMessages()[0]);
//                    } catch (Exception e) {
//                        throw new RuntimeException(e);
//                    }
//                    return null;
//                }).exceptionally(ex -> {
//                    ex.printStackTrace();
//                    return null;
//                });
//            }else if (mode.equals("LocalScan")){
//                CompletableFuture.supplyAsync(() -> {
//                    try {
//                        scan2(invocation.getSelectedMessages()[0]);
//                    } catch (Exception e) {
//                        throw new RuntimeException(e);
//                    }
//                    return null;
//                }).exceptionally(ex -> {
//                    ex.printStackTrace();
//                    return null;
//                });
//            } else if (mode.equals("DetectScan")) {
//                CompletableFuture.supplyAsync(() -> {
//                    try {
//                        scan3(invocation.getSelectedMessages()[0]);
//                    } catch (Exception e) {
//                        throw new RuntimeException(e);
//                    }
//                    return null;
//                }).exceptionally(ex -> {
//                    ex.printStackTrace();
//                    return null;
//                });
//            }else if (mode.equals("LibraryScan")) {
//                // 异步执行扫描
//                CompletableFuture.runAsync(() -> {
//                    try {
//                        scan4(invocation.getSelectedMessages()[0]);
//
//                    } catch (Exception ex) {
//                        // 在Burp的报警窗口显示错误
//                        callbacks.issueAlert("Scan failed: " + ex.getMessage());
//                        callbacks.printError("Scan error: " + ex.toString());
//                    }
//                });
//            }
        }
    }
}
