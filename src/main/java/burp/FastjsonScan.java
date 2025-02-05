package burp;

import burp.bean.CustomBurpUrl;
import burp.bean.Issus;
import burp.dnslogs.Ceye;
import burp.extension.RemoteCmd;
import burp.ui.Tags;
import burp.utils.FindJsons;
import burp.utils.YamlReader;

import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.util.*;

/**
 * @ClassName: FastjsonScan
 * @Auther: niko
 * @Date: 2025/1/16 17:07
 * @Description:
 */
public class FastjsonScan implements IBurpExtender,IExtensionStateListener,IScannerCheck,IHttpListener{
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
        this.helpers = callbacks.getHelpers();
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);
        this.tags = new Tags(callbacks, name);
        this.yamlReader = YamlReader.getInstance(callbacks);
        stdout.println("success");

        callbacks.addSuiteTab(this.tags);
        callbacks.registerHttpListener(this);


    }

    @Override
    public void extensionUnloaded() {

    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse iHttpRequestResponse) {
        return null;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse iHttpRequestResponse, IScannerInsertionPoint iScannerInsertionPoint) {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue iScanIssue, IScanIssue iScanIssue1) {
        return 0;
    }

    @Override
    public void processHttpMessage(int i, boolean b, IHttpRequestResponse iHttpRequestResponse) {
        List<IScanIssue> issues = new ArrayList<>();

        List<String> domainNameBlacklist = this.yamlReader.getStringList("scan.domainName.blacklist");
        List<String> domainNameWhitelist = this.yamlReader.getStringList("scan.domainName.whitelist");

        // 基础url解析
        CustomBurpUrl baseBurpUrl = new CustomBurpUrl(this.callbacks, iHttpRequestResponse);
        // 判断域名黑名单
        if (domainNameBlacklist != null && domainNameBlacklist.size() >= 1) {
            if (isMatchDomainName(baseBurpUrl.getRequestHost(), domainNameBlacklist)) {
                return;
            }
        }

        // 判断域名白名单
        if (domainNameWhitelist != null && domainNameWhitelist.size() >= 1) {
            if (!isMatchDomainName(baseBurpUrl.getRequestHost(), domainNameWhitelist)) {
                return;
            }
        }
        // 判断当前请求后缀,是否为url黑名单后缀
        if (this.isUrlBlackListSuffix(baseBurpUrl)) {
            return;
        }
        // 对proxy&repeater进行监听
        if (i == IBurpExtenderCallbacks.TOOL_PROXY|| i == IBurpExtenderCallbacks.TOOL_REPEATER){

            stdout.println( helpers.analyzeRequest(iHttpRequestResponse).getContentType());
            FindJsons findJsons = new FindJsons(helpers, iHttpRequestResponse);
            String url = helpers.analyzeRequest(iHttpRequestResponse).getUrl().toString();
            String method = helpers.analyzeRequest(iHttpRequestResponse).getMethod();
            String statusCode = String.valueOf(helpers.analyzeResponse(iHttpRequestResponse.getResponse()).getStatusCode());
            List<String> payloads = this.yamlReader.getStringList("application.remoteCmdExtension.config.payloads");
            Iterator<String> payloadIterator = payloads.iterator();

            String key = null;
            RemoteCmd remoteCmd =null;
            remoteCmd = new RemoteCmd(callbacks,iHttpRequestResponse ,helpers, null);

            if (remoteCmd == null){
                return;
            }
            // 熬夜重点对象
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
                return;
            }

            // 循环调用dnslog，填入payload
            List<Issus> issuses = remoteCmd.insertPayloads(payloadIterator, key);
            for (Issus issus:issuses){
                switch (issus.getState()){
                    case SAVE:
                        this.tags.getScanQueueTagClass().save(id,
                                issus.getPayload(),
                                issus.getMethod(),
                                issus.getUrl(),
                                issus.getStatus(),
                                issus.getResult(),
                                issus.getiHttpRequestResponse());
                        break;
                    case ADD:
                        this.tags.getScanQueueTagClass().add(
                                issus.getPayload(),
                                issus.getMethod(),
                                issus.getUrl(),
                                issus.getStatus(),
                                issus.getResult(),
                                issus.getiHttpRequestResponse());
                    case ERROR:
                    case TIMEOUT:
                        break;
                }
            }
        }
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
}
