package burp.extension.scan.impl;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.bean.Issus;
import burp.bean.ScanResultType;
import burp.dnslogs.DnsLog;
import burp.dnslogs.DnslogInterface;
import burp.extension.scan.BaseScan;

import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static burp.utils.Customhelps.tabFormat;

public class versionDetect extends BaseScan {

    public versionDetect(IBurpExtenderCallbacks callbacks, IHttpRequestResponse iHttpRequestResponse, IExtensionHelpers helpers,boolean isBypass) {
        super(callbacks, iHttpRequestResponse, helpers, isBypass);
    }

    @Override
    public List<Issus> insertPayloads(String jsonKey) throws ClassNotFoundException, InvocationTargetException, NoSuchMethodException, IllegalAccessException, InstantiationException {
        boolean flag = true;
        boolean havePoc = false;
        int i = 0 ;
//        先进行不出网报错判断
        List<String> versionList = new ArrayList<>();
        List<String> payloads = yamlReader.getStringList("application.detectVersionExtension.config.regexPayloads");
        Iterator<String> payloadIterator = payloads.iterator();
        Issus issus = null;
        List<Issus> issuses = new ArrayList<>();
        IHttpRequestResponse newRequestResonse = null;

        while (payloadIterator.hasNext()){
            String versionPayload = payloadIterator.next();
            String versionRegex = versionPayload.substring(0,versionPayload.indexOf(";")).trim();
            String payload = versionPayload.substring(versionPayload.indexOf("payload=")+8);
            if (jsonKey == null || jsonKey.length()<=0){
                newRequestResonse = run(payload);
            }else {
                newRequestResonse = run(payload,jsonKey);
            }
            String bodyContent = customBurpUrl.getHttpResponseBody();
            // 捕获api.ceye 503异常，避免导致issus未更新
            exportLogs(getExtensionName(),helpers.analyzeRequest(iHttpRequestResponse).getUrl().toString(),jsonKey,payload,bodyContent);

            if(bodyContent == null|| bodyContent.length()<=0){
                continue;
            }
            Pattern pattern = Pattern.compile(versionRegex);
            Matcher matcher = pattern.matcher(bodyContent);
            if (matcher.find()) {
                versionList.add(matcher.group(1));
                // 碰到能检测出多个payload，则更新第一个issus的状态为[+]，后续payload直接add [+]issus进去
                if (flag){
                    issus = new Issus(customBurpUrl.getHttpRequestUrl(),
                            customBurpUrl.getRequestMethod(),
                            getExtensionName(),
                            customBurpUrl.getHttpResponseStatus(),
                            payload,
                            "[+] fastjson version may " + versionList.get(i),
                            newRequestResonse,
                            Issus.State.SAVE);
                    issuses.add(issus);
                    flag = false;
                }else {
                    issus = new Issus(customBurpUrl.getHttpRequestUrl(),
                            customBurpUrl.getRequestMethod(),
                            getExtensionName(),
                            customBurpUrl.getHttpResponseStatus(),
                            payload,
                            "[+] fastjson version may  " + versionList.get(i),
                            newRequestResonse,
                            Issus.State.ADD);
                    issuses.add(issus);
                }
                // 第一次发现，havePoc = true
                havePoc = true;
            }
            i ++;
        }
        if (!issuses.isEmpty()){
            return issuses;
        }

        payloads = yamlReader.getStringList("application.detectVersionExtension.config.dnslogPayloads");
        payloadIterator = payloads.iterator();

        while (payloadIterator.hasNext()){
            DnslogInterface dnslog = new DnsLog(callbacks, yamlReader.getString("dnsLogModule.provider")).run();
            String dnsurl = dnslog.getRandomDnsUrl();
            String versionPayload = payloadIterator.next();
            String version = versionPayload.substring(0,versionPayload.indexOf(";"));
            String payload = versionPayload.substring(versionPayload.indexOf("payload=")+8);
            if (jsonKey == null || jsonKey.length()<=0){
                newRequestResonse = run(payload.replace("dnslog-url",dnsurl));
            }else {
                newRequestResonse = run(payload.replace("dnslog-url",dnsurl),jsonKey);
            }
            // 记录随机值存入list中，以便二次验证
            randomList.add(dnslog.getRandomPredomain());
            this.iHttpRequestResponseList.add(newRequestResonse);
            this.payloads.add(payload.replace("dnslog-url",dnsurl));
            versionList.add(version);
            String bodyContent = null;
            // 捕获api.ceye 503异常，避免导致issus未更新
            try {
                bodyContent = dnslog.getBodyContent();
            } catch (Exception e) {
                bodyContent = null;
                System.err.println("获取 bodyContent 失败：" + e.getMessage()); // 记录错误信息
            }
            //修正返回issus结果：仅for循环结束后或找到payload后才变为[+]/[-]
            // dns平台返回为空且payload已循环完毕，则[-]， 否则直接跳入下一个循环
            if(bodyContent == null|| bodyContent.length()<=0){
                continue;
            }

            // dns平台有结果且匹配random 则[+]，否则[-]
            if (bodyContent.contains(dnslog.getRandomPredomain())){
                // 碰到能检测出多个payload，则更新第一个issus的状态为[+]，后续payload直接add [+]issus进去
                if (flag){
                    issus = new Issus(customBurpUrl.getHttpRequestUrl(),
                            customBurpUrl.getRequestMethod(),
                            getExtensionName(),
                            customBurpUrl.getHttpResponseStatus(),
                            payload,
                            tabFormat(ScanResultType.VERSION_INFO,version),
                            newRequestResonse,
                            Issus.State.SAVE);
                    issuses.add(issus);
                    flag = false;
                }else {
                    issus = new Issus(customBurpUrl.getHttpRequestUrl(),
                            customBurpUrl.getRequestMethod(),
                            getExtensionName(),
                            customBurpUrl.getHttpResponseStatus(),
                            payload,
                            tabFormat(ScanResultType.VERSION_INFO,version),
                            newRequestResonse,
                            Issus.State.ADD);
                    issuses.add(issus);
                }
                // 第一次发现，havePoc = true
                havePoc = true;
            }
        }

        if (havePoc){
            return issuses;
        }
        //加入二次验证后需要在最后进行判断
        issuses = checkoutDnslog(getExtensionName(),new DnsLog(callbacks, yamlReader.getString("dnsLogModule.provider")).run(),randomList,iHttpRequestResponseList,payloads,versionList);
        return issuses;
    }

    @Override
    public String getExtensionName() {
        return "versionDetect";
    }
//    private List<Issus> checkoutDnslog(DnslogInterface dnslog,List<String>randlist,List<IHttpRequestResponse> httpRequestResponseList,List<String> payloads,List<String> versionList) {
//        List<Issus> issuses = new ArrayList<>();
//        try {
//            Thread.sleep(8000);
//        } catch (InterruptedException e) {
//            throw new RuntimeException(e);
//        }
//
//        // 开始进行二次验证
//        Issus issus;
//        try {
//            String dnsLogAllContent = dnslog.getAllContent();
//            if (dnsLogAllContent == null || dnsLogAllContent.length() <= 0) {
//                issus = new Issus(customBurpUrl.getHttpRequestUrl(),
//                        customBurpUrl.getRequestMethod(),
//                        customBurpUrl.getHttpResponseStatus(),
//                        null,
//                        "[-] fastjson version not find",
//                        this.iHttpRequestResponse,
//                        Issus.State.SAVE);
//                issuses.add(issus);
//            }else {
//                // 这里进行二次判断
//                boolean isFirst = true;
//                for (int i = 0; i < randlist.size(); i++) {
//                    // dnslog 内容匹配判断
//                    if (!dnsLogAllContent.contains(randlist.get(i))) {
//                        if ((i + 1) != randlist.size()) {
//                            continue;
//                        } else {
//                            issus = new Issus(customBurpUrl.getHttpRequestUrl(),
//                                    customBurpUrl.getRequestMethod(),
//                                    customBurpUrl.getHttpResponseStatus(),                                    null,
//                                    "[-] fastjson version not find",
//                                    httpRequestResponseList.get(i),
//                                    Issus.State.SAVE);
//                            issuses.add(issus);
//                            return issuses;
//                        }
//                    }
//                    if (isFirst){
//                        issus = new Issus(customBurpUrl.getHttpRequestUrl(),
//                                customBurpUrl.getRequestMethod(),
//                                customBurpUrl.getHttpResponseStatus(),
//                                payloads.get(i),
//                                "[+] fastjson " + versionList.get(i),
//                                httpRequestResponseList.get(i),
//                                Issus.State.SAVE);
//                        issuses.add(issus);
//                        isFirst = false;
//                    }else {
//                        issus = new Issus(customBurpUrl.getHttpRequestUrl(),
//                                customBurpUrl.getRequestMethod(),
//                                customBurpUrl.getHttpResponseStatus(),
//                                payloads.get(i),
//                                "[+] fastjson " +versionList.get(i),
//                                httpRequestResponseList.get(i),
//                                Issus.State.ADD);
//                        issuses.add(issus);
//                    }
//                }
//            }
//            return issuses;
//        } catch (Exception e) {
//            issus = new Issus(customBurpUrl.getHttpRequestUrl(),
//                    customBurpUrl.getRequestMethod(),
//                    customBurpUrl.getHttpResponseStatus(),
//                    null,
//                    "[-] dnslog error",
//                    this.iHttpRequestResponse,
//                    Issus.State.SAVE);
//            issuses.add(issus);
//            return issuses;
//        }
//    }
}
