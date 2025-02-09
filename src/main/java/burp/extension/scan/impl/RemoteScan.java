package burp.extension.scan.impl;

import burp.*;
import burp.bean.Issus;
import burp.dnslogs.DnsLog;
import burp.dnslogs.DnslogInterface;
import burp.extension.scan.BaseScan;
import burp.utils.YamlReader;

import java.io.PrintWriter;
import java.lang.reflect.InvocationTargetException;
import java.util.*;

/**
 * @ClassName: RemoteCmd
 * @Auther: niko
 * @Date: 2025/1/20 17:25
 * @Description:
 */
public class RemoteScan extends BaseScan {
    public RemoteScan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse iHttpRequestResponse, IExtensionHelpers helpers) {
        super(callbacks,iHttpRequestResponse,helpers);
    }

    @Override
    public List<Issus> insertPayloads(Iterator<String> payloadIterator, String jsonKey) throws ClassNotFoundException, InvocationTargetException, NoSuchMethodException, IllegalAccessException, InstantiationException {
        boolean flag = true;
        boolean havePoc = false;
        Issus issus = null;
        List<Issus> issuses = new ArrayList<>();
        // dnslos 平台初始化
        YamlReader yamlReader = YamlReader.getInstance(callbacks);
        IHttpRequestResponse newRequestResonse = null;
        while (payloadIterator.hasNext()){
//            try {
//                Thread.sleep(1200);
//            } catch (InterruptedException e) {
//                throw new RuntimeException(e);
//            }
            DnslogInterface dnslog = new DnsLog(callbacks, yamlReader.getString("dnsLogModule.provider")).run();
            String dnsurl = dnslog.getRandomDnsUrl();
            String payload = payloadIterator.next();
            if (jsonKey == null || jsonKey.length()<=0){
                newRequestResonse = run(payload.replace("dnslog-url",dnsurl));
            }else {
                newRequestResonse = run(payload.replace("dnslog-url",dnsurl),jsonKey);
            }
            // 记录随机值存入list中，以便二次验证
            randomList.add(dnslog.getRandomPredomain());
            this.iHttpRequestResponseList.add(newRequestResonse);
            this.payloads.add(payload.replace("dnslog-url",dnsurl));

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
                            customBurpUrl.getHttpResponseStatus(),
                            payload,
                            "[+] fastjson payloads save",
                            newRequestResonse,
                            Issus.State.SAVE);
                    issuses.add(issus);
                    flag = false;
                }else {
                  issus = new Issus(customBurpUrl.getHttpRequestUrl(),
                          customBurpUrl.getRequestMethod(),
                          customBurpUrl.getHttpResponseStatus(),
                            payload,
                            "[+] fastjson payloads add",
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
        // 熬夜重点对象
        issuses = checkoutDnslog(new DnsLog(callbacks, yamlReader.getString("dnsLogModule.provider")).run(),randomList,iHttpRequestResponseList,payloads);
        return issuses;
    }
    private List<Issus> checkoutDnslog(DnslogInterface dnslog,List<String>randlist,List<IHttpRequestResponse> httpRequestResponseList,List<String> payloads) {
        List<Issus> issuses = new ArrayList<>();
        try {
            Thread.sleep(8000);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }

        // 开始进行二次验证
        Issus issus;
        try {
            String dnsLogAllContent = dnslog.getAllContent();
            if (dnsLogAllContent == null || dnsLogAllContent.length() <= 0) {
                issus = new Issus(customBurpUrl.getHttpRequestUrl(),
                        customBurpUrl.getRequestMethod(),
                        customBurpUrl.getHttpResponseStatus(),
                        null,
                        "[-] fastjson payloads not find",
                        this.iHttpRequestResponse,
                        Issus.State.SAVE);
                issuses.add(issus);
            }else {
                // 这里进行二次判断
                boolean isFirst = true;
                for (int i = 0; i < randlist.size(); i++) {
                    // dnslog 内容匹配判断
                    if (!dnsLogAllContent.contains(randlist.get(i))) {
                        if ((i + 1) != randlist.size()) {
                            continue;
                        } else {
                            issus = new Issus(customBurpUrl.getHttpRequestUrl(),
                                    customBurpUrl.getRequestMethod(),
                                    customBurpUrl.getHttpResponseStatus(),                                    null,
                                    "[-] fastjson payloads not find",
                                    httpRequestResponseList.get(i),
                                    Issus.State.SAVE);
                            issuses.add(issus);
                            return issuses;
                        }
                    }
                    if (isFirst){
                        issus = new Issus(customBurpUrl.getHttpRequestUrl(),
                                customBurpUrl.getRequestMethod(),
                                customBurpUrl.getHttpResponseStatus(),
                                payloads.get(i),
                                "[+] fastjson payloads save2",
                                httpRequestResponseList.get(i),
                                Issus.State.SAVE);
                        issuses.add(issus);
                        isFirst = false;
                    }else {
                        issus = new Issus(customBurpUrl.getHttpRequestUrl(),
                                customBurpUrl.getRequestMethod(),
                                customBurpUrl.getHttpResponseStatus(),
                                payloads.get(i),
                                "[+] fastjson payloads add2",
                                httpRequestResponseList.get(i),
                                Issus.State.ADD);
                        issuses.add(issus);
                    }
                }
            }
            return issuses;
        } catch (Exception e) {
            issus = new Issus(customBurpUrl.getHttpRequestUrl(),
                    customBurpUrl.getRequestMethod(),
                    customBurpUrl.getHttpResponseStatus(),
                    null,
                    "[-] dnslog error",
                    this.iHttpRequestResponse,
                    Issus.State.SAVE);
            issuses.add(issus);
            return issuses;
        }
    }
}
