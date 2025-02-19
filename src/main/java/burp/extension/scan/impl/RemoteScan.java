package burp.extension.scan.impl;

import burp.*;
import burp.bean.Issus;
import burp.bean.ScanResultType;
import burp.dnslogs.DnsLog;
import burp.dnslogs.DnslogInterface;
import burp.extension.scan.BaseScan;
import burp.utils.YamlReader;

import java.io.PrintWriter;
import java.lang.reflect.InvocationTargetException;
import java.util.*;

import static burp.utils.Customhelps.tabFormat;

/**
 * @ClassName: RemoteCmd
 * @Auther: niko
 * @Date: 2025/1/20 17:25
 * @Description:
 */
public class RemoteScan extends BaseScan {
    public RemoteScan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse iHttpRequestResponse, IExtensionHelpers helpers,boolean isBypass,String dnsName) {
        super(callbacks,iHttpRequestResponse,helpers, isBypass, dnsName);
    }

    @Override
    public List<Issus> insertPayloads(String jsonKey) throws ClassNotFoundException, InvocationTargetException, NoSuchMethodException, IllegalAccessException, InstantiationException {
        boolean flag = true;
        List<String> payloads = yamlReader.getStringList("application.remoteCmdExtension.config.payloads");
        Iterator<String> payloadIterator = payloads.iterator();
        Issus issus = null;
        List<Issus> issuses = new ArrayList<>();
        // dnslos 平台初始化
        IHttpRequestResponse newRequestResonse = null;
        while (payloadIterator.hasNext()){
            DnslogInterface dnslog = new DnsLog(callbacks, dnsName).run();
            String dnsurl = dnslog.getRandomDnsUrl();
            String payload = payloadIterator.next();
            payload = payload.replace("dnslog-url",dnsurl);
            if (jsonKey == null){
                newRequestResonse = run(payload);
            }else {
                newRequestResonse = run(payload,jsonKey);
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
            exportLogs(getExtensionName(),helpers.analyzeRequest(iHttpRequestResponse).getUrl().toString(),jsonKey,payload.replace("dnslog-url",dnsurl),bodyContent);
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
                            tabFormat(ScanResultType.PAYLOADS_FIND),
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
                          tabFormat(ScanResultType.PAYLOADS_FIND),
                            newRequestResonse,
                          Issus.State.ADD);
                    issuses.add(issus);
                }
                // 第一次发现，havePoc = true
            }
        }

        if (!issuses.isEmpty()){
            return issuses;
        }
        //todo 修正二次验证函数判断
        issuses = checkoutDnslog(getExtensionName(),new DnsLog(callbacks, dnsName).run(),randomList,iHttpRequestResponseList,payloads,null);
        return issuses;
    }

    @Override
    public String getExtensionName() {
        return "RemoteScan";
    }
}
