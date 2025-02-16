package burp.extension.scan.impl;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IParameter;
import burp.bean.CustomBurpUrl;
import burp.bean.Issus;
import burp.bean.ScanResultType;
import burp.dnslogs.DnsLog;
import burp.dnslogs.DnslogInterface;
import burp.extension.scan.BaseScan;
import burp.utils.Customhelps;

import java.lang.reflect.InvocationTargetException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import static burp.utils.Customhelps.tabFormat;

public class lowPerceptScan extends BaseScan {


    public lowPerceptScan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse iHttpRequestResponse, IExtensionHelpers helpers,boolean isBypass) {
        super(callbacks, iHttpRequestResponse, helpers, isBypass);
    }

    @Override
    public List<Issus> insertPayloads(String jsonKey) throws ClassNotFoundException, InvocationTargetException, NoSuchMethodException, IllegalAccessException, InstantiationException {

        boolean flag = true;
        IHttpRequestResponse newRequestResonse = null;
        List<Issus> issuses = new ArrayList<>();
        boolean havePoc = false;
        Issus issus = null;
        if (jsonKey ==null || jsonKey.length()<=0){
            String httpRequestBody = customBurpUrl.getHttpRequestBody();
            List<String> headers = customBurpUrl.getHttpRequestHeaders();
            byte[] bytes = helpers.buildHttpMessage(headers, helpers.stringToBytes(httpRequestBody.replace("}","")));
            newRequestResonse = callbacks.makeHttpRequest(iHttpRequestResponse.getHttpService(), bytes);
            this.customBurpUrl = new CustomBurpUrl(callbacks,newRequestResonse);
        }else {
            byte[] request = iHttpRequestResponse.getRequest();
            try {
                List<IParameter> parameters = customBurpUrl.getHttpRequestParameters();
                // 寻找json param位置
                for (IParameter parameter:parameters){
                    if (jsonKey.equals(parameter.getName())){
                        IParameter newParam = null;
                        // 如果参数在 URL 中
                        if (parameter.getType() == IParameter.PARAM_URL) {
                            newParam = helpers.buildParameter(jsonKey, parameter.getValue().replace("%7d",""), IParameter.PARAM_URL);
                        }
                        // 如果参数在 POST body 中
                        else if (parameter.getType() == IParameter.PARAM_BODY) {
                            newParam = helpers.buildParameter(jsonKey, parameter.getValue().replace("%7d",""), IParameter.PARAM_BODY);
                        }
                        request = helpers.updateParameter(request, newParam);
                        newRequestResonse = callbacks.makeHttpRequest(iHttpRequestResponse.getHttpService(), request);
                        this.customBurpUrl = new CustomBurpUrl(callbacks,newRequestResonse);
                    }
                }
            }catch (Exception e){
                throw e;
            }
        }
        if (customBurpUrl.getHttpResponseBody().toLowerCase().contains("syntax error")){
                issus = new Issus(customBurpUrl.getHttpRequestUrl(),
                        customBurpUrl.getRequestMethod(),
                        getExtensionName(),
                        customBurpUrl.getHttpResponseStatus(),
                        "{",
                        tabFormat(ScanResultType.MAY_FASTJSON),
                        newRequestResonse,
                        Issus.State.SAVE);
                issuses.add(issus);
                flag = false;
            }
        List<String> payloads = this.yamlReader.getStringList("application.lowPerceptionScan.config.dnslogPayloads");
        Iterator<String> payloadIterator = payloads.iterator();
        while (payloadIterator.hasNext()){
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
                            getExtensionName(),
                            customBurpUrl.getHttpResponseStatus(),
                            payload,
                            tabFormat(ScanResultType.IS_FASTJSON),
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
                            tabFormat(ScanResultType.IS_FASTJSON),
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
        issuses = checkoutDnslog(getExtensionName(),new DnsLog(callbacks, yamlReader.getString("dnsLogModule.provider")).run(),randomList,iHttpRequestResponseList,payloads,null);
        return issuses;
    }




    @Override
    public String getExtensionName() {
        return "lowPerceptScan";
    }
}
