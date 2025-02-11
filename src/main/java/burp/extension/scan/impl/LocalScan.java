package burp.extension.scan.impl;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.bean.Issus;
import burp.extension.scan.BaseScan;
import burp.utils.Customhelps;
import burp.utils.YamlReader;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * @ClassName: LocalScan
 * @Auther: niko
 * @Date: 2025/2/7 22:45
 * @Description:
 */
public class LocalScan extends BaseScan {

    public LocalScan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse iHttpRequestResponse, IExtensionHelpers helpers) {
        super(callbacks, iHttpRequestResponse, helpers);
    }

    @Override
    public List<Issus> insertPayloads(String jsonKey) {
        boolean flag = true;
        IHttpRequestResponse newRequestResonse = null;
        List<Issus> issuses = new ArrayList<>();
        Issus issus = null;
        List<String> payloads = this.yamlReader.getStringList("application.cmdEchoExtension.config.payloads");
        Iterator<String> payloadIterator = payloads.iterator();
        String cmdHeader = this.yamlReader.getString("application.cmdEchoExtension.config.commandInputPointField");
        String randomString = new Customhelps().randomString(16);
        cmdHeader = cmdHeader + ": echo " + randomString;
        List<String> headers = customBurpUrl.getHttpRequestHeaders();
        headers.add(cmdHeader);
        byte[] bytes = helpers.buildHttpMessage(headers, new byte[0]);
        iHttpRequestResponse = callbacks.makeHttpRequest(iHttpRequestResponse.getHttpService(),bytes);
        while (payloadIterator.hasNext()){
            String payload = payloadIterator.next();
            if (jsonKey ==null || jsonKey.length()<=0){
                newRequestResonse = run(payload);
            }else {
                newRequestResonse = run(payload, jsonKey);
            }
            try {
                Thread.sleep(5000);
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }
            String responseBody = null;
            responseBody = customBurpUrl.getHttpResponseBody();
            if (responseBody.contains(randomString)){
                if (flag){
                    issus = new Issus(customBurpUrl.getHttpRequestUrl(),
                            customBurpUrl.getRequestQuery(),
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
                            "[+] fastjson payloads save",
                            newRequestResonse,
                            Issus.State.ADD);
                    issuses.add(issus);
                }
            }
        }
        if (issuses.isEmpty()){
            issus = new Issus(customBurpUrl.getHttpRequestUrl(),
                    customBurpUrl.getRequestMethod(),
                    customBurpUrl.getHttpResponseStatus(),
                    null,
                    "[-] fastjson payloads not find",
                    this.iHttpRequestResponse,
                    Issus.State.SAVE);
            issuses.add(issus);
        }
        return issuses;
    }
}
