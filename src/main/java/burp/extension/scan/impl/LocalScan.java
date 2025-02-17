package burp.extension.scan.impl;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.bean.CustomBurpUrl;
import burp.bean.Issus;
import burp.bean.ScanResultType;
import burp.extension.scan.BaseScan;
import burp.utils.Customhelps;
import burp.utils.YamlReader;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import static burp.utils.Customhelps.tabFormat;

/**
 * @ClassName: LocalScan
 * @Auther: niko
 * @Date: 2025/2/7 22:45
 * @Description:
 */
public class LocalScan extends BaseScan {

    public LocalScan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse iHttpRequestResponse, IExtensionHelpers helpers,boolean isBypass) {
        super(callbacks, iHttpRequestResponse, helpers, isBypass);
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
        List<String> headers = new ArrayList<>();
        headers = customBurpUrl.getHttpRequestHeaders();
        headers.add(cmdHeader);
        byte[] bytes = helpers.buildHttpMessage(headers, new byte[0]);
        iHttpRequestResponse = callbacks.makeHttpRequest(iHttpRequestResponse.getHttpService(),bytes);
        customBurpUrl = new CustomBurpUrl(callbacks,iHttpRequestResponse);
        while (payloadIterator.hasNext()){
            String payload = payloadIterator.next();
            if (jsonKey ==null || jsonKey.length()<=0){
                newRequestResonse = run(payload);

            }else {
                newRequestResonse = run(payload, jsonKey);
            }
            try {
                Thread.sleep(3000);
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }
            String responseBody = null;
            responseBody = customBurpUrl.getHttpResponseBody();
            if (responseBody.contains(randomString)){
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
            }
        }
        if (issuses.isEmpty()){
            issus = new Issus(customBurpUrl.getHttpRequestUrl(),
                    customBurpUrl.getRequestMethod(),
                    getExtensionName(),
                    customBurpUrl.getHttpResponseStatus(),
                    null,
                    tabFormat(ScanResultType.NOT_FOUND),
                    this.iHttpRequestResponse,
                    Issus.State.SAVE);
            issuses.add(issus);
        }
        return issuses;
    }

    @Override
    public String getExtensionName() {
        return "LocalScan";
    }
}
