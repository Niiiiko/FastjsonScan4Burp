package burp.extension.impl;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.bean.Issus;
import burp.extension.BaseScan;
import burp.utils.Customhelps;
import burp.utils.YamlReader;

import java.io.UnsupportedEncodingException;
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
    private YamlReader yamlReader;

    public LocalScan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse iHttpRequestResponse, IExtensionHelpers helpers) {
        super(callbacks, iHttpRequestResponse, helpers);
    }

    @Override
    public List<Issus> insertPayloads(Iterator<String> payloadIterator, String jsonKey) {
        boolean flag = true;
        IHttpRequestResponse newRequestResonse = null;
        List<Issus> issuses = new ArrayList<>();
        Issus issus = null;
        this.yamlReader = YamlReader.getInstance(callbacks);
        String cmdHeader = this.yamlReader.getString("application.cmdEchoExtension.config.commandInputPointField");
        String randomString = new Customhelps().randomString(16);
        cmdHeader = cmdHeader + ": echo " + randomString;
        List<String> headers = iRequestInfo.getHeaders();
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
            IRequestInfo response = helpers.analyzeRequest(newRequestResonse.getResponse());
            int bodyOffset = response.getBodyOffset();
            int bodylength = newRequestResonse.getResponse().length - bodyOffset;
            String responseBody = null;
            try {
                responseBody = new String(newRequestResonse.getResponse(), bodyOffset, bodylength, "UTF-8");
            } catch (UnsupportedEncodingException e) {
                throw new RuntimeException(e);
            }
            if (responseBody.contains(randomString)){
                if (flag){
                    issus = new Issus(this.iRequestInfo.getUrl(),
                            this.iRequestInfo.getMethod(),
                            String.valueOf(helpers.analyzeResponse(this.iHttpRequestResponse.getResponse()).getStatusCode()),
                            payload,
                            "[+] fastjson payloads save",
                            newRequestResonse,
                            Issus.State.SAVE);
                    issuses.add(issus);
                    flag = false;
                }else {
                    issus = new Issus(this.iRequestInfo.getUrl(),
                            this.iRequestInfo.getMethod(),
                            String.valueOf(helpers.analyzeResponse(this.iHttpRequestResponse.getResponse()).getStatusCode()),
                            payload,
                            "[+] fastjson payloads save",
                            newRequestResonse,
                            Issus.State.ADD);
                    issuses.add(issus);
                }
            }
        }
        if (issuses.isEmpty()){
            issus = new Issus(this.iRequestInfo.getUrl(),
                    this.iRequestInfo.getMethod(),
                    String.valueOf(helpers.analyzeResponse(this.iHttpRequestResponse.getResponse()).getStatusCode()),
                    null,
                    "[-] fastjson payloads not find",
                    this.iHttpRequestResponse,
                    Issus.State.SAVE);
            issuses.add(issus);
        }
        return issuses;
    }
}
