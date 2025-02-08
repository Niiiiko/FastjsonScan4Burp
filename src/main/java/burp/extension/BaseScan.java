package burp.extension;

import burp.*;
import burp.bean.Issus;
import burp.dnslogs.DnslogInterface;

import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

/**
 * @ClassName: BaseScan
 * @Auther: niko
 * @Date: 2025/2/7 21:50
 * @Description:
 */
public abstract class BaseScan {
    protected IBurpExtenderCallbacks callbacks;

    protected IExtensionHelpers helpers;

    protected List<String> payloads;

    protected IHttpRequestResponse iHttpRequestResponse;

    protected IRequestInfo iRequestInfo;

    protected List<String> randomList;

    protected List<IHttpRequestResponse> iHttpRequestResponseList;

    protected DnslogInterface dnsLog;

    protected BaseScan(IBurpExtenderCallbacks callbacks,IHttpRequestResponse iHttpRequestResponse, IExtensionHelpers helpers) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.payloads = new ArrayList<>();
        this.iHttpRequestResponse = iHttpRequestResponse;
        this.iRequestInfo = helpers.analyzeRequest(iHttpRequestResponse);
        this.dnsLog = null;
//        this.issuses = new ArrayList<Issus>();
        this.randomList = new ArrayList<>();
        this.iHttpRequestResponseList = new ArrayList<>();
    }

    protected IHttpRequestResponse run(String payload){
        try {
            Thread.sleep(1200);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
        List<String> headers = this.iRequestInfo.getHeaders();
        byte[] bytes = helpers.buildHttpMessage(headers, helpers.stringToBytes(payload));
        return callbacks.makeHttpRequest(iHttpRequestResponse.getHttpService(), bytes);
    }


    protected IHttpRequestResponse run(String payloads,String key) {
        try {
            Thread.sleep(1200);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
        byte[] request = iHttpRequestResponse.getRequest();
        try {
            List<IParameter> parameters = this.iRequestInfo.getParameters();
            // 寻找json param位置
            for (IParameter parameter:parameters){
                if (key.equals(parameter.getName())){
                    IParameter newParam = null;
                    // 如果参数在 URL 中
                    if (parameter.getType() == IParameter.PARAM_URL) {
                        newParam = helpers.buildParameter(key, URLEncoder.encode(payloads), IParameter.PARAM_URL);
                    }
                    // 如果参数在 POST body 中
                    else if (parameter.getType() == IParameter.PARAM_BODY) {
                        newParam = helpers.buildParameter(key, URLEncoder.encode(payloads), IParameter.PARAM_BODY);
                    }
                    request = helpers.updateParameter(request, newParam);
                    return callbacks.makeHttpRequest(iHttpRequestResponse.getHttpService(),request);
                }
            }

        }catch (Exception e){
            throw e;
        }
        return iHttpRequestResponse;
    }
    public abstract List<Issus> insertPayloads(Iterator<String> payloadIterator, String jsonKey);

}
