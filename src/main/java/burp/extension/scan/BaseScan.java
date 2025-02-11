package burp.extension.scan;

import burp.*;
import burp.bean.CustomBurpUrl;
import burp.bean.Issus;
import burp.dnslogs.DnslogInterface;
import burp.utils.YamlReader;

import java.lang.reflect.InvocationTargetException;
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

    protected CustomBurpUrl customBurpUrl;
    protected List<String> randomList;

    protected List<IHttpRequestResponse> iHttpRequestResponseList;

    protected DnslogInterface dnsLog;
    protected YamlReader yamlReader;

    protected BaseScan(IBurpExtenderCallbacks callbacks,IHttpRequestResponse iHttpRequestResponse, IExtensionHelpers helpers) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.payloads = new ArrayList<>();
        this.yamlReader = YamlReader.getInstance(callbacks);
        this.iHttpRequestResponse = iHttpRequestResponse;
        this.dnsLog = null;
        this.customBurpUrl = new CustomBurpUrl(callbacks,iHttpRequestResponse);
        this.randomList = new ArrayList<>();
        this.iHttpRequestResponseList = new ArrayList<>();
    }

    protected IHttpRequestResponse run(String payload){
        try {
            Thread.sleep(1200);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
        List<String> headers = customBurpUrl.getHttpRequestHeaders();
        byte[] bytes = helpers.buildHttpMessage(headers, helpers.stringToBytes(payload));
        IHttpRequestResponse newRequestResp = callbacks.makeHttpRequest(iHttpRequestResponse.getHttpService(), bytes);
        this.customBurpUrl = new CustomBurpUrl(callbacks,newRequestResp);
        return newRequestResp;
    }


    protected IHttpRequestResponse run(String payloads,String key) {
        try {
            Thread.sleep(1200);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
        byte[] request = iHttpRequestResponse.getRequest();
        try {
            List<IParameter> parameters = customBurpUrl.getHttpRequestParameters();
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
                    IHttpRequestResponse newRequestResp = callbacks.makeHttpRequest(iHttpRequestResponse.getHttpService(), request);
                    this.customBurpUrl = new CustomBurpUrl(callbacks,newRequestResp);
                    return newRequestResp;
                }
            }

        }catch (Exception e){
            throw e;
        }
        return iHttpRequestResponse;
    }
    public abstract List<Issus> insertPayloads(String jsonKey) throws ClassNotFoundException, InvocationTargetException, NoSuchMethodException, IllegalAccessException, InstantiationException;

}
