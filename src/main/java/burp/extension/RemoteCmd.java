package burp.extension;

import burp.*;

import java.net.URLEncoder;
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

    // 添加payload
    public IHttpRequestResponse run(String payload){
        byte[] request = iHttpRequestResponse.getRequest();
        IRequestInfo requestInfo = helpers.analyzeRequest(request);
        List<String> headers = requestInfo.getHeaders();
        byte[] bytes = helpers.buildHttpMessage(headers, helpers.stringToBytes(payload));
        return callbacks.makeHttpRequest(iHttpRequestResponse.getHttpService(), bytes);
    }


    public IHttpRequestResponse run(String payloads,String key) {
        byte[] bytes;
        byte[] request = iHttpRequestResponse.getRequest();
        IRequestInfo requestInfo = helpers.analyzeRequest(request);
        List<IParameter> parameters = requestInfo.getParameters();
        try {
            // 寻找json param位置
            for (IParameter parameter:parameters){
                if (key.equals(parameter.getName())){
                    IParameter parameter1 = helpers.buildParameter(key, URLEncoder.encode(payloads), IParameter.PARAM_URL);
                    bytes = helpers.updateParameter(request, parameter1);
                    return callbacks.makeHttpRequest(iHttpRequestResponse.getHttpService(),bytes);
                }
            }
        }catch (Exception e){
            throw e;
        }
        return iHttpRequestResponse;
    }

    public void insertPayloads() {
    }
}
