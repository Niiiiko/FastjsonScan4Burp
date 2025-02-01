package burp.bean;

import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;

/**
 * @ClassName: ReqResp
 * @Auther: niko
 * @Date: 2025/2/1 19:28
 * @Description:
 */
public class ReqResp {
    private IHttpRequestResponse iHttpRequestResponse;
    private IExtensionHelpers helpers;

    public ReqResp(IHttpRequestResponse iHttpRequestResponse,IExtensionHelpers helpers){
        this.helpers = helpers;
        this.iHttpRequestResponse = iHttpRequestResponse;
        IRequestInfo iRequestInfo = helpers.analyzeRequest(iHttpRequestResponse);


    }

}
