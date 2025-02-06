package burp.bean;

import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IScanIssue;

import java.net.URL;

/**
 * @ClassName: Issus
 * @Auther: niko
 * @Date: 2025/2/1 19:22
 * @Description:
 */
///**
// *
// * @param url 漏洞地址
// * @param issueName 漏洞名
// * @param issueType 漏洞类型?，默认0，不知道干啥的
// * @param severity 漏洞等级；"High", "Medium", "Low", "Information" "False positive" 5选1
// * @param confidence 置信度，或者说漏洞存在的信心；"Certain", "Firm" "Tentative" 3选1
// * @param issueBackground 漏洞背景，设置为null不显示
// * @param remediationBackground 修复背景，设置为null不显示
// * @param issueDetail 漏洞描述
// * @param remediationDetail 修复建议
// * @param httpMessages 漏洞请求
// * @param httpService 漏洞的httpService
// */
public class Issus implements IScanIssue {
    public enum State{
        SAVE,ADD,TIMEOUT,ERROR
    }
    private URL url;
    private String method;
    private String status;
    private String payload;
    private String result;
    private IHttpRequestResponse iHttpRequestResponse;
    private State state;

    public Issus(URL url, String method, String status, String payload, String result, IHttpRequestResponse iHttpRequestResponse, State state) {
        this.url = url;
        this.method = method;
        this.status = status;
        this.payload = payload;
        this.result = result;
        this.iHttpRequestResponse = iHttpRequestResponse;
        this.state = state;
    }

    public String getMethod() {
        return method;
    }

    public String getStatus() {
        return status;
    }


    public String getPayload() {
        return payload;
    }


    public String getResult() {
        return result;
    }

    public IHttpRequestResponse getiHttpRequestResponse() {
        return iHttpRequestResponse;
    }




    @Override
    public URL getUrl() {
        return url;
    }

    @Override
    public String getIssueName() {
        return "fastjson rce";
    }

    @Override
    public int getIssueType() {
        return 0;
    }

    @Override
    public String getSeverity() {
        return "High";
    }

    @Override
    public String getConfidence() {
        return "Certain";
    }

    @Override
    public String getIssueBackground() {
        return "漏洞背景";
    }

    @Override
    public String getRemediationBackground() {
        return "修复背景";
    }

    @Override
    public String getIssueDetail() {
        return payload;
    }

    @Override
    public String getRemediationDetail() {
        return "修复建议";
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages() {
        return new IHttpRequestResponse[]{iHttpRequestResponse};
    }

    @Override
    public IHttpService getHttpService() {
        return iHttpRequestResponse.getHttpService();
    }

    public void setUrl(URL url) {
        this.url = url;
    }

    public State getState() {
        return state;
    }

    public void setPayload(String payload) {
        this.payload = payload;
    }
}
