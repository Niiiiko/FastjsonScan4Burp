package burp;

import burp.ui.Tags;
import burp.utils.FindJsons;

import java.io.PrintWriter;
import java.util.List;

/**
 * @ClassName: FastjsonScan
 * @Auther: niko
 * @Date: 2025/1/16 17:07
 * @Description:
 */
public class FastjsonScan implements IBurpExtender,IExtensionStateListener,IScannerCheck,IHttpListener{
    private IBurpExtenderCallbacks callbacks;
    public String name = "FastjsonScan";
    private IScanIssue iScanIssue;
    private PrintWriter printWriter;

    private IExtensionHelpers helpers;
    private Tags tags;

    private PrintWriter stdout;
    private PrintWriter stderr;
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);
        this.tags = new Tags(callbacks, name);
        stdout.println("success");

        callbacks.addSuiteTab(this.tags);
        callbacks.registerHttpListener(this);
    }

    @Override
    public void extensionUnloaded() {

    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse iHttpRequestResponse) {
        return null;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse iHttpRequestResponse, IScannerInsertionPoint iScannerInsertionPoint) {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue iScanIssue, IScanIssue iScanIssue1) {
        return 0;
    }

    @Override
    public void processHttpMessage(int i, boolean b, IHttpRequestResponse iHttpRequestResponse) {
        // 对proxy&repeater进行监听
        if (i == IBurpExtenderCallbacks.TOOL_PROXY|| i == IBurpExtenderCallbacks.TOOL_REPEATER){
            stdout.println( helpers.analyzeRequest(iHttpRequestResponse).getContentType());
            FindJsons findJsons = new FindJsons(helpers, iHttpRequestResponse);
            String url = helpers.analyzeRequest(iHttpRequestResponse).getUrl().toString();
            String method = helpers.analyzeRequest(iHttpRequestResponse).getMethod();
            String statusCode = String.valueOf(helpers.analyzeResponse(iHttpRequestResponse.getResponse()).getStatusCode());
            String out = method + " : " + url + " : " + statusCode;
            if (findJsons.isParamsJson().isFlag()){
                stdout.println(findJsons.isParamsJson().getJson());
                this.tags.getScanQueueTagClass().add(method,method,url,statusCode,findJsons.isParamsJson().getJson(),iHttpRequestResponse);
            }else if (findJsons.isContypeJson().isFlag()){
                stdout.println(findJsons.isContypeJson().getJson());
                this.tags.getScanQueueTagClass().add(method,method,url,statusCode,findJsons.isContypeJson().getJson(),iHttpRequestResponse);
            }
        }
    }
}
