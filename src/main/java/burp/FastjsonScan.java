package burp;

import burp.dnslogs.Ceye;
import burp.extension.RemoteCmd;
import burp.ui.Tags;
import burp.utils.Customhelps;
import burp.utils.FindJsons;
import burp.utils.YamlReader;

import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashMap;
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
    private YamlReader yamlReader;
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
            System.out.println();
            // 后续考虑剥离：读取yml文件，获取payloads
            this.yamlReader = YamlReader.getInstance(callbacks);
            List<String> payloads = this.yamlReader.getStringList("application.remoteCmdExtension.config.payloads");
            // 任务id
            int id = 0;
            //
            List<String> randomList = new ArrayList<String >();
            //
            List<IHttpRequestResponse> httpRequestResponseList = new ArrayList<IHttpRequestResponse >();
            // 判断数据包中是否存在json，有则加入到tags中
            if (findJsons.isParamsJson().isFlag()){
                // 先添加任务
                id = this.tags.getScanQueueTagClass().add(method, method, url, statusCode, "find json param.wait for testing.", iHttpRequestResponse);

                String key = findJsons.isParamsJson().getKey();
                RemoteCmd remoteCmd = new RemoteCmd(callbacks,iHttpRequestResponse ,helpers, null);
                boolean flag = true;
                // 循环调用dnslog，填入payload
                for(String payload : payloads){
                    Ceye ceye = new Ceye();
//                    randomList.add(ceye.getPredomain());
                    String dnsurl = String.format("%s.%s.ceye.io", ceye.getPredomain(), ceye.getKey());
                    IHttpRequestResponse newRequestResonse = remoteCmd.run(payload.replace("dnslog-url",dnsurl),key);
//                    httpRequestResponseList.add(newRequestResonse);
                    String bodyContent = ceye.getBodyContent();
                    if (bodyContent == null|| bodyContent.length()<=0){
                        this.tags.getScanQueueTagClass().save(id,method,method,url,statusCode,"[-] fastjson payloads not find",iHttpRequestResponse);
                    }else if (bodyContent.contains(ceye.getPredomain()+".")){
                        if (flag){
                            this.tags.getScanQueueTagClass().save(id,method,method,url,statusCode,"[+] fastjson payloads",newRequestResonse);
                            flag = false;
                        }
                        this.tags.getScanQueueTagClass().add(method,method,url,statusCode,"[+] fastjson payloads",newRequestResonse);
                    }
                }
            }else if (findJsons.isContypeJson().isFlag()){
                id = this.tags.getScanQueueTagClass().add(method, method, url, statusCode, "find json body. wait for testing.", iHttpRequestResponse);

                RemoteCmd remoteCmd = new RemoteCmd(callbacks, iHttpRequestResponse,helpers, null);
                for(String payload : payloads){
                    Ceye ceye = new Ceye();
                    String dnsurl = String.format("%s.%s.ceye.io", ceye.getPredomain(), ceye.getKey());
                    IHttpRequestResponse newRequestResonse = remoteCmd.run(payload.replace("dnslog-url",dnsurl));
                    String bodyContent = ceye.getBodyContent();
                    if (bodyContent.contains(ceye.getPredomain())){
                        this.tags.getScanQueueTagClass().save(id,method,method,url,statusCode,"[+] fastjson payloads",newRequestResonse);
                    }else {
                        this.tags.getScanQueueTagClass().save(id,method,method,url,statusCode,"[-] fastjson payloads not find",newRequestResonse);
                    }
                }
            }
        }
    }
}
