package burp.extension;

import burp.*;
import burp.bean.Issus;
import burp.dnslogs.Ceye;
import burp.dnslogs.DnslogInterface;

import java.io.PrintWriter;
import java.net.URLEncoder;
import java.util.*;

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

    private IRequestInfo iRequestInfo;

//    private List<Issus> issuses;

    private List<String> randomList;

    private List<IHttpRequestResponse> iHttpRequestResponseList;

    private DnslogInterface dnsLog;

    public RemoteCmd(IBurpExtenderCallbacks callbacks,IHttpRequestResponse iHttpRequestResponse, IExtensionHelpers helpers, List<String> payloads) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.payloads = payloads;
        this.iHttpRequestResponse = iHttpRequestResponse;
        this.iRequestInfo = helpers.analyzeRequest(iHttpRequestResponse);
        this.dnsLog = null;
//        this.issuses = new ArrayList<Issus>();
        this.randomList = new ArrayList<>();
        this.iHttpRequestResponseList = new ArrayList<>();
    }

    // 添加payload
    public IHttpRequestResponse run(String payload){

        List<String> headers = this.iRequestInfo.getHeaders();
        byte[] bytes = helpers.buildHttpMessage(headers, helpers.stringToBytes(payload));
        return callbacks.makeHttpRequest(iHttpRequestResponse.getHttpService(), bytes);
    }


    public IHttpRequestResponse run(String payloads,String key) {
        byte[] bytes;
        byte[] request = iHttpRequestResponse.getRequest();
        try {
            List<IParameter> parameters = this.iRequestInfo.getParameters();
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


    public List<Issus> insertPayloads(Iterator<String> payloadIterator, String jsonKey) {
        boolean flag = true;
        boolean havePoc = false;
        Issus issus = null;
        List<Issus> issuses = new ArrayList<>();

        IHttpRequestResponse newRequestResonse = null;
        while (payloadIterator.hasNext()){
            try {
                Thread.sleep(400);
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }
            // dnslos 平台初始化
            Ceye ceye = new Ceye();
            String dnsurl = String.format("%s.%s.ceye.io", ceye.getPredomain(), ceye.getKey());


            String payload = payloadIterator.next();
            if (jsonKey == null || jsonKey.length()<=0){
                newRequestResonse = run(payload.replace("dnslog-url",dnsurl));
            }else {
                newRequestResonse = run(payload.replace("dnslog-url",dnsurl),jsonKey);
            }
            // 记录随机值存入list中，以便二次验证
            this.randomList.add(ceye.getPredomain());
            this.iHttpRequestResponseList.add(newRequestResonse);

            String bodyContent = null;
            // 捕获api.ceye 503异常，避免导致issus未更新
            try {
                bodyContent = ceye.getBodyContent();
            } catch (Exception e) {
                bodyContent = null;
                System.err.println("获取 bodyContent 失败：" + e.getMessage()); // 记录错误信息
            }
            //修正返回issus结果：仅for循环结束后或找到payload后才变为[+]/[-]
            // dns平台返回为空且payload已循环完毕，则[-]， 否则直接跳入下一个循环
            if(bodyContent == null|| bodyContent.length()<=0){
                continue;
            }

            // dns平台有结果且匹配random 则[+]，否则[-]
            if (bodyContent.contains(ceye.getPredomain()+".")){
                havePoc = true;
                // 碰到能检测出多个payload，则更新第一个issus的状态为[+]，后续payload直接add [+]issus进去
                if (flag){
//                    this.tags.getScanQueueTagClass().save(id,method,method,url,statusCode,"[+] fastjson payloads",newRequestResonse);
                    issus = new Issus(this.iRequestInfo.getUrl().toString(),
                            this.iRequestInfo.getMethod(),
                            String.valueOf(helpers.analyzeResponse(this.iHttpRequestResponse.getResponse()).getStatusCode()),
                            payload,
                            "[+] fastjson payloads save",
                            newRequestResonse,
                            Issus.State.SAVE);
                    issuses.add(issus);
                    flag = false;
                }else {
                  issus = new Issus(this.iRequestInfo.getUrl().toString(),
                          this.iRequestInfo.getMethod(),
                            String.valueOf(helpers.analyzeResponse(this.iHttpRequestResponse.getResponse()).getStatusCode()),
                            payload,
                            "[+] fastjson payloads add",
                            newRequestResonse,
                          Issus.State.ADD);
                    issuses.add(issus);
                }
                // 第一次发现，havePoc = true
                havePoc = true;
            }
        }

        if (havePoc){
            return issuses;
        }
        //加入二次验证后需要在最后进行判断
        // 熬夜重点对象
        issuses = checkoutDnslog(new Ceye(),randomList,iHttpRequestResponseList);
        PrintWriter printWriter = new PrintWriter(callbacks.getStdout(), true);
        printWriter.println("second: " + this.iRequestInfo.getUrl().toString());

        return issuses;
    }
    private List<Issus> checkoutDnslog(DnslogInterface dnslog,List<String>randlist,List<IHttpRequestResponse> httpRequestResponseList) {
        List<Issus> issuses = new ArrayList<>();
        try {
            Thread.sleep(8000);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }

        // 开始进行二次验证
        Issus issus;
        try {
            String dnsLogAllContent = dnslog.getAllContent();
            if (dnsLogAllContent == null || dnsLogAllContent.length() <= 0) {
                issus = new Issus(this.iRequestInfo.getUrl().toString(),
                        this.iRequestInfo.getMethod(),
                        String.valueOf(helpers.analyzeResponse(this.iHttpRequestResponse.getResponse()).getStatusCode()),
                        "twice function",
                        "[-] fastjson payloads not find",
                        this.iHttpRequestResponse,
                        Issus.State.SAVE);
                issuses.add(issus);
            }else {
                // 这里进行二次判断
                boolean isFirst = true;
                for (int i = 0; i < randlist.size(); i++) {
                    // dnslog 内容匹配判断
                    if (!dnsLogAllContent.contains(randlist.get(i))) {
                        if ((i + 1) != randlist.size()) {
                            continue;
                        } else {
                            issus = new Issus(this.iRequestInfo.getUrl().toString(),
                                    this.iRequestInfo.getMethod(),
                                    String.valueOf(helpers.analyzeResponse(httpRequestResponseList.get(i).getResponse()).getStatusCode()),
                                    "twice function 2",
                                    "[-] fastjson payloads not find",
                                    httpRequestResponseList.get(i),
                                    Issus.State.SAVE);
                            issuses.add(issus);
                            return issuses;
                        }
                    }
                    if (isFirst){
                        issus = new Issus(this.iRequestInfo.getUrl().toString(),
                                this.iRequestInfo.getMethod(),
                                String.valueOf(helpers.analyzeResponse(httpRequestResponseList.get(i).getResponse()).getStatusCode()),
                                "twice function",
                                "[+] fastjson payloads save2",
                                httpRequestResponseList.get(i),
                                Issus.State.SAVE);
                        issuses.add(issus);
                        isFirst = false;
                    }else {
                        issus = new Issus(this.iRequestInfo.getUrl().toString(),
                                this.iRequestInfo.getMethod(),
                                String.valueOf(helpers.analyzeResponse(httpRequestResponseList.get(i).getResponse()).getStatusCode()),
                                "twice function",
                                "[+] fastjson payloads add2",
                                httpRequestResponseList.get(i),
                                Issus.State.ADD);
                        issuses.add(issus);
                    }
                }
            }
            return issuses;
        } catch (Exception e) {
            issus = new Issus(this.iRequestInfo.getUrl().toString(),
                    this.iRequestInfo.getMethod(),
                    String.valueOf(helpers.analyzeResponse(this.iHttpRequestResponse.getResponse()).getStatusCode()),
                    "twice function",
                    "[-] dnslog error",
                    this.iHttpRequestResponse,
                    Issus.State.SAVE);
            issuses.add(issus);
            return issuses;
        }
    }
}
