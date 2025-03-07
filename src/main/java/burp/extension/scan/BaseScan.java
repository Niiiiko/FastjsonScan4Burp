package burp.extension.scan;

import burp.*;
import burp.bean.CustomBurpUrl;
import burp.bean.Issus;
import burp.bean.ScanResultType;
import burp.dnslogs.DnslogInterface;
import burp.extension.bypass.PayloadBypass;
import burp.ui.Tags;
import burp.utils.Customhelps;
import burp.utils.YamlReader;

import java.io.PrintWriter;
import java.lang.reflect.InvocationTargetException;
import java.net.URLEncoder;
import java.text.SimpleDateFormat;
import java.util.*;

import static burp.utils.Customhelps.tabFormat;

/**
 * @ClassName: BaseScan
 * @Auther: niko
 * @Date: 2025/2/7 21:50
 * @Description:
 */
public abstract class BaseScan {
    public PrintWriter stdout;
    protected IBurpExtenderCallbacks callbacks;

    protected IExtensionHelpers helpers;

    protected List<String> payloads;

    protected IHttpRequestResponse iHttpRequestResponse;

    protected CustomBurpUrl customBurpUrl;
    protected List<String> randomList;

    protected List<IHttpRequestResponse> iHttpRequestResponseList;

    protected String dnsName;
    protected YamlReader yamlReader;
    private boolean isBypass;
    private Integer startTime;

    protected BaseScan(IBurpExtenderCallbacks callbacks,IHttpRequestResponse iHttpRequestResponse, IExtensionHelpers helpers,boolean isBypass,String dnsName) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.payloads = new ArrayList<>();
        this.yamlReader = YamlReader.getInstance(callbacks);
        this.iHttpRequestResponse = iHttpRequestResponse;
        this.dnsName = dnsName;
        this.customBurpUrl = new CustomBurpUrl(callbacks,iHttpRequestResponse);
        this.randomList = new ArrayList<>();
        this.iHttpRequestResponseList = new ArrayList<>();
        this.isBypass = isBypass;
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.startTime = Customhelps.getSecondTimestamp(new Date());
    }

    protected IHttpRequestResponse run(String payload){
        try {
            Thread.sleep(500);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
        if (this.isBypass){
            payload = PayloadBypass.processJson(payload,true);
        }


        List<String> headers = customBurpUrl.getHttpRequestHeaders();
        byte[] bytes = helpers.buildHttpMessage(headers, helpers.stringToBytes(payload));
        IHttpRequestResponse newRequestResp = callbacks.makeHttpRequest(iHttpRequestResponse.getHttpService(), bytes);
        this.customBurpUrl = new CustomBurpUrl(callbacks,newRequestResp);
        return newRequestResp;
    }


    protected IHttpRequestResponse run(String payloads,String key) {
        try {
            Thread.sleep(500);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
        if (this.isBypass){
            payloads = PayloadBypass.processJson(payloads,false);
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

    public void exportLogs(String extendName,String url,String key,String payload,String dnslogContent){
        this.stdout.println(String.format("================%s扫描详情================",extendName));
        this.stdout.println(String.format("扫描地址: %s", url));
        this.stdout.println(String.format("扫描参数： %s", key!=null?key:"content-type: application/json"));
        this.stdout.println(String.format("扫描payload： %s", payload));
        this.stdout.println(String.format("dnslog检测/响应包： %s", dnslogContent));
        Date d = new Date();
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        String endTime = sdf.format(d);
        this.stdout.println(String.format("检测时间： %s", endTime));
        this.stdout.println("========================================");
        this.stdout.println(" ");
    }

    public abstract String getExtensionName();

    public Issus TimeoutCheck(int count){
        int maxExecutionTime = 15 * count;
        // 判断程序是否运行超时
        Integer currentTime = Customhelps.getSecondTimestamp(new Date());
        Integer runTime = currentTime - startTime;
        if (runTime >= maxExecutionTime) {
            return new Issus(customBurpUrl.getHttpRequestUrl(),
                    customBurpUrl.getRequestMethod(),
                    this.getExtensionName(),
                    customBurpUrl.getHttpResponseStatus(),
                    "timeout",
                    tabFormat(ScanResultType.WAIT_CONFIRM),
                    iHttpRequestResponse,
                    Issus.State.SAVE);
        }
        return null;
    }
    protected List<Issus> checkoutDnslog(String extendName,DnslogInterface dnslog,List<String>randlist,List<IHttpRequestResponse> httpRequestResponseList,List<String> payloads,List<String> versionList) {

        List<Issus> issuses = new ArrayList<>();
        String tabResult = null ;
        try {
            Thread.sleep(5000);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
        if (extendName.equals("lowPerceptScan")){
            tabResult = tabFormat(ScanResultType.IS_FASTJSON);
        } else if (extendName.equals("RemoteScan")) {
            tabResult = tabFormat(ScanResultType.PAYLOADS_FIND);
        }
        // 开始进行二次验证
        Issus issus;
        try {
            boolean isFirst = true;
            for (int i = 0; i < randlist.size(); i++) {
                String random = randlist.get(i);
                String dnsLogAllContent = "";
                dnsLogAllContent = dnslog.getAllContent(random);
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    throw new RuntimeException(e);
                }
                this.stdout.println(String.format("================%s二次校验详情================",extendName));
                this.stdout.println(String.format("dnslog响应包： %s", dnsLogAllContent));
                Date d = new Date();
                SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
                String endTime = sdf.format(d);
                this.stdout.println(String.format("检测时间： %s", endTime));
                this.stdout.println("========================================\n");
                if (dnsLogAllContent == null){
                    issus = new Issus(customBurpUrl.getHttpRequestUrl(),
                            customBurpUrl.getRequestMethod(),
                            this.getExtensionName(),
                            customBurpUrl.getHttpResponseStatus(),
                            null,
                            tabFormat(ScanResultType.NOT_FOUND),
                            httpRequestResponseList.get(i),
                            Issus.State.SAVE);
                    issuses.add(issus);
                    return issuses;
                }
                // dnslog 内容匹配判断
                if (!dnsLogAllContent.contains(random)) {
                    if ((i + 1) != randlist.size()) {
                        continue;
                    } else {
                        issus = new Issus(customBurpUrl.getHttpRequestUrl(),
                                customBurpUrl.getRequestMethod(),
                                this.getExtensionName(),
                                customBurpUrl.getHttpResponseStatus(),
                                null,
                                tabFormat(ScanResultType.NOT_FOUND),
                                httpRequestResponseList.get(i),
                                Issus.State.SAVE);
                        issuses.add(issus);
                        return issuses;
                    }
                }
                if (extendName.equals("versionDetect")){
                    tabResult = tabFormat(ScanResultType.VERSION_INFO,versionList.get(i));
                }
                if (isFirst){
                    issus = new Issus(customBurpUrl.getHttpRequestUrl(),
                            customBurpUrl.getRequestMethod(),
                            this.getExtensionName(),
                            customBurpUrl.getHttpResponseStatus(),
                            payloads.get(i),
                            tabResult,
                            httpRequestResponseList.get(i),
                            Issus.State.SAVE);
                    issuses.add(issus);
                    isFirst = false;
                }else {
                    issus = new Issus(customBurpUrl.getHttpRequestUrl(),
                            customBurpUrl.getRequestMethod(),
                            this.getExtensionName(),
                            customBurpUrl.getHttpResponseStatus(),
                            payloads.get(i),
                            tabResult,
                            httpRequestResponseList.get(i),
                            Issus.State.ADD);
                    issuses.add(issus);
                }
            }
            return issuses;
        } catch (Exception e) {
            // 抛出dnslog平台error
            issus = new Issus(customBurpUrl.getHttpRequestUrl(),
                    customBurpUrl.getRequestMethod(),
                    this.getExtensionName(),
                    customBurpUrl.getHttpResponseStatus(),
                    null,
                    tabFormat(ScanResultType.DNS_ERROR),
                    this.iHttpRequestResponse,
                    Issus.State.SAVE);
            issuses.add(issus);
            return issuses;
        }
    }

}
