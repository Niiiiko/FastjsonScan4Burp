package burp.dnslogs.impl;
import java.io.PrintWriter;

import burp.dnslogs.DnslogInterface;
import burp.utils.Customhelps;
import com.github.kevinsawicki.http.HttpRequest;
import burp.IBurpExtenderCallbacks;

public class DnsLogCn implements DnslogInterface {
    private IBurpExtenderCallbacks callbacks;

    private String dnslogDomainName;

    private String dnsLogCookieName;
    private String dnsLogCookieValue;
    private String randomDnsUrl;

    public DnsLogCn(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;

        this.dnslogDomainName = "http://dnslog.cn";

        this.init();
    }

    private void init() {
        String url = this.dnslogDomainName + "/getdomain.php";
        String userAgent = "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36";

        HttpRequest request = HttpRequest.get(url);
        request.trustAllCerts();
        request.trustAllHosts();
        request.followRedirects(false);
        request.header("User-Agent", userAgent);
        request.header("Accept", "*/*");
        request.readTimeout(30 * 1000);
        request.connectTimeout(30 * 1000);

        int statusCode = request.code();
        if (statusCode != 200) {
            throw new RuntimeException(
                    String.format(
                            "%s 扩展-访问url-%s, 请检查本机是否可访问 %s",
                            this.getExtensionName(),
                            statusCode,
                            url));
        }

        // 设置 dnslog 的临时域名
        String temporaryDomainName = request.body();
        if (request.isBodyEmpty()) {
            throw new RuntimeException(
                    String.format(
                            "%s 扩展-获取临时域名失败, 请检查本机是否可访问 %s",
                            this.getExtensionName(),
                            this.dnslogDomainName));
        }
        this.randomDnsUrl= temporaryDomainName;

        String cookie = request.header("Set-Cookie");
        System.out.println(cookie);
        String sessidKey = "PHPSESSID";
        String sessidValue =  Customhelps.getParam(cookie, sessidKey);
        if (sessidValue.length() == 0) {
            throw new IllegalArgumentException(
                    String.format(
                            "%s 扩展-访问站点 %s 时返回Cookie为空, 导致无法正常获取dnsLog数据, 请检查",
                            this.getExtensionName(),
                            this.dnslogDomainName));
        }

        this.dnsLogCookieName = sessidKey;
        this.dnsLogCookieValue = sessidValue;
    }

    @Override
    public String getBodyContent() {
        String url = this.dnslogDomainName + "/getrecords.php";
        String userAgent = "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36";

        HttpRequest request = HttpRequest.get(url);
        request.trustAllCerts();
        request.trustAllHosts();
        request.followRedirects(false);
        request.header("User-Agent", userAgent);
        request.header("Accept", "*/*");
        request.header("Cookie", this.dnsLogCookieName + "=" + this.dnsLogCookieValue + ";");
        request.readTimeout(30 * 1000);
        request.connectTimeout(30 * 1000);

        String body = request.body();

        if (!request.ok()) {
            throw new RuntimeException(
                    String.format(
                            "%s 扩展-%s内容有异常,异常内容: %s",
                            this.getExtensionName(),
                            this.dnslogDomainName,
                            body
                    )
            );
        }

        if (body.equals("[]")) {
            return null;
        }
        return body;
    }

    @Override
    public String getAllContent() {
        return null;
    }

    @Override
    public String getExtensionName() {
        return "DnsLogCn";
    }

    @Override
    public String getRandomDnsUrl() {
        return this.randomDnsUrl;
    }

    @Override
    public String getRandomPredomain() {
        return this.randomDnsUrl.replace(".dnslog.cn","");
    }
}
