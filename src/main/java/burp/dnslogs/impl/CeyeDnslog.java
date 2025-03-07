package burp.dnslogs.impl;

import burp.IBurpExtenderCallbacks;
import burp.dnslogs.DnslogInterface;
import burp.utils.Customhelps;
import burp.utils.YamlReader;
import com.github.kevinsawicki.http.HttpRequest;

/**
 * @ClassName: Ceye
 * @Auther: niko
 * @Date: 2025/1/20 16:10
 * @Description:
 */
public class CeyeDnslog implements DnslogInterface {

    private String Identifier;
    private String token;
    private String random;
    private String api;
    private YamlReader yamlReader;
    private String randomDnsUrl;


    public CeyeDnslog(IBurpExtenderCallbacks callbacks){
        Customhelps customhelps = new Customhelps();
        this.yamlReader = YamlReader.getInstance(callbacks);
        this.api = "http://api.ceye.io";
        this.Identifier = yamlReader.getString("dnsLogModule.CeyeDnslog.Identifier").trim();
        this.random = customhelps.randomString(4);
        this.token = yamlReader.getString("dnsLogModule.CeyeDnslog.token").trim();
        init();
    }
    private void init() {
        if (this.token == null || this.token.length() <= 0) {
            throw new RuntimeException(String.format("%s 扩展-token参数不能为空", this.getExtensionName()));
        }
        if (this.Identifier == null || this.Identifier.length() <= 0) {
            throw new RuntimeException(String.format("%s 扩展-key参数不能为空", this.getExtensionName()));
        }
        String temporaryDomainName = this.random + "." + this.Identifier + "." + "ceye.io";
        this.randomDnsUrl = temporaryDomainName;
    }
    @Override
    public String getRandomDnsUrl() {
        return this.randomDnsUrl;
    }

    @Override
    public String getRandomPredomain() {
        return this.random;
    }

    @Override
    public String checkConnection() {
        return "";
    }

    @Override
    public String getBodyContent() {
        String url = String.format("%s/v1/records?token=%s&type=dns&filter=%s",api,token,"random");
        HttpRequest httpRequest = HttpRequest.get(url);
        String ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1_1 like Mac OS X) AppleWebKit/604.2.15 (KHTML, like Gecko) Mobile/22B91 Ariver/1.0.10 Jupiter/1.0.0";
        httpRequest.header("User-Agent",ua);
        httpRequest.header("Accept","*/*");
        httpRequest.trustAllCerts();
        httpRequest.trustAllHosts();
        httpRequest.readTimeout(30 * 1000);
        httpRequest.connectTimeout(30 * 1000);
        httpRequest.followRedirects(false);

        String body = httpRequest.body();
        if (!httpRequest.ok()){
            throw new RuntimeException(
                    String.format(
                            "%s 扩展-内容有异常,异常内容: %s",
                            this.api,
                            body
                    )
            );
        }
        if (body.contains("[]")){
            return null;
        }
        return body;
    }

    @Override
    public String getAllContent(String random) {
        String url = String.format("%s/v1/records?token=%s&type=dns",api,token);
        HttpRequest httpRequest = HttpRequest.get(url);
        String ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1_1 like Mac OS X) AppleWebKit/604.2.15 (KHTML, like Gecko) Mobile/22B91 Ariver/1.0.10 Jupiter/1.0.0";
        httpRequest.header("User-Agent",ua);
        httpRequest.header("Accept","*/*");
        httpRequest.trustAllCerts();
        httpRequest.trustAllHosts();
        httpRequest.readTimeout(30 * 1000);
        httpRequest.connectTimeout(30 * 1000);
        httpRequest.followRedirects(false);

        String body = httpRequest.body();
        if (!httpRequest.ok()){
            throw new RuntimeException(
                    String.format(
                            "%s 扩展-内容有异常,异常内容: %s",
                            this.api,
                            body
                    )
            );
        }
        if (body.contains("[]")){
            return null;
        }
        return body;
    }

    @Override
    public String getExtensionName() {
        return "CeyeDnslog";
    }

}
