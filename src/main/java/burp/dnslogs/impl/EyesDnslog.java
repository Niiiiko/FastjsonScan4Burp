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
public class EyesDnslog implements DnslogInterface {

    private String Identifier;
    private String token;
    private String random;
    private String api;
    private YamlReader yamlReader;
    private String randomDnsUrl;


    public EyesDnslog(IBurpExtenderCallbacks callbacks){
        Customhelps customhelps = new Customhelps();
        this.yamlReader = YamlReader.getInstance(callbacks);
        this.api = "https://eyes.sh";
        this.Identifier = yamlReader.getString("dnsLogModule.EyesDnslog.Identifier").trim();
        this.random = customhelps.randomString(4);
//        this.randomGroup = "n1ngoax";
        this.token = yamlReader.getString("dnsLogModule.EyesDnslog.token").trim();
        init();
    }
    private void init() {
        if (this.token == null || this.token.length() <= 0) {
            throw new RuntimeException(String.format("%s 扩展-token参数不能为空", this.getExtensionName()));
        }
        if (this.Identifier == null || this.Identifier.length() <= 0) {
            throw new RuntimeException(String.format("%s 扩展-key参数不能为空", this.getExtensionName()));
        }
//        String temporaryDomainName = this.random + "." + this.randomGroup + "." + this.Identifier + "." + "eyes.sh";
        String temporaryDomainName = this.random + "." + this.Identifier + "." + "eyes.sh";

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
        String url = this.randomDnsUrl;
        HttpRequest httpRequest = HttpRequest.get(url);
        String ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1_1 like Mac OS X) AppleWebKit/604.2.15 (KHTML, like Gecko) Mobile/22B91 Ariver/1.0.10 Jupiter/1.0.0";
        httpRequest.header("User-Agent",ua);
        httpRequest.header("Accept","*/*");
        httpRequest.trustAllCerts();
        httpRequest.trustAllHosts();
        httpRequest.readTimeout(8 * 1000);
        httpRequest.connectTimeout(8 * 1000);
        httpRequest.followRedirects(false);
        httpRequest.disconnect();
        String bodyContent = getBodyContent();
        if (bodyContent.contains("True")){
            return String.format(getExtensionName() + "平台已连接");
        }else {
            return "连接失败，建议更换dnslog平台";
        }
    }

    @Override
    public String getBodyContent() {
        String url = String.format("%s/api/dns/%s/%s/?token=%s",api,Identifier,random,token);
        HttpRequest httpRequest = HttpRequest.get(url);
        String ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1_1 like Mac OS X) AppleWebKit/614.2.15 (KHTML, like Gecko) Mobile/22B91 Ariver/1.0.10 Jupiter/1.0.0";
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
        httpRequest.disconnect();
        if (body.toLowerCase().contains("false")){
            return null;
        }else {
            return random;
        }

//        return body;
    }

    // eyes.sh无法做二次校验
    @Override
    public String getAllContent(String random) {
        String url = String.format("%s/api/dns/%s/%s/?token=%s",api,Identifier,random,token);
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
        httpRequest.disconnect();
        if (body.equals("False")){
            return null;
        }else {
            return random;
        }
    }

    @Override
    public String getExtensionName() {
        return "EyesDnslog";
    }

}
