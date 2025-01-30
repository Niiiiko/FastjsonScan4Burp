package burp.dnslogs;

import burp.utils.Customhelps;
import com.github.kevinsawicki.http.HttpRequest;

/**
 * @ClassName: Ceye
 * @Auther: niko
 * @Date: 2025/1/20 16:10
 * @Description:
 */
public class Ceye implements DnslogInterface{

    private String key;
    private String token;
    private String predomain;
    private String content;
    private String api;


    public String getPredomain() {
        return predomain;
    }

    public Ceye(){
        Customhelps customhelps = new Customhelps();
        this.api = "http://api.ceye.io";
        this.key = "3l7rni";
        this.predomain = customhelps.randomString(4);
        this.token = "34207baba06e1866cae98fbcd3369d36";
    }
    public String getKey(){
        return this.key;
    }

    @Override
    public String getBodyContent() {
//        String url = String.format("%s/v1/records?token=%s&type=dns&filter=%s",api,token,predomain);
        String url = String.format("%s/v1/records?token=%s&type=dns&filter=",api,token);

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

    public static void main(String[] args) {
        Ceye ceye = new Ceye();
        String url = String.format("http://%s.%s.ceye.io",ceye.getPredomain(),ceye.key);
        HttpRequest httpRequest = HttpRequest.get(url);
        String body = httpRequest.body();
        httpRequest.readTimeout(30 * 1000);
        httpRequest.connectTimeout(30 * 1000);

        System.out.println(body);
        System.out.println(ceye.getBodyContent());
    }
}
