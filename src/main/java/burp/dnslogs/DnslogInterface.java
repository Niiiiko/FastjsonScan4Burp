package burp.dnslogs;

public interface DnslogInterface {
    String getBodyContent();

    String getAllContent(String random);

    String getExtensionName();

    String getRandomDnsUrl();

    String getRandomPredomain();

    String checkConnection();
}
