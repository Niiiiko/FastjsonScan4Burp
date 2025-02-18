package burp.utils;

import burp.IBurpExtenderCallbacks;
import burp.bean.ScanResultType;
import org.yaml.snakeyaml.Yaml;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.util.*;

/**
 * @ClassName: Customhelps
 * @Auther: niko
 * @Date: 2025/1/20 16:50
 * @Description:
 */
public class Customhelps {
    private IBurpExtenderCallbacks callbacks;
    private static Map<String, Map<String, Object>> properties = new HashMap<>();

    public Customhelps() {
    }

    public static String randomString(Integer j){
        String characters = "abcdefghijklmnopqrstuvwxyz0123456789";
        StringBuilder result = new StringBuilder(4);
        Random random = new Random();
        for (int i = 0; i < j; i++) {
            int index = random.nextInt(characters.length());
            result.append(characters.charAt(index));
        }
        return result.toString();
    }


    public String getConfigPath(){
        int lastIndexOf = this.callbacks.getExtensionFilename().lastIndexOf(File.separator);
        String path = "";
        path = this.callbacks.getExtensionFilename().substring(0,lastIndexOf) + File.separator + "resources/config.yml";
        return path;
    }
    public void load() throws FileNotFoundException {
        String configPath = getConfigPath();
        File file = new File(configPath);
        properties = new Yaml().load(new FileInputStream(file));
    }
    /**
     * 获取参数数据
     * 例如:
     * getParam("token=xx;Identifier=xxx;", "token"); 返回: xx
     *
     * @param d         被查找的数据
     * @param paramName 要查找的字段
     * @return
     */
    public static String getParam(final String d, final String paramName) {
        if (d == null || d.length() == 0)
            return null;

        String value = "test=test;" + d;

        final int length = value.length();
        int start = value.indexOf(';') + 1;
        if (start == 0 || start == length)
            return null;

        int end = value.indexOf(';', start);
        if (end == -1)
            end = length;

        while (start < end) {
            int nameEnd = value.indexOf('=', start);
            if (nameEnd != -1 && nameEnd < end
                    && paramName.equals(value.substring(start, nameEnd).trim())) {
                String paramValue = value.substring(nameEnd + 1, end).trim();
                int valueLength = paramValue.length();
                if (valueLength != 0)
                    if (valueLength > 2 && '"' == paramValue.charAt(0)
                            && '"' == paramValue.charAt(valueLength - 1))
                        return paramValue.substring(1, valueLength - 1);
                    else
                        return paramValue;
            }

            start = end + 1;
            end = value.indexOf(';', start);
            if (end == -1)
                end = length;
        }

        return null;
    }
    /**
     * 获取精确到秒的时间戳
     *
     * @param date
     * @return Integer
     */
    public static Integer getSecondTimestamp(Date date) {
        if (null == date) {
            return 0;
        }
        String timestamp = String.valueOf(date.getTime() / 1000);
        return Integer.valueOf(timestamp);
    }
    public static String tabFormat(ScanResultType type, Object... args){
        return type.format(args);
    }

    private static int levenshteinDistance(String s1, String s2) {
        int m = s1.length();
        int n = s2.length();
        int[][] dp = new int[m + 1][n + 1];

        for (int i = 0; i <= m; i++) {
            for (int j = 0; j <= n; j++) {
                if (i == 0) {
                    dp[i][j] = j;
                } else if (j == 0) {
                    dp[i][j] = i;
                } else {
                    dp[i][j] = Math.min(
                            Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1),
                            dp[i - 1][j - 1] + (s1.charAt(i - 1) == s2.charAt(j - 1) ? 0 : 1)
                    );
                }
            }
        }
        return dp[m][n];
    }
    public static boolean isSimilarity(String resp1,String resp2){
        int distance = levenshteinDistance(resp1, resp2);
        double similarity = 1 - (double) distance / Math.max(resp1.length(), resp2.length());
        if (similarity>0.7){
            return true;
        }
        return false;
    }
}
