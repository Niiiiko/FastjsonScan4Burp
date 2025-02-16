package burp.utils;

import burp.IBurpExtenderCallbacks;
import burp.bean.ScanResultType;
import org.yaml.snakeyaml.Yaml;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

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
    public static String tabFormat(ScanResultType type, Object... args){
        return type.format(args);
    }
}
