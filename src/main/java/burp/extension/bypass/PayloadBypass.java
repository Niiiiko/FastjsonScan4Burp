package burp.extension.bypass;

import burp.utils.Customhelps;
import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;
import com.google.gson.reflect.TypeToken;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Random;

public class PayloadBypass {
    public static String processJson(String inputJson,boolean isContentJson) {
        try {

            // 2. 解析JSON到Map（保留顺序）
            Map<String, Object> map = new Gson().fromJson(inputJson,
                    new TypeToken<LinkedHashMap<String, Object>>(){}.getType());

            // 3. 创建新Map处理加密
            Map<String, Object> newMap = new LinkedHashMap<>();
            for (Map.Entry<String, Object> entry : map.entrySet()) {
                String encodedKey = entry.getKey().toString();
                if (encodedKey.equals("@type")||encodedKey.equals("val")){
                    encodedKey =toUnicodeHex(encodedKey);
                }else {
                    encodedKey = keyEncode(encodedKey);
                }
                Object encodedValue = entry.getValue() != null ?
                        deepEncode(entry.getValue()) : null;
                newMap.put(encodedKey, encodedValue);
            }
            String json = new Gson().toJson(newMap);
            if (isContentJson){
                json = addComments(json);
            }
            // 4. 生成新JSON
            return json.replace("\\\\","\\");
        } catch (JsonSyntaxException e) {
            String json = inputJson.replace("@type", toUnicodeHex("@type"));
            json = addComments(json);
            String replace = ":/*"+Customhelps.randomString(6)+"*/";
            json = json.replace(":", replace);
            // 极端情况处理：当无法解析时返回空对象
            return json;
        }}
    private static Object deepEncode(Object value) {
        if (value instanceof Map) {
            Map<?, ?> map = (Map<?, ?>) value;
            Map<String, Object> newMap = new LinkedHashMap<>();
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                String encodedKey = entry.getKey().toString();
                if (encodedKey.equals("@type")||encodedKey.equals("val")){
                    encodedKey =toUnicodeHex(encodedKey);
                }else {
                    encodedKey =keyEncode(encodedKey);
                }
                newMap.put(encodedKey, deepEncode(entry.getValue()));
            }
            return newMap;
        }
        return toUnicodeHex(value.toString());
    }
    public static String toUnicodeHex(String value){
        Random random = new Random();
        StringBuilder unicodeString = new StringBuilder();
        for (char c : value.toCharArray()) {
            int i = random.nextInt(10);

            if (i>6){
                unicodeString.append(String.format("\\u%04x", (int) c));
            }else {
                unicodeString.append(String.format("\\x%02x", (int) c));
            }
            // 对每个字符进行 Unicode 编码
        }
        System.out.println("toUnicodeHex： " + unicodeString);
        return unicodeString.toString();
    }
    public static String keyEncode(String payload){
        String s = toUnicodeHex(randomCaseConvert(addSome(payload)));
        return s;
    }
    public static String addComments(String payload){
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < payload.length(); i++) {
            char c = payload.charAt(i);
            if (c == '\r' || c == '\n' || c == '\b' || c == ' ') {
                continue;
            }
            result.append(c);
            // 如果当前字符是 {，则在其后添加 //random\n
            if (c == '{') {
                String s = Customhelps.randomString(5);
                result.append("//"+s+"\n");
            }
            if (c == ',') {
                result.append("/*"+Customhelps.randomString(7)+"*/");
            }
        }
        return result.toString();
    }
    public static String randomCaseConvert(String input) {
        // 将输入字符串转换为字符数组
        char[] charArray = input.toCharArray();
        Random random = new Random();

        // 遍历字符数组
        for (int i = 0; i < charArray.length; i++) {
            // 随机决定是否转换大小写
            if (random.nextBoolean()) {
                char c = charArray[i];
                if (Character.isUpperCase(c)) {
                    // 如果是大写字母，转换为小写
                    charArray[i] = Character.toLowerCase(c);
                } else if (Character.isLowerCase(c)) {
                    // 如果是小写字母，转换为大写
                    charArray[i] = Character.toUpperCase(c);
                }
            }
        }
        // 将修改后的字符数组转换回字符串
        return new String(charArray);
    }
    private static String addSome(String payload){
        Random random = new Random();

        StringBuilder stringBuilder = new StringBuilder(payload);
        for (int j = 1; j < payload.length()/2; j++) {
            int i = random.nextInt(payload.length() + 1);
            stringBuilder.insert(i,"-");
        }
        System.out.println(stringBuilder.toString());
        return stringBuilder.toString();
    }

}
