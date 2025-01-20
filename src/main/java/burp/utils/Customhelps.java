package burp.utils;

import java.util.Random;

/**
 * @ClassName: Customhelps
 * @Auther: niko
 * @Date: 2025/1/20 16:50
 * @Description:
 */
public class Customhelps {
    public String randomString(Integer j){
        String characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        StringBuilder result = new StringBuilder(4);
        Random random = new Random();
        for (int i = 0; i < j; i++) {
            int index = random.nextInt(characters.length());
            result.append(characters.charAt(index));
        }
        return result.toString();
    }

}
