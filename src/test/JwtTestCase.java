import com.chen.utils.JwtTokenUtils;

import java.util.HashMap;
import java.util.Map;

public class JwtTestCase {


    public static void main(String[] args) {

        Map<String, Object> map = new HashMap<String, Object>();
        map.put("userid", "chen123");
        map.put("username", "testchen");
        map.put("email", "65626596569@qq.com");

        String token = JwtTokenUtils.generateToken(map);
        System.out.println(token);

        Map<String, Object> map2 = JwtTokenUtils.getClaimsFromToken(token);
        System.out.println(map2);

        System.out.println(JwtTokenUtils.isTokenExpired(token));
        System.out.println(JwtTokenUtils.validateToken(token, "chen123"));
    }

}
