package com.chen.utils;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import javax.servlet.http.HttpServletRequest;
import java.io.Serializable;
import java.util.*;

/**
 * JWT工具类
 * @author chen
 * @date Nov 28, 2018
 */
public class JwtTokenUtils implements Serializable {

	private static final long serialVersionUID = 1L;

	/**
	 * 创建时间
	 */
	private static final String CREATED = "created";
	/**
     * 密钥
     */
    private static final String SECRET = "wkewqsdfenWsdOjfjewPdswfenceqwq";
    /**
     * 有效期12小时
     */
    private static final long EXPIRE_TIME = 12 * 60 * 60 * 1000;

	/**
     * 从数据声明生成令牌
     *
     * @param claims 数据声明
     * @return 令牌
     */
    public static String generateToken(Map<String, Object> claims) {
        Date expirationDate = new Date(System.currentTimeMillis() + EXPIRE_TIME);
        String userId = (String) claims.get("userid");
        if (userId == null) {
			userId = UUID.randomUUID().toString();
		}
        String token = Jwts.builder().setSubject(userId).setClaims(claims).setExpiration(expirationDate).signWith(SignatureAlgorithm.HS512, SECRET).compact();
    	return token;
    }

    /**
	 * 从令牌中获取用户名
	 *
	 * @param token 令牌
	 * @return 用户名
	 */
	public static String getUserIdFromToken(String token) {
	    String userid;
	    try {
	        Claims claims = getClaimsFromToken(token);
			userid = (String) claims.get("userid");
	    } catch (Exception e) {
			userid = null;
	    }
	    return userid;
	}

	/**
     * 从令牌中获取数据声明
     *
     * @param token 令牌
     * @return 数据声明
     */
    public static Claims getClaimsFromToken(String token) {
        Claims claims;
        try {
            claims = Jwts.parser().setSigningKey(SECRET).parseClaimsJws(token).getBody();
        } catch (Exception e) {
            claims = null;
        }
        return claims;
    }

    /**
	 * 验证令牌
	 * @param token
	 * @param userId
	 * @return
	 */
	public static Boolean validateToken(String token, String userId) {
	    String userid = getUserIdFromToken(token);
	    return (userId.equals(userid) && !isTokenExpired(token));
	}

	/**
	 * 刷新令牌
	 * @param token
	 * @return
	 */
	public static String refreshToken(String token) {
	    String refreshedToken;
	    try {
	        Claims claims = getClaimsFromToken(token);
	        claims.put(CREATED, new Date());
	        refreshedToken = generateToken(claims);
	    } catch (Exception e) {
	        refreshedToken = null;
	    }
	    return refreshedToken;
	}

	/**
     * 判断令牌是否过期
     *
     * @param token 令牌
     * @return 是否过期
     */
    public static Boolean isTokenExpired(String token) {
        try {
            Claims claims = getClaimsFromToken(token);
            Date expiration = claims.getExpiration();
            return expiration.before(new Date());
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 获取请求token
     * @param request
     * @return
     */
    public static String getToken(HttpServletRequest request, String TOKENFLAG) {
    	String token = request.getHeader(TOKENFLAG);
        String tokenHead = "Bearer ";
        if(token == null) {
        	token = request.getHeader("token");
        } else if(token.contains(tokenHead)){
        	token = token.substring(tokenHead.length());
        } 
        if("".equals(token)) {
        	token = null;
        }
        return token;
    }
}