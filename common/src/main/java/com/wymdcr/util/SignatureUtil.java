package com.wymdcr.util;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class SignatureUtil {

	public static final String KEY_ALGORITHM       = "RSA";
	public static final String SIGNATURE_ALGORITHM = "SHA1withRSA";
	
	/**
     *验签
     * @param body 传入参数
     * @param publicKey 公钥
     * @param useBase64Code 是否使用Base64编码
     * @param charset 编码格式
     * @return
     */
    public static Boolean checkSign(byte[] body ,String sign, String publicKey,boolean useBase64Code, String charset){

		try {
			/*RSA验签*/
			Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
			signature.initVerify(getPublicKey(publicKey));
			signature.update(body);
			boolean isValid = false;
			// 如果是Base64编码的话，需要对验签的数组以Base64解码
			if (useBase64Code) {
				isValid = signature.verify(Base64RSA.decode(new String(
						sign.getBytes(), charset).toCharArray()));
			} else {
				isValid = signature.verify(sign.getBytes());
			}
			
			return isValid;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return false;
    	
    }
    
    /**
	 * 生成RSA签名
	 * 
	 * @param privateKey
	 *            私钥
	 * @param body
	 *            需要签名的信息
	 * @return byte[]
	 * @throws Exception
	 */
	public static byte[] signRSA(String privateKey,byte[] body, boolean useBase64Code,
			String charset) throws Exception {
		/*RSA生成签名*/
		Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
		signature.initSign(getPrivateKey(privateKey));
		signature.update(body);
		// 如果是Base64编码的话，需要对签名后的数组以Base64编码
		if (useBase64Code) {
			return new String(Base64RSA.encode(signature.sign())).getBytes(charset);
		} else {
			return signature.sign();
		}
	}
    
	/**
	 * 从字符串中加载私钥
	 * @param privateKeyStr
	 * @return
	 * @throws Exception
	 */
	public static RSAPrivateKey getPrivateKey(String privateKeyStr) throws Exception {
		try {
			byte[] buffer = Base64RSA.decode(privateKeyStr.toCharArray());
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(buffer);
			RSAPrivateKey privateKey = (RSAPrivateKey) keyFactory
					.generatePrivate(keySpec);
			return privateKey;
		} catch (NoSuchAlgorithmException e) {
			throw new Exception("无此算法");
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
			throw new Exception("私钥非法");
		}catch (NullPointerException e) {
			throw new Exception("私钥数据为空");
		}
	}
	
	/**
	 * 从字符串中加载公钥
	 * 
	 * @param publicKeyStr
	 *            公钥数据字符串
	 * @throws Exception
	 *             加载公钥时产生的异常
	 */
	public static RSAPublicKey getPublicKey(String publicKeyStr) throws Exception {
		try {
			byte[] buffer = Base64RSA.decode(publicKeyStr.toCharArray());
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(buffer);
			RSAPublicKey publicKey = (RSAPublicKey) keyFactory
					.generatePublic(keySpec);
			return publicKey;
		} catch (NoSuchAlgorithmException e) {
			throw new Exception("无此算法");
		} catch (InvalidKeySpecException e) {
			throw new Exception("公钥非法");
		} catch (NullPointerException e) {
			throw new Exception("公钥数据为空");
		} catch (Exception e) {
			throw new Exception(e);
		}
	}
	
}
