/**********************
 * 问卷网逆向处理流程 v1.0 *
 **********************/
package org.ayakaji.ques;

import java.io.BufferedReader;
import java.io.CharArrayWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECPoint;
import org.joda.time.DateTime;
import org.joda.time.Instant;
import org.joda.time.format.DateTimeFormat;
import org.joda.time.format.DateTimeFormatter;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.xiets.rsa.IOUtils;

public class ReverseUtilities {

	private static String NGINX_SRC_PATH = "D:\\nginx-1.16.1\\html";
	private static String FILENAME_SUFFIX = ".下载";
	private static List<Map<String, String>> listConvSet = new ArrayList<Map<String, String>>() {
		private static final long serialVersionUID = -8906440923152781604L;
		{
//			add(new HashMap<String, String>() {
//				private static final long serialVersionUID = 1L;
//				{
//					put("file", "D:\\nginx-1.16.1\\html\\survey\\main.html");
//					put("origin", "https://www.wenjuan.com");
//					put("local", "https://www.sd.10086.cn");
//				}
//			});
//			add(new HashMap<String, String>() {
//				private static final long serialVersionUID = 1L;
//				{
//					put("file", "D:\\nginx-1.16.1\\html\\survey\\main_files\\base_utils.js");
//					put("origin", "https://www.wenjuan.com");
//					put("local", "https://www.sd.10086.cn");
//				}
//			});
//			add(new HashMap<String, String>() {
//				private static final long serialVersionUID = 1L;
//				{
//					put("file", "D:\\nginx-1.16.1\\html\\survey\\main_files\\e3ab5f4a1957c3d4ca538cca593afbbc.js");
//					put("origin", "https://www.wenjuan.com");
//					put("local", "https://www.sd.10086.cn");
//				}
//			});
//			add(new HashMap<String, String>() {
//				private static final long serialVersionUID = 1L;
//				{
//					put("file",
//							"D:\\nginx-1.16.1\\html\\survey\\main_files\\push.js");
//					put("origin", "https://sp0.baidu.com/9_Q4simg2RQJ8t7jm9iCKT-xh_/s.gif");
//					put("local", "https://www.sd.10086.cn/survey/static/images/hm.gif");
//				}
//			});
//			add(new HashMap<String, String>() {
//				private static final long serialVersionUID = 1L;
//				{
//					put("file",
//							"D:\\nginx-1.16.1\\html\\survey\\main_files\\hm.js");
//					put("origin", "hm.baidu.com/hm.gif");
//					put("local", "www.sd.10086.cn/survey/static/images/hm.gif");
//				}
//			});
//			add(new HashMap<String, String>() {
//				private static final long serialVersionUID = 1L;
//				{
//					put("file",
//							"D:\\nginx-1.16.1\\html\\survey\\main_files\\wj.hawkeye.js");
//					put("origin", "hawkeye.wenjuan.com/wj.hawkeye.gif");
//					put("local", "www.sd.10086.cn/survey/static/images/hm.gif");
//				}
//			});
//			add(new HashMap<String, String>() {
//				private static final long serialVersionUID = 1L;
//				{
//					put("file",
//							"D:\\nginx-1.16.1\\html\\survey\\main_files\\survey_mobile_main.js");
//					put("origin", "cn-hangzhou.log.aliyuncs.com\",\"wenjuan");
//					put("local", "sd.10086.cn\",\"www");
//				}
//			});
//			add(new HashMap<String, String>() {
//				private static final long serialVersionUID = 1L;
//				{
//					put("file",
//							"D:\\nginx-1.16.1\\html\\survey\\main_files\\survey_mobile_main.js");
//					put("origin", "logstores");
//					put("local", "survey/logstores");
//				}
//			});
//			add(new HashMap<String, String>() {
//				private static final long serialVersionUID = 1L;
//				{
//					put("file", "D:\\nginx-1.16.1\\html\\survey\\main.html");
//					put("origin", "webapi.amap.com");
//					put("local", "www.sd.10086.cn/survey/static");
//				}
//			});
//			add(new HashMap<String, String>() {
//				private static final long serialVersionUID = 1L;
//				{
//					put("file", "D:\\nginx-1.16.1\\html\\survey\\main_files\\maps");
//					put("origin", "webapi.amap.com");
//					put("local", "www.sd.10086.cn/survey/static");
//				}
//			});
//			add(new HashMap<String, String>() {
//				private static final long serialVersionUID = 1L;
//				{
//					put("file", "D:\\nginx-1.16.1\\html\\survey\\main_files\\modules");
//					put("origin", "webapi.amap.com");
//					put("local", "www.sd.10086.cn/survey/static");
//				}
//			});
//			add(new HashMap<String, String>() {
//				private static final long serialVersionUID = 1L;
//				{
//					put("file", "D:\\nginx-1.16.1\\html\\survey\\main_files\\android.js");
//					put("origin", "hawkeye.wenjuan.com");
//					put("local", "www.sd.10086.cn/survey/static");
//				}
//			});
//			add(new HashMap<String, String>() {
//				private static final long serialVersionUID = 1L;
//				{
//					put("file", "D:\\nginx-1.16.1\\html\\survey\\main_files\\survey_common.js");
//					put("origin", "hawkeye.wenjuan.com");
//					put("local", "www.sd.10086.cn/survey/static");
//				}
//			});
//			add(new HashMap<String, String>() {
//				private static final long serialVersionUID = 1L;
//				{
//					put("file", "D:\\nginx-1.16.1\\html\\survey\\main_files\\survey_mobile_main.js");
//					put("origin", "hawkeye.wenjuan.com");
//					put("local", "www.sd.10086.cn/survey/static");
//				}
//			});
//			add(new HashMap<String, String>() {
//				private static final long serialVersionUID = 1L;
//				{
//					put("file", "D:\\nginx-1.16.1\\html\\survey\\main_files\\baidu_auto_push.js");
//					put("origin", "zz.bdstatic.com");
//					put("local", "www.sd.10086.cn/survey/static");
//				}
//			});
//			add(new HashMap<String, String>() {
//				private static final long serialVersionUID = 1L;
//				{
//					put("file", "D:\\nginx-1.16.1\\html\\survey\\main_files\\baidu_auto_push.js");
//					put("origin", "push.zhanzhang.baidu.com");
//					put("local", "www.sd.10086.cn/survey/static");
//				}
//			});
//			add(new HashMap<String, String>() {
//				private static final long serialVersionUID = 1L;
//				{
//					put("file", "D:\\nginx-1.16.1\\html\\survey\\main.html");
//					put("origin", "cdn1.wenjuan.com");
//					put("local", "www.sd.10086.cn/survey/static");
//				}
//			});
//			add(new HashMap<String, String>() {
//				private static final long serialVersionUID = 1L;
//				{
//					put("file", "D:\\nginx-1.16.1\\html\\survey\\main_files\\survey_mobile_main.css");
//					put("origin", "cdn1.wenjuan.com");
//					put("local", "www.sd.10086.cn/survey/static");
//				}
//			});
//			add(new HashMap<String, String>() {
//				private static final long serialVersionUID = 1L;
//				{
//					put("file", "D:\\nginx-1.16.1\\html\\survey\\main.html");
//					put("origin", "www.sd.10086.cn/s/BrUVFn8");
//					put("local", "www.sd.10086.cn/survey/static/s/BrUVFn8");
//				}
//			});
//			add(new HashMap<String, String>() {
//				private static final long serialVersionUID = 1L;
//				{
//					put("file", "D:\\nginx-1.16.1\\html\\survey\\main.html");
//					put("origin", "api.wenjuan.link");
//					put("local", "www.sd.10086.cn/survey/static");
//				}
//			});
//			add(new HashMap<String, String>() {
//				private static final long serialVersionUID = 1L;
//				{
//					put("file", "D:\\nginx-1.16.1\\html\\survey\\main_files\\survey_mobile_main.js");
//					put("origin", "api.wenjuan.link");
//					put("local", "www.sd.10086.cn/survey/static");
//				}
//			});
//			add(new HashMap<String, String>() {
//				private static final long serialVersionUID = 1L;
//				{
//					put("file", "D:\\nginx-1.16.1\\html\\survey\\main_files\\survey_mobile_main.css");
//					put("origin", "/static/img/survey_mobile/ico_arrow_down.png");
//					put("local", "/survey/static/img/survey_mobile/ico_arrow_down.png");
//				}
//			});
//			add(new HashMap<String, String>() {
//				private static final long serialVersionUID = 1L;
//				{
//					put("file", "D:\\nginx-1.16.1\\html\\survey\\main_files\\survey_mobile_main.css");
//					put("origin", "/static/img/survey_mobile/ico_tool.png");
//					put("local", "/survey/static/img/survey_mobile/ico_tool.png");
//				}
//			});
		}
	};

	public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeyException,
			InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		// 1. 使用chrome浏览器，以android模式启动
		// 命令：D:\Chrome-bin\chrome.exe --user-agent="Mozilla/5.0 (Linux; U; Android 2.2;
		// en-us; Nexus One Build/FRF91) AppleWebKit/533.1 (KHTML, like Gecko)
		// Version/4.0 Mobile Safari/533.1"
		// 2. 打开F12 开发人员模式，并启动device模式，查看手机版本页面
		// 3. 保存所有html资源到本地目录：D:\nginx-1.16.1\html
		// 4. 替换所有静态资源文件名，去掉‘.下载’后缀
//		remFilenameSuffix(NGINX_SRC_PATH, FILENAME_SUFFIX);
		// 5. 替换main.html中的引用路径
//		replacTextContent("D:\\nginx-1.16.1\\html\\survey\\main.html", ".下载", "");
//		for (Map<String, String> map : listConvSet) {
//			replacTextContent(map.get("file"), map.get("origin"), map.get("local"));
//		}
//		regTest();
//		genKeyPair();
//		decrypt();
//		DateTime dt = new DateTime("2020-04-14 13:47:03");
//		System.out.println(dt.getDayOfMonth());
//		joda("2020-04-14 16:00:14");
		System.out.println(URLEncoder.encode(encrypt("15069071152,2020-05-07 14:45:00")));
//		decrypt(URLDecoder.decode(
//				"K89J0LR8YHdTC7FxzdT0igUa%2FrQ2%2BF8%2B6ZhVqqzrevE3OPOgqZc3ADWRcX2ZF87KMKHZ3fDFwGm5JuWq0tPk19MU84QNwMtKatWsO3etoZK8Q2XR0pvvTZ4tHjhmKtmqxJZyTiD2Wu2EhwjRNZvXm1myn53D%2BH6F%2FCOGR3IW25Q9eZw%2FV44plsCuNVnBq4qEIeISpANVo7oUTtH5ex6dJU9Gu5U7sfhCHbiRKZQHnui4hGH7HAE5AwNo5UC%2FcLXj47ehr7bVHRog6IoLJJ1vVBQKcTgYl9HYRL9YfHdsfzLKnCUrnR3G%2BgIHVu6NUEKASnh4Rmsdd3jJ5aLvCLZjew%3D%3D"));
//		genKeyPair_ECC();
//		Pattern p = Pattern.compile("(evaluate_id=)([^&]*)(&|$)");
//		Matcher m = p.matcher("https://www.sd.10086.cn/survey/main.html?evaluate_id=gWdc5vn78mK860pCsPROK9us%2BsITtGUq1q%2B7gQbKzdy2pb2O0kA56MdRM4pJo0UfyRaId0%2Bw%2Bqej5ghdTiV09uTz%2FtxUtGWRElYB6fg%2B9aj1QeRkkC0ndywG3F%2FxA0MMlJ1djWe6IDled2%2FT99MEGcAdP0kCWHyq%2BdayqTeunTsgSKQvoeiEIadIUYw50NMkE1c29A%2BuTXsyKdDuLZ0tolnkXxQkiTLhM0lZjQUML5XOAWEkp7LVdvH6O9TROrWyeWeUJ7YzJCiy3qk00PELvdiqusm%2Fm76UK0zaKmlwcW8cSXagXM3%2Bs9XPa4uiaOZwpvwxwCc7UJxBCj3bxHLKhA%3D%3D&a=ss");
//		if (m.find() && m.groupCount() > 2) {
//			String v = m.group(2);
//			if (!v.equals("")) {
//				System.out.println(v);
//			}
//		}
	}

	// 1. Save Web Pages into nginx html folder

	/**
	 * 删除文件名后缀，后缀suffix如‘.下载’，目录folder为absolute path
	 * 
	 * @param folder
	 * @param suffix
	 */
	private static void remFilenameSuffix(String folder, String suffix) {
		File dir = new File(folder);
		File[] files = dir.listFiles();
		for (File file : files) {
			if (file.isDirectory()) {
				remFilenameSuffix(file.getAbsolutePath(), suffix);
			} else {
				if (file.getAbsolutePath().indexOf(suffix) != -1) {
					file.renameTo(new File(file.getAbsolutePath().replace(suffix, "")));
				}
			}
		}
	}

	/**
	 * 替换文本文件中的无效字符
	 * 
	 * @param path
	 * @throws IOException
	 */
	private static void replacTextContent(String path, String src, String dst) throws IOException {
		File file = new File(path);
		FileReader in = new FileReader(file);
		BufferedReader bufIn = new BufferedReader(in);
		CharArrayWriter tempStream = new CharArrayWriter();
		String line = null;
		while ((line = bufIn.readLine()) != null) {
			line = line.replaceAll(src, dst);
			tempStream.write(line);
			tempStream.append(System.getProperty("line.separator"));
		}
		bufIn.close();
		in.close();
		FileWriter out = new FileWriter(file);
		tempStream.writeTo(out);
		out.close();
		System.out.println("====path:" + path);
	}

	/**
	 * 批量替换文件中的内容
	 * 
	 * @param folder
	 * @param strSrc
	 * @param strDst
	 * @throws IOException
	 */
	private static void batReplcTxtCont(String folder, String strSrc, String strDst) throws IOException {
		File dir = new File(folder);
		File[] files = dir.listFiles();
		for (File file : files) {
			String absPath = file.getAbsolutePath();
			if (file.isDirectory()) {
				batReplcTxtCont(absPath, strSrc, strDst);
			} else {
				if (absPath.indexOf(".js") != -1 && absPath.indexOf(".html") != -1 && absPath.indexOf(".css") != -1) {
					replacTextContent(absPath, strSrc, strDst);
				}
			}
		}
	}

	// 4. Open main html in eclipse and format
	// 5. 检测手机效果

	// 16. 删除断坏链
	// 17. 版权风险处理

	private static void regTest() throws UnsupportedEncodingException {
		JSONObject obj = JSON.parseObject("{\"代理机构名称\":[\r\n" + "		\"华信咨询设计研究院有限公司\"\r\n" + "	]}");
		System.out.println(obj.getJSONArray("代理机构名称").get(0));
	}

	/**
	 * RSA算法生成秘钥对
	 * 
	 * @throws NoSuchAlgorithmException
	 * @throws IOException
	 */
	private static void genKeyPair() throws NoSuchAlgorithmException, IOException {
		KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
		gen.initialize(2048);
		KeyPair keyPair = gen.generateKeyPair();
		PublicKey pubKey = keyPair.getPublic();
		PrivateKey priKey = keyPair.getPrivate();
		byte[] pubEncBytes = pubKey.getEncoded();
		byte[] priEncBytes = priKey.getEncoded();
		final Base64.Encoder encoder = Base64.getEncoder();
		String pubEncBase64 = encoder.encodeToString(pubEncBytes);
		String priEncBase64 = encoder.encodeToString(priEncBytes);
		IOUtils.writeFile(pubEncBase64, new File("pub.txt"));
		IOUtils.writeFile(priEncBase64, new File("pri.txt"));
	}

	/**
	 * ECC椭圆曲线加密
	 */
	private static void genKeyPair_ECC() {
		X9ECParameters ecp = SECNamedCurves.getByName("secp256r1");
		ECDomainParameters ecdp = new ECDomainParameters(ecp.getCurve(), ecp.getG(), ecp.getN(), ecp.getH(),
				ecp.getSeed());
		AsymmetricCipherKeyPair keyPair = null;
		ECKeyGenerationParameters keyGenerationParameters = new ECKeyGenerationParameters(ecdp, new SecureRandom());
		ECKeyPairGenerator generator = new ECKeyPairGenerator();
		generator.init(keyGenerationParameters);
		keyPair = generator.generateKeyPair();
		ECPublicKeyParameters publicKeyParameters = (ECPublicKeyParameters) keyPair.getPublic();
		ECPrivateKeyParameters privateKeyParameters = (ECPrivateKeyParameters) keyPair.getPrivate();
		BigInteger priKey = privateKeyParameters.getD();
		System.out.println("privatekey: " + priKey.toString(16));
		System.out.println("publicKey x: "+publicKeyParameters.getQ().getXCoord().toBigInteger().toString(16));
		System.out.println("publicKey y: "+publicKeyParameters.getQ().getYCoord().toBigInteger().toString(16));
		ECPoint Q = keyGenerationParameters.getDomainParameters().getG().multiply(priKey);
		Q = ECAlgorithms.importPoint(Q.getCurve(), Q).normalize();
		System.out.println(" multiply x: " + Q.getXCoord().toBigInteger().toString(16));
		System.out.println(" multiply x: " + Q.getXCoord().toBigInteger().toString(16));

	}

	private static PublicKey readPubKey() throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
		String pubKeyBase64 = IOUtils.readFile(new File("pub.txt"));
		final Base64.Decoder decoder = Base64.getDecoder();
		byte[] encPubKey = decoder.decode(pubKeyBase64);
		X509EncodedKeySpec encPubKeySpec = new X509EncodedKeySpec(encPubKey);
		PublicKey pubKey = KeyFactory.getInstance("RSA").generatePublic(encPubKeySpec);
		return pubKey;
	}

	private static PrivateKey readPriKey() throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
		String priKeyBase64 = IOUtils.readFile(new File("pri.txt"));
		final Base64.Decoder decoder = Base64.getDecoder();
		byte[] decPriKey = decoder.decode(priKeyBase64);
		PKCS8EncodedKeySpec decPriKeySpec = new PKCS8EncodedKeySpec(decPriKey);
		PrivateKey priKey = KeyFactory.getInstance("RSA").generatePrivate(decPriKeySpec);
		return priKey;
	}

	private static String encrypt(String plain) throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, InvalidKeySpecException, IOException, IllegalBlockSizeException, BadPaddingException {
		Cipher ciEnc = Cipher.getInstance("RSA");
		ciEnc.init(Cipher.ENCRYPT_MODE, readPubKey());
		byte[] data = ciEnc.doFinal(plain.getBytes());
		Base64.Encoder encoder = Base64.getEncoder();
		return encoder.encodeToString(data);
	}

	private static void decrypt(String data)
			throws InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException, IOException,
			NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		Base64.Decoder decoder = Base64.getDecoder();
		byte[] plainData = decoder.decode(data);
		Cipher ciDec = Cipher.getInstance("RSA");
		ciDec.init(Cipher.DECRYPT_MODE, readPriKey());
		byte[] result = ciDec.doFinal(plainData);
		System.out.println(new String(result));
	}

	private static void joda(String evalTime) {
		DateTimeFormatter fmt = DateTimeFormat.forPattern("yyyy-MM-dd HH:mm:ss");
		DateTime dtEval = DateTime.parse(evalTime, fmt);
		DateTime now = DateTime.now();
		Instant upperLimit = now.plusHours(1).toInstant();
		Instant lowerLimit = now.minusHours(1).toInstant();
		if (dtEval.isAfter(lowerLimit) && dtEval.isBefore(upperLimit)) {
			System.out.println("时差在1小时内！");
		} else {
			System.out.println("时差超出1小时！");
		}
	}

}
