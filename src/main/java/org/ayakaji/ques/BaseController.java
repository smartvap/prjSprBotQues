package org.ayakaji.ques;

import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.joda.time.DateTime;
import org.joda.time.Instant;
import org.joda.time.format.DateTimeFormat;
import org.joda.time.format.DateTimeFormatter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.xiets.rsa.IOUtils;

@RestController
public class BaseController {

	private static DateTimeFormatter fmt = DateTimeFormat.forPattern("yyyy-MM-dd HH:mm:ss");
	private static PrivateKey priKey = null;

	static {
		try {
			priKey = readPriKey();
		} catch (InvalidKeySpecException | NoSuchAlgorithmException | IOException e) {
			e.printStackTrace();
		}
	}

	private static Map<String, String> mapField = new HashMap<String, String>() {
		private static final long serialVersionUID = -8114711583442737790L;
		{
			// 第1部分：
			put("5e86c9dd92beb5256396052b", "项目名称");
			put("5e86c9de92beb5256396052c_open", "项目名称");
			put("5e86e2b63631f2719bc6f06a", "项目编号");
			put("5e86e3b792beb5230bccfb14_open", "项目编号");
			put("5e86ce063631f2728c89a7d2", "评审日期");
			put("5e86ce073631f2728c89a7d3_open", "评审日期");
			put("5e86cfc53631f27133947816", "评审地点");
			put("5e86cfc53631f27133947817_open", "一级");
			put("5e86cfc53631f27133947818_open", "二级");
			put("5e86d07992beb52596397320_open", "三级");
			put("5e86e42892beb52482abbff0", "代理机构名称");
			// 第2部分：对评审组织的总体满意度
			put("5e830e9492beb5146e291c29", "组织工作");
			put("5e830e9492beb5146e291c33", "代理机构对评审工作组织情况");
			put("5e830e9492beb5146e291c34", "代理机构按法定程序组织评审情况");
			put("5e830e9492beb5146e291c35", "代理机构评审工作合法合规情况");
			put("5e830e9492beb5146e291c36", "评委评审工作合法合规情况");
			put("5e83133f3631f229b8af25a2", "对评审工作的其他建议");
			put("5e8313403631f229b8af25a3_open", "对评审工作的其他建议");
			// 第3部分：
			put("5e830e9492beb5146e291c2a", "对办公条件及环境的满意度");
			put("5e830e9492beb5146e291c3f", "对办公条件及环境的满意度");
			put("5e86d3013631f26fb3adaf8c", "对餐饮、住宿的满意度");
			put("5e86d3013631f26fb3adaf91", "对餐饮的满意度");
			put("5e86d3c73631f270a165d371", "对住宿的满意度");
			put("5e86d3fe3631f270d19569aa", "对办公、餐饮和住宿的建议");
			put("5e86d3fe3631f270d19569ac", "对调查表的改进建议");
			put("5e86d3fe3631f270d19569ab_open", "对办公、餐饮和住宿的建议");
			put("5e86d3fe3631f270d19569ad_open", "对调查表的改进建议");
			// 字典
			put("5e830e9492beb5146e291c2e", "十分满意");
			put("5e830e9492beb5146e291c2f", "满意");
			put("5e830e9492beb5146e291c30", "基本满意");
			put("5e83121b3631f22a58a401fb", "不满意");
			put("5e830e9492beb5146e291c3a", "十分满意");
			put("5e830e9492beb5146e291c3b", "满意");
			put("5e830e9492beb5146e291c3c", "基本满意");
			put("5e8313ef3631f22b8eb13391", "不满意");
			put("5e86d3013631f26fb3adaf8d", "十分满意");
			put("5e86d3013631f26fb3adaf8e", "满意");
			put("5e86d3013631f26fb3adaf8f", "基本满意");
			put("5e86d3013631f26fb3adaf8g", "无住宿");
			put("5e86d3013631f26fb3adaf90", "不满意");
		}
	};

	private Map<String, String> mapVal = new HashMap<String, String>(); // 字段值

	@Autowired
	private NamedParameterJdbcTemplate jdbcTemplate;

	private static PrivateKey readPriKey() throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
		String priKeyBase64 = IOUtils.readFile(new File("pri.txt"));
		final Base64.Decoder decoder = Base64.getDecoder();
		byte[] decPriKey = decoder.decode(priKeyBase64);
		PKCS8EncodedKeySpec decPriKeySpec = new PKCS8EncodedKeySpec(decPriKey);
		PrivateKey priKey = KeyFactory.getInstance("RSA").generatePrivate(decPriKeySpec);
		return priKey;
	}

	/**
	 * Parse Parameter with key
	 * 
	 * @param param
	 * @param key
	 * @return
	 * @throws UnsupportedEncodingException
	 */
	private String parseParam(String param, String key) throws UnsupportedEncodingException {
		String decoded = URLDecoder.decode(param, "UTF-8");
		Pattern p = Pattern.compile("(" + key + "=)([^&]*)(&|$)");
		Matcher m = p.matcher(decoded);
		if (m.find() && m.groupCount() > 2) {
			String v = m.group(2);
			if (!v.equals("")) {
				return v;
			}
		}
		return null;
	}

	/**
	 * decrypt ciphertext
	 * 
	 * @param secret
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	private String decrypt(String secret) {
		if (secret == null || secret.equals(""))
			return null;
		Cipher ciDec = null;
		try {
			ciDec = Cipher.getInstance("RSA");
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			e.printStackTrace();
		}
		if (ciDec == null)
			return null;
		try {
			ciDec.init(Cipher.DECRYPT_MODE, priKey);
		} catch (InvalidKeyException e) {
			e.printStackTrace();
			return null;
		}
		byte[] b1 = null; // base64 decoded bytes
		byte[] b2 = null; // decrypted bytes
		Base64.Decoder decoder = Base64.getDecoder();
		b1 = decoder.decode(secret);
		try {
			b2 = ciDec.doFinal(b1);
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
			return null;
		}
		if (b2 == null || b2.length == 0)
			return null;
		return new String(b2);
	}

	/**
	 * Validate Evaluator Id
	 * 
	 * @param evalId
	 * @return
	 */
	private boolean validate(String evalId) {
		if (evalId == null || evalId.equals(""))
			return false;
		String[] arr = evalId.split("[,]");
		if (arr.length < 2)
			return false;
		DateTime dtEval = DateTime.parse(arr[1], fmt);
		DateTime now = DateTime.now();
		Instant upperLimit = now.plusHours(1).toInstant();
		Instant lowerLimit = now.minusHours(1).toInstant();
		if (dtEval.isAfter(lowerLimit) && dtEval.isBefore(upperLimit)) {
			mapVal.put("telNum", arr[0]);
			return true;
		} else {
			return false;
		}
	}

	@RequestMapping("/survey/main.html")
	public String store(@RequestBody String param) throws UnsupportedEncodingException {
		String evalId = parseParam(param, "evaluator_id");
		if (evalId == null || evalId.equals("")) return null;
		String tel_time = decrypt(evalId);
		if (tel_time == null || tel_time.equals("")) return null;
		if (!validate(tel_time)) return null;
		String json = parseParam(param, "total_answers_str");
		for (String key : mapField.keySet()) { // 替换报文关键词
			json = json.replaceAll(key, mapField.get(key));
		}
		JSONObject jsonObj = JSONObject.parseObject(json);
		mapVal.put("projName", jsonObj.getJSONObject("项目名称").getString("项目名称"));
		mapVal.put("projId", jsonObj.getJSONObject("项目编号").getString("项目编号"));
		mapVal.put("revDate", jsonObj.getJSONObject("评审日期").getString("评审日期"));
		JSONObject jsonRevLoc = jsonObj.getJSONObject("评审地点");
		mapVal.put("revLoc",
				jsonRevLoc.getString("一级") + (jsonRevLoc.containsKey("二级") ? jsonRevLoc.getString("二级") : "")
						+ (jsonRevLoc.containsKey("三级") ? jsonRevLoc.getString("三级") : ""));
		mapVal.put("agentName", jsonObj.getJSONArray("代理机构名称").getString(0));
		JSONArray arrJdgLeg = jsonObj.getJSONObject("组织工作").getJSONArray("评委评审工作合法合规情况");
		mapVal.put("jdgLeg", arrJdgLeg.getString(0));
		mapVal.put("jdgLegDtl", arrJdgLeg.size() > 1 ? arrJdgLeg.getString(1) : "");
		JSONArray arrRevOgnz = jsonObj.getJSONObject("组织工作").getJSONArray("代理机构对评审工作组织情况");
		mapVal.put("revOgnz", arrRevOgnz.getString(0));
		mapVal.put("revOgnzDtl", arrRevOgnz.size() > 1 ? arrRevOgnz.getString(1) : "");
		JSONArray arrLegProc = jsonObj.getJSONObject("组织工作").getJSONArray("代理机构按法定程序组织评审情况");
		mapVal.put("legProc", arrLegProc.getString(0));
		mapVal.put("legProcDtl", arrLegProc.size() > 1 ? arrLegProc.getString(1) : "");
		JSONArray arrRevLeg = jsonObj.getJSONObject("组织工作").getJSONArray("代理机构评审工作合法合规情况");
		mapVal.put("revLeg", arrRevLeg.getString(0));
		mapVal.put("revLegDtl", arrRevLeg.size() > 1 ? arrRevLeg.getString(1) : "");
		if (jsonObj.containsKey("对评审工作的其他建议")) {
			mapVal.put("revSugg", jsonObj.getJSONObject("对评审工作的其他建议").getString("对评审工作的其他建议"));
		}
		JSONArray arrOfcEnv = jsonObj.getJSONObject("对办公条件及环境的满意度").getJSONArray("对办公条件及环境的满意度");
		mapVal.put("ofcEnv", arrOfcEnv.getString(0));
		mapVal.put("ofcEnvDtl", arrOfcEnv.size() > 1 ? arrOfcEnv.getString(1) : "");
		if (jsonObj.containsKey("对餐饮、住宿的满意度")) {
			JSONArray arrCatEval = jsonObj.getJSONObject("对餐饮、住宿的满意度").getJSONArray("对餐饮的满意度");
			mapVal.put("catEval", arrCatEval.size() > 0 ? arrCatEval.getString(0) : "");
			mapVal.put("catEvalDtl", arrCatEval.size() > 1 ? arrCatEval.getString(1) : "");
			JSONArray arrHtlEval = jsonObj.getJSONObject("对餐饮、住宿的满意度").getJSONArray("对住宿的满意度");
			mapVal.put("htlEval", arrHtlEval.size() > 0 ? arrHtlEval.getString(0) : "");
			mapVal.put("catHtlEval", arrHtlEval.size() > 1 ? arrHtlEval.getString(1) : "");
		}
		if (jsonObj.containsKey("对办公、餐饮和住宿的建议")) {
			mapVal.put("catHtlSugg", jsonObj.getJSONObject("对办公、餐饮和住宿的建议").getString("对办公、餐饮和住宿的建议"));
		}
		if (jsonObj.containsKey("对调查表的改进建议")) {
			mapVal.put("quesImprSugg", jsonObj.getJSONObject("对调查表的改进建议").getString("对调查表的改进建议"));
		}
		exec();
		return "Success!";
	}

	private void exec() {
		String sqlTxt = "INSERT INTO sat_survey (sat_id, proj_name, proj_id, rev_date, rev_loc, agent_name, rev_ognz, rev_ognz_dtl, "
				+ "leg_proc, leg_proc_dtl, rev_leg, rev_leg_dtl, jdg_leg, jdg_leg_dtl, rev_sugg, ofc_env, ofc_env_dtl, cat_eval, "
				+ "cat_eval_dtl, htl_eval, htl_eval_dtl, cat_htl_sugg, ques_impr_sugg, evtr_id) VALUES (seq_sat_id.nextval, :projName, "
				+ ":projId, :revDate, :revLoc, :agentName, :revOgnz, :revOgnzDtl, :legProc, :legProcDtl, :revLeg, :revLegDtl, :jdgLeg, "
				+ ":jdgLegDtl, :revSugg, :ofcEnv, :ofcEnvDtl, :catEval, :catEvalDtl, :htlEval, :htlEvalDtl, :catHtlSugg, :quesImprSugg, :evtrId)";
		Map<String, Object> para = new HashMap<String, Object>() {
			private static final long serialVersionUID = 6002845785012072073L;
			{
				put("projName", mapVal.get("projName"));
				put("projId", mapVal.get("projId"));
				put("revDate", mapVal.get("revDate"));
				put("revLoc", mapVal.get("revLoc"));
				put("agentName", mapVal.get("agentName"));
				put("revOgnz", mapVal.get("revOgnz"));
				put("revOgnzDtl", mapVal.get("revOgnzDtl"));
				put("legProc", mapVal.get("legProc"));
				put("legProcDtl", mapVal.get("legProcDtl"));
				put("revLeg", mapVal.get("revLeg"));
				put("revLegDtl", mapVal.get("revLegDtl"));
				put("jdgLeg", mapVal.get("jdgLeg"));
				put("jdgLegDtl", mapVal.get("jdgLegDtl"));
				put("revSugg", mapVal.get("revSugg"));
				put("ofcEnv", mapVal.get("ofcEnv"));
				put("ofcEnvDtl", mapVal.get("ofcEnvDtl"));
				put("catEval", mapVal.get("catEval"));
				put("catEvalDtl", mapVal.get("catEvalDtl"));
				put("htlEval", mapVal.get("htlEval"));
				put("htlEvalDtl", mapVal.get("htlEvalDtl"));
				put("catHtlSugg", mapVal.get("catHtlSugg"));
				put("quesImprSugg", mapVal.get("quesImprSugg"));
				put("evtrId", mapVal.get("telNum"));
			}
		};
		jdbcTemplate.update(sqlTxt, para);
	}
}