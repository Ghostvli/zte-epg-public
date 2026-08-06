import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/** 与 ZTESpider.login() 逐行一致的独立验证程序 */
public class ZteLoginTest {
    static String easIp = "124.132.240.38";
    static String easPort = "8080";
    static String encryptKey = "38828200";
    static String userId = "053804388392";
    static String stbId = "000004370019900018502CCCE649221F";
    static String mac = "2C:CC:E6:49:22:1F";
    static String model = "E900V21C";
    static String customStr = "$CTC";
    static String base;
    static String localIp;

    public static void main(String[] args) throws Exception {
        localIp = detectLocalIp();
        System.out.println("localIp=" + localIp);
        String getUrl = "http://" + easIp + ":" + easPort
                + "/iptvepg/platform/getencrypttoken.jsp?UserID=" + userId
                + "&Action=Login&TerminalFlag=1&TerminalOsType=0&STBID=&stbtype=";
        String handshake = httpGet(getUrl);
        if (handshake == null) { System.out.println("handshake null"); return; }
        Matcher m = Pattern.compile("GetAuthInfo\\('(.*?)'\\)").matcher(handshake);
        if (!m.find()) { System.out.println("no GetAuthInfo"); return; }
        String challenge = m.group(1);
        System.out.println("challenge=" + challenge);
        Matcher m2 = Pattern.compile("<form\\s+action=\"http://([^/]+):\\d+/iptvepg/platform/auth\\.jsp").matcher(handshake);
        if (!m2.find()) { System.out.println("no auth.jsp"); return; }
        base = "http://" + m2.group(1) + ":8080";
        System.out.println("base=" + base);
        long randomNum = new SecureRandom().nextLong() % 9_0000_000L + 1000_0000L;
        String raw = String.format("%d$%s$%s$%s$%s$%s$%s", randomNum, challenge, userId, stbId, localIp, mac, customStr);
        String auth = desEncrypt(raw, encryptKey);
        System.out.println("authenticator=" + auth);
        String authUrl = base + "/iptvepg/platform/auth.jsp?easip=" + easIp + "&ipVersion=4&networkid=1";
        String data = "UserID=" + URLEncoder.encode(userId, "UTF-8")
                + "&Authenticator=" + URLEncoder.encode(auth, "UTF-8")
                + "&StbIP=" + URLEncoder.encode(localIp, "UTF-8");
        String result = httpPost(authUrl, data);
        if (result == null) { System.out.println("auth null"); return; }
        System.out.println("authResult len=" + result.length());
        Matcher m3 = Pattern.compile("jsSetConfig\\('UserToken','([^']+)'").matcher(result);
        String token = null;
        if (m3.find()) token = m3.group(1);
        else {
            Matcher m4 = Pattern.compile("UserToken=([A-Za-z0-9_\\-.]+)").matcher(result);
            if (m4.find()) token = m4.group(1);
        }
        if (token == null) {
            System.out.println("FAIL: " + (result.length() > 300 ? result.substring(0, 300) : result));
        } else {
            System.out.println("SUCCESS UserToken=" + token);
        }
    }

    static String detectLocalIp() throws Exception {
        try {
            try (Socket s = new Socket()) {
                s.connect(new InetSocketAddress(easIp, Integer.parseInt(easPort)), 3000);
                return s.getLocalAddress().getHostAddress();
            }
        } catch (Exception e) {
            return "127.0.0.1";
        }
    }

    static String desEncrypt(String str, String key) throws Exception {
        while (key.length() < 8) key = key + "0";
        byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
        byte[] srcBytes = str.getBytes(StandardCharsets.UTF_8);
        int length = ((srcBytes.length / 8) + 1) * 8;
        byte[] paddingBytes = new byte[length];
        System.arraycopy(srcBytes, 0, paddingBytes, 0, srcBytes.length);
        for (int i = srcBytes.length; i < length; i++) paddingBytes[i] = (byte) (length - srcBytes.length);
        SecretKeySpec spec = new SecretKeySpec(keyBytes, "DES");
        Cipher cipher = Cipher.getInstance("DES/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, spec);
        byte[] enc = cipher.doFinal(paddingBytes);
        StringBuilder sb = new StringBuilder();
        for (byte b : enc) sb.append(String.format("%02X", b));
        return sb.toString().toUpperCase();
    }

    static String httpGet(String urlStr) {
        try {
            HttpURLConnection conn = (HttpURLConnection) new URL(urlStr).openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(8000);
            conn.setReadTimeout(8000);
            conn.setInstanceFollowRedirects(true);
            conn.setRequestProperty("Accept-Language", "zh-CN,en-US;q=0.8");
            conn.setRequestProperty("X-Requested-With", "com.android.smart.terminal.iptv");
            if (conn.getResponseCode() != 200) { conn.disconnect(); return null; }
            BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream(), "UTF-8"));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = in.readLine()) != null) sb.append(line);
            in.close();
            conn.disconnect();
            return sb.toString();
        } catch (Exception e) { return null; }
    }

    static String httpPost(String urlStr, String data) {
        try {
            HttpURLConnection conn = (HttpURLConnection) new URL(urlStr).openConnection();
            conn.setRequestMethod("POST");
            conn.setConnectTimeout(8000);
            conn.setReadTimeout(8000);
            conn.setInstanceFollowRedirects(true);
            conn.setDoOutput(true);
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            byte[] bytes = data.getBytes(StandardCharsets.UTF_8);
            conn.setRequestProperty("Content-Length", String.valueOf(bytes.length));
            conn.getOutputStream().write(bytes);
            int code = conn.getResponseCode();
            if (code != 200) { conn.disconnect(); return null; }
            String charset = "UTF-8";
            String ct = conn.getContentType();
            if (ct != null && (ct.toLowerCase().contains("gbk") || ct.toLowerCase().contains("gb2312"))) charset = "GBK";
            BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream(), charset));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = in.readLine()) != null) sb.append(line).append("\n");
            in.close();
            conn.disconnect();
            return sb.toString();
        } catch (Exception e) { return null; }
    }
}
