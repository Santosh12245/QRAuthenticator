package QrAuthentication.controller;

import QrAuthentication.utils.TotpUtil;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
public class AuthController {

    // Store secret here statically for demo (in real app, store per user in DB)
    private static String secret;

    private static final String ACCOUNT_NAME = "MyApplication@iserveu";
    private static final String ISSUER = "My2FAApp";

    @GetMapping("/qrcode")
    public ResponseEntity<String> getQrCode() throws Exception {
        if (secret == null) {
            secret = TotpUtil.generateSecret();
        }
        String qrCodeDataUri = TotpUtil.getQrCodeDataUri(secret, ACCOUNT_NAME, ISSUER);
        String html = "<!DOCTYPE html>" +
                "<html lang='en'>" +
                "<head>" +
                "  <meta charset='UTF-8'>" +
                "  <title>Scan QR for 2FA</title>" +
                "  <style>" +
                "    body { font-family: Arial, sans-serif; background: linear-gradient(135deg, #1d2b64, #f8cdda); color: #fff; text-align: center; padding: 50px; }" +
                "    .qr-container { background: #fff; color: #000; padding: 30px; border-radius: 16px; box-shadow: 0 0 20px rgba(0,0,0,0.3); display: inline-block; }" +
                "    .qr-title { font-size: 24px; margin-bottom: 20px; }" +
                "    .secret { margin-top: 20px; font-size: 16px; color: #f3f3f3; word-break: break-all; }" +
                "    img { width: 250px; height: 250px; border: 10px solid #fff; border-radius: 16px; }" +
                "  </style>" +
                "</head>" +
                "<body>" +
                "  <div class='qr-container'>" +
                "    <div class='qr-title'>Scan this QR code using Google Authenticator</div>" +
                "    <img src='" + qrCodeDataUri + "' alt='2FA QR Code'>" +
                "    <div class='secret'>Secret Key (keep this safe):<br><b>" + secret + "</b></div>" +
                "  </div>" +
                "</body>" +
                "</html>";

        return ResponseEntity.ok().header("Content-Type", "text/html").body(html);
    }

    @PostMapping("/verify")
    public String verifyCode(@RequestBody Map<String, String> payload) {
        if (secret == null) {
            return "Secret not generated yet! Visit /api/qrcode first.";
        }

        String code = payload.get("code");
        if (code == null || code.isEmpty()) {
            return "Code is required!";
        }

        boolean valid = TotpUtil.verifyCode(secret, code);
        return valid ? "✅ Verified!" : "❌ Invalid code!";
    }
}
