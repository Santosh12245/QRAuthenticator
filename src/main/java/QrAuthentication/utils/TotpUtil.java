package QrAuthentication.utils;

import dev.samstevens.totp.code.*;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.ZxingPngQrGenerator;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;
import dev.samstevens.totp.util.Utils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class TotpUtil {
    private static final SecretGenerator secretGenerator = new DefaultSecretGenerator();
    private static final CodeGenerator codeGenerator = new DefaultCodeGenerator();
    private static final TimeProvider timeProvider = new SystemTimeProvider();
    private static final ZxingPngQrGenerator qrGenerator = new ZxingPngQrGenerator();

    // Generate a new secret key (do this once per user)
    public static String generateSecret() {
        return secretGenerator.generate();
    }

    // Generate QR code as Data URI String (for embedding in img src)
    public static String getQrCodeDataUri(String secret, String account, String issuer) throws Exception {
        QrData data = new QrData.Builder()
                .label(issuer + ":" + account)
                .secret(secret)
                .issuer(issuer)
                .digits(6)
                .period(30)
                .build();

        byte[] imageData = qrGenerator.generate(data);
        String mimeType = qrGenerator.getImageMimeType();

        return Utils.getDataUriForImage(imageData, mimeType);
    }

    // Verify code with ±1 time step tolerance
    public static boolean verifyCode(String secret, String code) {
        DefaultCodeVerifier verifier = new DefaultCodeVerifier(codeGenerator, timeProvider);
        verifier.setAllowedTimePeriodDiscrepancy(1); // ±1 step = 30 seconds
        return verifier.isValidCode(secret, code);
    }

}
