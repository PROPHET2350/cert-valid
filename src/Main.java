import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Enumeration;

public class Main {
    public static void main(String[] args) {
        Validate("13428298_identity_1720916079.p12", "Trend2024");
    }

    public static Date Validate(String path, String password) {
        InputStream stream;
        try {
            stream = new FileInputStream(path);
        } catch (Exception e) {
            System.exit(-2);
            throw new IllegalArgumentException("Bad path");
        }
        try {
            KeyStore store = KeyStore.getInstance("PKCS12");
            store.load(stream, password.toCharArray());
            Enumeration<String> aliases = store.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                X509Certificate certFromKeyStore = (X509Certificate) store.getCertificate(alias);
                String subject = certFromKeyStore.getSubjectX500Principal().toString();
                Date certExpiryDate = ((X509Certificate) store.getCertificate(alias)).getNotAfter();
                SimpleDateFormat ft = new SimpleDateFormat("yyyy-MM-dd");
                ft.format(certExpiryDate);
                Date today = new Date();
                long dateDiff = certExpiryDate.getTime() - today.getTime();
                long expiresIn = dateDiff / (24 * 60 * 60 * 1000);
                System.out.println(ft.format(certExpiryDate));
                if (expiresIn < 0) {
                    System.out.println("FIRMA EXPIRADA");
                    System.exit(-1);
                    throw new IllegalArgumentException("The sign is expired, expiration date is " + certExpiryDate);
                } else {
                    System.out.println("CASO BUENO");
                    System.exit(0);
                }
            }
        } catch (Exception e) {
            System.out.println("Contraseña Incorrecta");
            System.exit(-1);
            throw new IllegalArgumentException(e.getMessage());
        }
        return null;
    }

    public static void validateRuc(String subject, String ruc) {
        var split = subject.split(" ");
        var certRuc = "";
        if (split.length > 0) {
            var secondSplit = split[0].split("-");
            if (secondSplit.length >= 1) {
                certRuc = secondSplit[1].replaceAll("[^\\d-]|-(?=\\D)", "");
                System.out.println(certRuc);
            }
        }
        if (!certRuc.equals(ruc)) {
            System.out.println("RUC NO COINCIDE");
        }
    }
}