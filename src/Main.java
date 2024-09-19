import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Enumeration;

public class Main {
    public static void main(String[] args) {
        if (args.length != 3) {
            System.out.println("Argumentos insuficientes");
            System.exit(-1);
//            Validate("13428298_identity_1720916079.p12", "Trend2024", "1793209168");
        } else {
            Validate(args[0], args[1], args[2]);
        }
    }

    public static Date Validate(String path, String password, String ruc) {
        InputStream stream = null;
        try {
            stream = new FileInputStream(path);
        } catch (Exception e) {
            System.out.println("Bad path");
            System.exit(-1);
        }
        try {
            KeyStore store = KeyStore.getInstance("PKCS12");
            store.load(stream, password.toCharArray());
            Enumeration<String> aliases = store.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                X509Certificate certFromKeyStore = (X509Certificate) store.getCertificate(alias);
                String a = certFromKeyStore.toString().replaceAll("\\n\\r", "");
                validateRuc(a, ruc);
                Date certExpiryDate = ((X509Certificate) store.getCertificate(alias)).getNotAfter();
                SimpleDateFormat ft = new SimpleDateFormat("yyyy-MM-dd");
                ft.format(certExpiryDate);
                Date today = new Date();
                long dateDiff = certExpiryDate.getTime() - today.getTime();
                long expiresIn = dateDiff / (24 * 60 * 60 * 1000);
                if (expiresIn < 0) {
                    System.out.println("Firma expirada desde " + ft.format(certExpiryDate));
                    System.exit(-2);
                } else {
                    System.out.println(ft.format(certExpiryDate));
                    System.exit(0);
                }
            }
        } catch (Exception e) {
            System.out.println("Contraseña Incorrecta");
            System.exit(-3);
        }
        return null;
    }

    public static void validateRuc(String subject, String ruc) {
        try {
            var x = subject.contains(ruc);
            if (!x) {
                System.out.println("RUC Incorrecto");
                System.exit(-4);
            }
        }catch (Exception e){
            System.exit(-5);
        }
    }
}