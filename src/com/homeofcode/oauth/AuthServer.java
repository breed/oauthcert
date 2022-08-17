package com.homeofcode.oauth;

import com.homeofcode.https.HttpPath;
import com.homeofcode.https.MultiPartFormDataParser;
import com.homeofcode.https.SimpleHttpsServer;
import com.sun.net.httpserver.HttpExchange;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.json.JSONObject;
import picocli.CommandLine;
import picocli.CommandLine.Help;

import javax.net.ssl.HttpsURLConnection;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.Date;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Calendar;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Properties;
import java.util.Random;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import static java.lang.System.Logger.Level.INFO;
import static java.net.HttpURLConnection.HTTP_BAD_REQUEST;
import static java.net.HttpURLConnection.HTTP_MOVED_TEMP;
import static java.net.HttpURLConnection.HTTP_OK;

public class AuthServer {
    public static final String LOGIN_CALLBACK = "/login/callback";
    final static String OPEN_ID_ENDPT = "https://accounts.google.com/.well-known/openid-configuration";
    static System.Logger LOG = System.getLogger(AuthServer.class.getPackageName());
    static String errorHTML;
    static String successHTML;
    static String uploadHTML;
    static byte[] faviconICO;
    static String styleCSS;

    // this will be filled in by setUpOutput and used by error() and info()
    static int screenWidth;

    static {
        try {
            errorHTML = getResource("/pages/error.html");
            successHTML = getResource("/pages/success.html");
            uploadHTML = getResource("/pages/upload.html");
            faviconICO = getBinaryResource("/favicon.png");
            styleCSS = getResource("/style.css");
        } catch (IOException e) {
            e.printStackTrace();
            System.exit(1);
        }
    }

    /**
     * the nonces that are currently being authenticated
     */
    public ConcurrentHashMap<String, NonceRecord> nonces = new ConcurrentHashMap<>();
    Random rand = new Random();
    /**
     * the client_id used to talk to google services
     */
    String clientId;
    /**
     * the client_secret used to talk to google services
     */
    String clientSecret;
    /**
     * the URL that should be invoked with authentication at google finishes
     */
    String authRedirectURL;
    String httpsURLPrefix;
    /**
     * the domain (email domain) of the idea that is being authenticated
     */
    String authDomain;
    /**
     * File path to your CA private key file, read from properties file
     */
    String CAPrivateKey;
    /**
     * File path to your CA certification file, read from properties file
     */
    String CACert;
    /**
     * the endpoint used to get the JWT token
     */
    String tokenEndpoint;
    /**
     * the endpoint used to start oauth
     */
    String authEndpoint;
    ScheduledExecutorService scheduledExecutor = Executors.newSingleThreadScheduledExecutor();

    private Connection connection;

    AuthServer(Properties properties) throws IOException {
        this.clientId = getProperty(properties, "clientId");
        this.clientSecret = getProperty(properties, "clientSecret");
        this.authRedirectURL = getProperty(properties, "redirectURL");
        this.authDomain = getProperty(properties, "authDomain");
        this.CAPrivateKey = getProperty(properties, "CAPrivateKey");
        this.CACert = getProperty(properties, "CACert");
        var authDBFile = getProperty(properties, "authDBFile");


        var indexOfPath = authRedirectURL.indexOf('/', 8); // find the / just past the https://
        if (indexOfPath == -1) {
            this.httpsURLPrefix = authRedirectURL;
        } else {
            this.httpsURLPrefix = authRedirectURL.substring(0, indexOfPath);
        }

        var endptsStr = new String(new URL(OPEN_ID_ENDPT).openConnection().getInputStream().readAllBytes());
        var endpts = new JSONObject(endptsStr);
        tokenEndpoint = endpts.getString("token_endpoint");
        authEndpoint = endpts.getString("authorization_endpoint");

        try {
            this.connection = DriverManager.getConnection(authDBFile);
            certificateTable();
        } catch (SQLException e) {
            System.out.println("problem accessing database: " + e.getMessage());
            System.exit(3);
        }
    }

    static private String getResource(String path) throws IOException {
        try (var stream = AuthServer.class.getResourceAsStream(path)) {
            if (stream == null) throw new FileNotFoundException(path);
            return new String(stream.readAllBytes());
        }
    }

    static private byte[] getBinaryResource(String path) throws IOException {
        try (var stream = AuthServer.class.getResourceAsStream(path)) {
            if (stream == null) throw new FileNotFoundException(path);
            return stream.readAllBytes();
        }
    }

    private static void redirect(HttpExchange exchange, String redirectURL) throws IOException {
        exchange.getRequestBody().close();
        exchange.getResponseHeaders().add("Location", redirectURL);
        exchange.sendResponseHeaders(HTTP_MOVED_TEMP, 0);
        exchange.getResponseBody().write(String.format("<a href=%1$s>%1$s</a>", redirectURL).getBytes());
        exchange.getResponseBody().close();
    }

    private static HashMap<String, String> extractParams(HttpExchange exchange) {
        var params = new HashMap<String, String>();
        for (var param : exchange.getRequestURI().getQuery().split("&")) {
            var keyVal = param.split("=", 2);
            params.put(keyVal[0], URLDecoder.decode(keyVal[1], Charset.defaultCharset()));
        }
        return params;
    }

    private static void sendOKResponse(HttpExchange exchange, byte[] response) throws IOException {
        exchange.getRequestBody().close();
        exchange.sendResponseHeaders(HTTP_OK, response.length);
        try (var os = exchange.getResponseBody()) {
            os.write(response);
        }
    }

    private static void setupOutput(CommandLine cmdline) {
        var spec = cmdline.getCommandSpec();
        spec.usageMessage().autoWidth(true);
        screenWidth = spec.usageMessage().width();
    }

    public static void main(String[] args) {
        var commandLine = new CommandLine(new Cli()).registerConverter(FileReader.class, s -> {
            try {
                return new FileReader(s);
            } catch (Exception e) {
                throw new CommandLine.TypeConversionException(e.getMessage());
            }
        });
        setupOutput(commandLine);
        int exitCode = commandLine.execute(args);
        System.exit(exitCode);
    }

    private static String getProperty(Properties properties, String key) {
        var value = properties.getProperty(key);
        if (value == null) {
            System.out.printf("%s property missing from property file\n", key);
            System.exit(1);
        }
        return value;
    }

    private static byte[] fullyRead(InputStream is) throws IOException {
        var baos = new ByteArrayOutputStream();
        is.transferTo(baos);
        return baos.toByteArray();
    }

    public String decodeCSR(byte[] csrBytes) throws IOException {
        String email = "";
        PEMParser pemParser = new PEMParser(new InputStreamReader(new ByteArrayInputStream(csrBytes)));
        var obj = pemParser.readObject();
        PKCS10CertificationRequest csr = (PKCS10CertificationRequest) obj;
        var names = new X500Name(RFC4519Style.INSTANCE, csr.getSubject().getRDNs());
        for (var rdn : names.getRDNs()) {
            for (var tv : rdn.getTypesAndValues()) {
                if (tv.getType().equals(RFC4519Style.cn))
                    email = tv.getValue().toString();
            }
        }
        return email;
    }

    public byte[] signCSR(byte[] csrBytes) throws IOException,
            OperatorCreationException// temporarily void until download is setup
    {
        var rand = new Random();
        var now = Calendar.getInstance();
        var expire = Calendar.getInstance();
        expire.add(Calendar.MONTH, 4);
        PEMParser pemParser = new PEMParser(new InputStreamReader(new ByteArrayInputStream(csrBytes)));
        var obj = pemParser.readObject();
        PKCS10CertificationRequest csr = (PKCS10CertificationRequest) obj;
        var caParser = new PEMParser(new FileReader(CAPrivateKey));
        var caPriv = (PrivateKeyInfo) caParser.readObject();
        caParser = new PEMParser(new FileReader(CACert));
        var caCert = (X509CertificateHolder) caParser.readObject();
        var names = new X500Name(RFC4519Style.INSTANCE, csr.getSubject().getRDNs());
        ASN1Primitive email = null;
        for (var rdn : names.getRDNs()) {
            for (var tv : rdn.getTypesAndValues()) {
                if (tv.getType().equals(RFC4519Style.cn)) email = tv.getValue().toASN1Primitive();
            }
        }
        var subject = new X500Name(new RDN[]{new RDN(new AttributeTypeAndValue(RFC4519Style.cn, email))});
        // from https://stackoverflow.com/questions/7230330/sign-csr-using-bouncy-castle
        var builder = new X509v3CertificateBuilder(
                caCert.getIssuer(),
                new BigInteger(128, rand),
                now.getTime(),
                expire.getTime(),
                subject,
                csr.getSubjectPublicKeyInfo()
        );
        var sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA1withRSA");
        var digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
        var signer =
                new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(
                        PrivateKeyFactory.createKey(caPriv.getEncoded()));
        var holder = builder.build(signer);
        var baos = new ByteArrayOutputStream();
        var writer = new JcaPEMWriter(new OutputStreamWriter(baos));
        writer.writeObject(holder);
        writer.close();
        return baos.toByteArray();
    }

    void certificateTable() throws SQLException {
        var stmt = connection.createStatement();
        stmt.execute("""
                create table if not exists certificate (
                serialNumber text primary key,
                email text,
                revoked int,
                expirationDate date,
                signedCertificate text
                );""");
    }

    void updateCertificateTable(String serialNumber, String email, int revoked,
                                Date expDate, String signedCertificate) throws SQLException {
        var stmt = connection.prepareStatement("""
                replace into certificate (
                serialNumber,
                email,
                revoked,
                expirationDate,
                signedCertificate
                ) values (?,?,?,?,?);""");
        stmt.setString(1, serialNumber);
        stmt.setString(2, email);
        stmt.setInt(3, revoked);
        stmt.setDate(4, expDate);
        stmt.setString(5, signedCertificate);
        stmt.execute();
    }

    private String createAuthURL(NonceRecord nonceRecord) {
        return authEndpoint +
                "?response_type=code&scope=openid%20email" +
                "&client_id=" + URLEncoder.encode(clientId, Charset.defaultCharset()) +
                "&redirect_uri=" + URLEncoder.encode(authRedirectURL, Charset.defaultCharset()) +
                "&state=" + URLEncoder.encode(nonceRecord.state, Charset.defaultCharset()) +
                "&nonce=" + URLEncoder.encode(nonceRecord.nonce, Charset.defaultCharset()) +
                "&hd=" + URLEncoder.encode(authDomain, Charset.defaultCharset());
    }

    synchronized private void checkExpirations() {
        var toDelete = new LinkedList<String>();
        LocalDateTime now = LocalDateTime.now();
        LocalDateTime nextExpire = null;
        for (var e : nonces.entrySet()) {
            var v = e.getValue();
            if (v.expireTime.isAfter(now)) {
                if (nextExpire == null || nextExpire.isAfter(v.expireTime)) {
                    nextExpire = v.expireTime;
                }
            } else {
                toDelete.add(e.getKey());
            }
        }
        for (var key : toDelete) {
            var nr = nonces.remove(key);
            nr.complete(null);
        }
        if (nextExpire != null) {
            scheduledExecutor.schedule(this::checkExpirations, now.until(nextExpire, ChronoUnit.SECONDS),
                    TimeUnit.SECONDS);
        }
    }

    public void sendFileDownload(HttpExchange exchange, byte[] data, String fileName) throws Exception {
        exchange.getResponseHeaders().add("Content-Disposition", "attachment; filename=" + fileName);
        exchange.sendResponseHeaders(HTTP_OK, data.length);
        OutputStream outputStream = exchange.getResponseBody();
        outputStream.write(data);
        outputStream.close();
    }

    synchronized public NonceRecord createValidation(byte[] csrFile) {
        var nonceRecord =
                new NonceRecord(Long.toHexString(rand.nextLong()), Long.toHexString(rand.nextLong()),
                        LocalDateTime.now().plus(5, ChronoUnit.MINUTES),
                        new CompletableFuture<>(), csrFile);
        if (nonces.isEmpty()) {
            scheduledExecutor.schedule(this::checkExpirations, 5, TimeUnit.MINUTES);
        }
        nonces.put(nonceRecord.nonce, nonceRecord);
        return nonceRecord;
    }

    @HttpPath(path = "/")
    public void rootPage(HttpExchange exchange) throws Exception {
        sendOKResponse(exchange, uploadHTML.getBytes());
    }

    @HttpPath(path = "/favicon.ico")
    public void favIcon(HttpExchange exchange) throws Exception {
        sendFileDownload(exchange, faviconICO, "favicon.png");
    }

    @HttpPath(path = "/style.css")
    public void styling(HttpExchange exchange) throws Exception {
        exchange.getResponseHeaders().add("Link", "rel=stylesheet href=style.css");
        exchange.sendResponseHeaders(HTTP_OK, styleCSS.length());
        OutputStream outputStream = exchange.getResponseBody();
        outputStream.write(styleCSS.getBytes());
        outputStream.close();
    }

    @HttpPath(path = "/upload")
    public void uploadPage(HttpExchange exchange) throws Exception {
        var fp = new MultiPartFormDataParser(exchange.getRequestBody());
        //putting into concurrent hashmap to feed into CertPOC
        var ff = fp.nextField();
        var bytes = fullyRead(ff.is);
        //nonce
        String nonce = new BigInteger(128, rand).toString();
        var nonceRecord = new NonceRecord(nonce, Long.toHexString(rand.nextLong()), LocalDateTime.now().plus(5,
                ChronoUnit.MINUTES), new CompletableFuture<>(), bytes);
        var authURL = createAuthURL(nonceRecord);
        nonces.put(nonce, nonceRecord);
        redirect(exchange, authURL);
    }

    @HttpPath(path = "/crl")
    public void returnCRL(HttpExchange exchange) throws Exception {
        //X500 Name comes from X509Certificate and use getSubject()
        var caParser = new PEMParser(new FileReader(CAPrivateKey));
        var caPriv = (PrivateKeyInfo) caParser.readObject();
        caParser = new PEMParser(new FileReader(CACert));
        var caCert = (X509CertificateHolder) caParser.readObject();
        X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(
                caCert.getSubject(),
                Calendar.getInstance().getTime()
        );
        String query = "select serialNumber from certificate where revoked = True";
        try (Statement ps = connection.createStatement()) {
            boolean rc = ps.execute(query);
            if (rc) {
                ResultSet rs = ps.getResultSet();
                while (rs.next()) {
                    var sn = rs.getString(1);
                    var date = new java.util.Date();
                    var superseded = CRLReason.superseded;
                    crlBuilder.addCRLEntry(new BigInteger(sn), date, superseded);
                }
            }
        } catch (SQLException sqlE) {
            Cli.error("Problem selecting serial number from certificate where revoked = true; " + sqlE);
        }
        var sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA1withRSA");
        var digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
        var signer = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(
                PrivateKeyFactory.createKey(caPriv.getEncoded()));
        //need both certificate and private key
        var holder = crlBuilder.build((ContentSigner) signer);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        var writer = new JcaPEMWriter(new OutputStreamWriter(baos));
        writer.writeObject(holder);
        writer.close();
        byte[] bytes = baos.toByteArray();
        sendFileDownload(exchange, bytes, "crl.pem");
    }

    @HttpPath(path = "/login")
    synchronized public void loginPage(HttpExchange exchange) throws Exception {
        var nonce = extractParams(exchange).get("nonce");
        var nonceRecord = nonces.get(nonce);
        var authURL = createAuthURL(nonceRecord);
        nonces.put(nonce, nonceRecord);
        redirect(exchange, authURL);
    }

    @HttpPath(path = LOGIN_CALLBACK)
    public void loginCallback(HttpExchange exchange) throws Exception {
        HashMap<String, String> params = extractParams(exchange);
        exchange.getRequestBody().close();
        if (params.containsKey("error")) {
            redirect(exchange, String.format("/login/error?error=%s",
                    URLEncoder.encode(params.get("error"), Charset.defaultCharset())));
            return;
        }
        var code = params.get("code");
        LOG.log(INFO, "starting post");
        var con = (HttpsURLConnection) new URL(tokenEndpoint).openConnection();
        con.setDoOutput(true);
        con.setRequestMethod("POST");
        con.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        String request =
                String.format("code=%s&client_id=%s&client_secret=%s&redirect_uri=%s&grant_type=authorization_code",
                        URLEncoder.encode(code, Charset.defaultCharset()),
                        URLEncoder.encode(clientId, Charset.defaultCharset()),
                        URLEncoder.encode(clientSecret, Charset.defaultCharset()),
                        URLEncoder.encode(authRedirectURL, Charset.defaultCharset()));
        try (OutputStream os = con.getOutputStream()) {
            os.write(request.getBytes());
        }
        var baos = new ByteArrayOutputStream();
        try (InputStream is = con.getResponseCode() < HTTP_BAD_REQUEST ? con.getInputStream() : con.getErrorStream()) {
            is.transferTo(baos);
        }
        LOG.log(INFO, "finished post");
        String response = baos.toString();
        var json = new JSONObject(response);
        if (json.has("error")) {
            redirect(exchange, String.format("/login/error?error=%s",
                    URLEncoder.encode(json.getString("error"), Charset.defaultCharset())));
            return;
        }
        // extract the email from the JWT token
        String idToken = json.getString("id_token");
        var tokenParts = idToken.split("\\.");
        var info = new JSONObject(new String(Base64.getUrlDecoder().decode(tokenParts[1])));
        var email = info.getString("email");
        var nonce = info.getString("nonce"); // use this to access csr
        var nr = nonces.get(nonce);
        if (nr == null) {
            redirect(exchange,
                    String.format("/login/error?error=%s", URLEncoder.encode("validation expired",
                            Charset.defaultCharset())));
        } else {
            String csrEmail = decodeCSR(nr.csr);
            if (csrEmail.equals(email)) { // just send email for database access
                // sign and add to database, but make sure all other certificates are revoked
                Date expire = new Date(System.currentTimeMillis());
                expire.setMonth(expire.getMonth() + 4);
                updateCertificateTable(nonce, email, 0, expire, new String(signCSR(nr.csr)));
                redirect(exchange, String.format("/login/success?email=%s", URLEncoder.encode(email,
                        Charset.defaultCharset())));
            } else {
                redirect(exchange, String.format("/login/error?error=%s",
                        URLEncoder.encode("CSR has " + csrEmail + ", but " + "authenticated with " + email,
                                Charset.defaultCharset())));
            }
        }
    }

    @HttpPath(path = "/login/error")
    public void loginError(HttpExchange exchange) throws Exception {
        var error = extractParams(exchange).get("error");
        byte[] response = errorHTML.replace("ERROR", error).getBytes();
        sendOKResponse(exchange, response);
    }

    @HttpPath(path = "/login/success")
    public void loginSuccess(HttpExchange exchange) throws Exception {
        var email = extractParams(exchange).get("email");
        byte[] response = successHTML.replace("EMAIL", email).getBytes();
        sendOKResponse(exchange, response);
    }

    @HttpPath(path = "/login/success/download")
    public void downloadSigned(HttpExchange exchange) throws Exception {
        var email = extractParams(exchange).get("email");
        String getSigned = null;
        //String query = "select signedCertificate from certificates where revoked = False and email = ?;";
        try (Statement stmt = connection.createStatement()) {
            boolean rc = stmt.execute(String.format("select signedCertificate from certificate where revoked = False" +
                    " and email = \"%s\";", email));
            if (rc) {
                ResultSet rs = stmt.getResultSet();
                if (rs.next()) {
                    getSigned = rs.getString("signedCertificate");
                }
                if (rs.next()) {
                    Cli.error("Duplicate signed certificates for " + email + ".");
                }
            }
        } catch (SQLException e) {
            Cli.error("problem getting certificate from email: " + email + " " + e);
        }
        if (getSigned != null) {
            sendFileDownload(exchange, getSigned.getBytes(), "signed.csr");
        } else {
            redirect(exchange, String.format("/login/error?error=%s",
                    URLEncoder.encode("Could not find signed certificate for " + email,
                            Charset.defaultCharset())));
        }
    }

    String getValidateURL(NonceRecord nr) {
        return String.format("%s/login?nonce=%s", httpsURLPrefix, nr.nonce);
    }

    record NonceRecord(String nonce, String state, LocalDateTime expireTime,
                       CompletableFuture<String> future, byte[] csr) {
        void complete(String email) {
            future.complete(email);
        }
    }

    @CommandLine.Command(name = "server", mixinStandardHelpOptions = true,
            description = "implements a simple HTTPS server for validating email addresses associated with discord " +
                    "ids using oath.")
    static class Cli implements Callable<Integer> {

        static {
            // make sure we don't miss any exceptions
            Thread.setDefaultUncaughtExceptionHandler((t, te) -> te.printStackTrace());
            System.setProperty("java.util.logging.SimpleFormatter.format", "%1$tF %1$tT %4$s %5$s%n");
        }

        static void wrapOutput(String str) {
            var line = new Help.Column(screenWidth, 0, Help.Column.Overflow.WRAP);
            var txtTable = Help.TextTable.forColumns(Help.defaultColorScheme(Help.Ansi.AUTO), line);
            txtTable.indentWrappedLines = 0;
            txtTable.addRowValues(str);
            System.out.print(txtTable);
            System.out.flush();
        }

        static void error(String message) {
            wrapOutput(Help.Ansi.AUTO.string("@|red " + message + "|@"));
        }

        static void info(String message) {
            wrapOutput(Help.Ansi.AUTO.string("@|blue " + message + "|@"));
        }

        @Override
        public Integer call() {
            CommandLine.usage(this, System.out);
            return 1;
        }

        @CommandLine.Command(name = "config", mixinStandardHelpOptions = true,
                description = "check the config file and provide guidance if needed.")
        int config(@CommandLine.Parameters(paramLabel = "prop_file",
                description = "property file containing config and creds.")
                           FileReader propFile) {
            var props = new Properties();
            try {
                props.load(propFile);
                if (props.get("clientId") == null || props.get("clientSecret") == null) {
                    error("""
                            you haven't specified the clientId and clientSecret in the config file. you can obtain them at https://console.cloud.google.com/apis/credentials.
                            create the following lines in the config file:
                            clientId=CLIENTID_FROM_GOOGLE
                            clientSecret=CLIENTSECRET_FROM_GOOGLE""");
                } else {
                    info("clientId and clientSecret look OK.");
                }
                String redirectURL = (String) props.get("redirectURL");
                if (redirectURL == null) {
                    error("missing redirectURL in the config. this will be the URL to redirect the " +
                            "browser to after google has authenticated the client.");
                } else if (!redirectURL.startsWith("http") || !redirectURL.endsWith(LOGIN_CALLBACK)) {
                    error(String.format("redirectURL must start with http and end with %s.", LOGIN_CALLBACK));
                } else {
                    info("redirectURL is set.");
                }
                if (props.get("authDomain") == null) {
                    error("missing authDomain in the config. this should specify a domain name of the id, like sjsu" +
                            ".edu .");
                } else {
                    info("authDomain is set.");
                }
                if (props.get("authDBFile") == null) {
                    error("missing the authDBFile string. this is the location of a sqlite DB.");
                } else {
                    info("authDBFIle is set.");
                }
            } catch (IOException e) {
                System.out.printf("couldn't read config file: %s\n", e.getMessage());
                return 2;
            }
            return 0;
        }

        @CommandLine.Command(name = "serve", mixinStandardHelpOptions = true,
                description = "start https verify endpoint.")
        int serve(@CommandLine.Parameters(paramLabel = "prop_file",
                description = "property file containing config and creds.")
                          FileReader propFile,
                  @CommandLine.Option(names = "--port", defaultValue = "443",
                          description = "TCP port to listen for web connections.",
                          showDefaultValue = Help.Visibility.ALWAYS)
                          int port,
                  @CommandLine.Option(names = "--noTLS",
                          description = "turn off TLS for web connections.",
                          showDefaultValue = Help.Visibility.ALWAYS)
                          boolean noTLS
        ) {
            try {
                var props = new Properties();
                props.load(propFile);

                var authServer = new AuthServer(props);

                var simpleHttpsServer = new SimpleHttpsServer(port, !noTLS);
                var added = simpleHttpsServer.addToHttpsServer(authServer);
                for (var add : added) {
                    LOG.log(INFO, "added {0}", add);
                }

                simpleHttpsServer.start();
                while (true) {
                    Thread.sleep(1000000);
                }
            } catch (IOException | NoSuchAlgorithmException | InterruptedException e) {
                e.printStackTrace();
            }
            return 0;
        }
    }
}
