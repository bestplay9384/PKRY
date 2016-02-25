package pl.pw.edu.proxysigner;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

/**
 * Klasa uruchamiająca aplikację
 * proxySigner - służy do generowania podpisu cyfrowego zadanego pliku
 */
public final class Main {

    /**
     * Zawartość bajtowa pliku wejściowego, który podpisujemy
     */
    private byte[] fileData;

    /**
     * Zawartość tekstowa klucza proxy
     */
    private String proxyKey;
    
    /**
     * Zawartość tekstowa klucza publicznego
     */
    private String publicKey;
    
    /**
     * Klucz publiczny
     */
    private final BigInteger q, p, g;

    /**
     * Parametry klucza proxy
     */
    private final BigInteger s, r;
    
    /**
     * Parametry poboczne niezbędne do wygenerowania sygnatury
     */
    private final BigInteger l, rp, sp, e;
    private static final BigInteger TWO = BigInteger.ONE.add(BigInteger.ONE);

    public Main(boolean debug, String proxyKey_, String publicKey_, String fileToSign_) {

        try {
            fileData = getFile(fileToSign_);
        } catch (IOException ex) {
            System.out.println("File to sign is wrong! Try again!");
            syntaxError();
        }

        try {
            proxyKey = new String(getFile(proxyKey_), StandardCharsets.UTF_8);
        } catch (IOException ex) {
            System.out.println("Proxy key file is wrong! Try again!");
            syntaxError();
        }

        String tmp[] = proxyKey.split("#");
        r = new BigInteger(tmp[0], 16);
        s = new BigInteger(tmp[1], 16);

        try {
            publicKey = new String(getFile(publicKey_), StandardCharsets.UTF_8);
        } catch (IOException ex) {
            System.out.println("Public key file is wrong! Try again!");
            syntaxError();
        }

        String tmp2[] = publicKey.split("#");
        p = new BigInteger(tmp2[0], 16);
        g = new BigInteger(tmp2[1], 16);
        q = new BigInteger(tmp2[2], 16);
        l = genL(q);
        rp = genRP(g, l, p);
        e = genE(fileData, rp);
        sp = genSP(s, e, l, q);
        
        if(debug) {
            System.out.println("r = " + r);
            System.out.println("s = " + s);
            System.out.println("");
            System.out.println("p = " + p);
            System.out.println("g = " + g);
            System.out.println("q = " + q);
            System.out.println("l = " + l);
            System.out.println("");
            System.out.println("rp = " + rp);
            System.out.println("e = " + e);
            System.out.println("e(hex) = " + e.toString(16));
            System.out.println("");
            System.out.println("sp = " + sp);
            System.out.println("sp(hex) = " + sp.toString(16));
            System.out.println("");
        }
        
        StringBuilder sb = new StringBuilder();
        sb.append(sp.toString(16)).append("#").append(e.toString(16)).append("#").append(r.toString(16));
        try {
            createFile(sb.toString(), "message.sign");
            System.out.println("File signature has beed generated successfully! Name of a file: message.sign");
        } catch (IOException ex) {
            System.out.println("Signature file save failed! Try again!");
            System.exit(1);
        }
    }

    /**
     * Geneacja r_p
     * @param g element Z*p rzędu q (q jak najmniejsza i dodatnia)
     * @param l losowa liczba z przedziału (1, q-1)
     * @param p duża losowa liczba pierwsza
     * @return BigInteger r_p
     */
    public BigInteger genRP(BigInteger g, BigInteger l, BigInteger p) {
        return g.modPow(l, p);
    }

    /**
     * Generacja s_p
     * @param s fragment klucza proxy
     * @param e skrót (SHA-256) dokumentu i konkatenacji z parametrem r_p
     * @param l losowa liczba z przedziału (1, q-1)
     * @param q element z*p rzędu q
     * @return BigInteger s_p
     */
    public BigInteger genSP(BigInteger s, BigInteger e, BigInteger l, BigInteger q) {
        return l.add(s.multiply(e)).mod(q);
    }

    /**
     * Generacja e
     * @param m treść pliku na którym naliczana jest sygnatura
     * @param rp parametr r_p
     * @return skrót (SHA-256) konkatenacji m i rp
     */
    public BigInteger genE(byte[] m, BigInteger rp) {
        byte[] rpByte = rp.toByteArray();
        byte[] c = new byte[m.length + rpByte.length];
        System.arraycopy(m, 0, c, 0, m.length);
        System.arraycopy(rpByte, 0, c, m.length, rpByte.length);
        MessageDigest mda = null;
        try {
            mda = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException ex) {
            System.out.println("Algorithm SHA-256 was not found!");
            System.exit(1);
        }
        byte[] coded = mda.digest(c);
        return new BigInteger(coded);
    }
    
    /**
     * Metoda konwertująca tablicę bajtów na wartość tekstową (String)
     * @param _bytes
     * @return String
     */
    public String bytesToString(byte[] _bytes) {
        String file_string = "";
        for (int i = 0; i < _bytes.length; i++) { 
            file_string += String.format("%8s", Integer.toBinaryString(_bytes[i] & 0xFF)).replace(' ', '0');
        }
        return file_string;
    }

    /**
     * Generacja L
     * @param n liczba będąca krańcem przedziału losowości
     * @return liczba losowa z przedziału (1, n-1)
     */
    public BigInteger genL(BigInteger n) {
        Random rand = new Random();
        BigInteger result = new BigInteger(n.bitLength(), rand);
        while (result.compareTo(n.subtract(TWO)) == 1 || result.compareTo(TWO) == -1) {
            result = new BigInteger(n.bitLength(), rand);
        }
        return result;
    }

    /**
     * Metoda pobierająca zawartość bajtową pliku wskazanego ścieżką
     * @param filePath ścieżka do pliku
     * @return zawartość bajtowa pliku
     * @throws IOException 
     */
    public byte[] getFile(String filePath) throws IOException {
        Path file = Paths.get(filePath);
        if (file.toFile().exists()) {
            return Files.readAllBytes(file);
        } else {
            return null;
        }
    }

    /**
     * Metoda zapisująca zawartość tekstową do pliku o określonej ścieżce
     * @param data zawartość
     * @param fileName ścieżka pliku
     * @throws IOException 
     */
    public void createFile(String data, String fileName) throws IOException {
        File file = new File(fileName);
        Files.write(file.toPath(), data.getBytes());
    }
    
    /**
     * Metoda zwracająca poprawne użycie aplikacji
     */
    private static void syntaxError() {
        System.out.println("Correct syntax: java -jar proxySigner.jar [-d] proxyKey publicKey fileToSign");
        System.exit(-1);
    }

    public static void main(String[] args) {
        if((args.length == 4 && args[0].equals("-d"))) {   
            Main main = new Main(true, args[1], args[2], args[3]);
        } else if((args.length == 3 && !args[0].equals("-d"))) {
            Main main = new Main(false, args[0], args[1], args[2]);
        } else {
            syntaxError();
        }
    }

}
