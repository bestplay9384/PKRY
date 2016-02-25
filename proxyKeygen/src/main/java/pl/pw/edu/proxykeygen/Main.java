package pl.pw.edu.proxykeygen;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Random;

/**
 * Klasa uruchamiająca aplikację
 * proxyKeygen - służy do generacji klucza prywatnego Proxy dla zastępcy.
 */
public final class Main {

    /**
     * Wartości pobrane od mocodawcy
     */
    private final BigInteger q, x, p, g, y;

    /**
     * Losowa liczba z przedziału (1, g)
     */
    private final BigInteger k;

    /**
     * r = g^k mod p
     */
    private final BigInteger r;

    /**
     * s = (x + kr) mod q
     */
    private final BigInteger s;

    /**
     * Klucz prywatny mocodawcy
     */
    private String bossPrivateKey = null;
    
    /**
     * Klucz publiczny mocodawcy
     */
    private String bossPublicKey = null;

    private static final BigInteger TWO = BigInteger.ONE.add(BigInteger.ONE);

    public Main(boolean debug, String privateKey_, String publicKey_) {
        
        try {
            bossPrivateKey = getFile(privateKey_);
        } catch (IOException ex) {
            System.out.println("Private key file is wrong! Try again!");
            syntaxError();
        }
        
        try {
            bossPublicKey = getFile(publicKey_);
        } catch (IOException ex) {
            System.out.println("Public key file is wrong! Try again!");
            syntaxError();
        }
        
        x = new BigInteger(bossPrivateKey, 16);

        String tmp[] = bossPublicKey.split("#");
        
        p = new BigInteger(tmp[0], 16);
        g = new BigInteger(tmp[1], 16);
        q = new BigInteger(tmp[2], 16);
        y = new BigInteger(tmp[3], 16);
        k = genK(q);
        r = genR(g, k, p);
        s = genS(x, k, r, q);

        if(debug) {
            System.out.println("p = " + p);
            System.out.println("g = " + g);
            System.out.println("q = " + q);
            System.out.println("y = " + y);
            System.out.println("x = " + x);
            System.out.println("");
            System.out.println("k = " + k);
            System.out.println("r = " + r);
            System.out.println("s = " + s);
            System.out.println("");
        }
        
        BigInteger L = g.modPow(s, p);
        BigInteger R = y.mod(p).multiply(r.modPow(r, p)).mod(p);

        if(!L.equals(R)) {
            System.out.println("Generated proxy Key verification failed! Try again!");
            syntaxError();
        } else {
            StringBuilder sb = new StringBuilder();
            sb.append(r.toString(16)).append("#").append(s.toString(16));
            try {
                createFile(sb.toString(), "proxy.key");
                System.out.println("Proxy key has been generated successfully! Name of a file: proxy.key");
            } catch (IOException ex) {
                System.out.println("Proxy key has NOT been saved to file! Try again!");
                System.exit(1);
            } 
        }
    }
    
    /**
     * Metoda pobierająca zawartość bajtową pliku wskazanego ścieżką
     * @param filePath ścieżka do pliku
     * @return zawartość bajtowa pliku
     * @throws IOException 
     */
    public String getFile(String filePath) throws IOException {
        Path file = Paths.get(filePath);
        if (file.toFile().exists()) {
            byte[] encoded = Files.readAllBytes(file);
            return new String(encoded, StandardCharsets.UTF_8);
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
     * Generacja r
     * @param g element Z*p rzędu q (q jak najmniejsza i dodatnia)
     * @param k tajna liczba losowa z przedziału (1,q)
     * @param p duża losowa liczba pierwsza
     * @return BigInteger r
     */
    public BigInteger genR(BigInteger g, BigInteger k, BigInteger p) {
        return g.modPow(k, p);
    }

    /**
     * Generacja s
     * @param x klucz prywatny mocodawcy
     * @param k tajna liczba losowa z przedziału (1,q)
     * @param r g^k modp
     * @param q czynnik pierwszy (p-1)
     * @return BigInteger s
     */
    public BigInteger genS(BigInteger x, BigInteger k, BigInteger r, BigInteger q) {
        return x.add(k.multiply(r)).mod(q);
    }

    /**
     * Generacja k
     * @param n liczba domykająca przedział
     * @return liczba losowa z przedziału (1,n)
     */
    public BigInteger genK(BigInteger n) {
        Random rand = new Random();
        BigInteger result = new BigInteger(n.bitLength(), rand);
        while (result.compareTo(n.subtract(BigInteger.ONE)) == 1 || result.compareTo(TWO) == -1) {
                result = new BigInteger(n.bitLength(), rand);
        }
        return result;
    }
    
    /**
     * Metoda zwracająca poprawne użycie aplikacji
     */
    private static void syntaxError() {
        System.out.println("Correct syntax: java -jar proxyKeygen.jar [-d] privateKey publicKey");
        System.exit(-1);
    }

    public static void main(String[] args) {
        if((args.length == 3 && args[0].equals("-d"))) {   
            Main main = new Main(true, args[1], args[2]);
        } else if((args.length == 2 && !args[0].equals("-d"))) {
            Main main = new Main(false, args[0], args[1]);
        } else {
            syntaxError();
        }
    }

}
