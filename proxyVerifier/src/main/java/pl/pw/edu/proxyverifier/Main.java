package pl.pw.edu.proxyverifier;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Klasa uruchamiająca aplikację
 * proxyVerifier - służy do weryfikacji poprawności podpisu dokumentu względem przekazywanego dokumentu.
 */
public final class Main {

    /**
     * Zawartość bajtowa pliku wejściowego, który podpisujemy
     */
    private byte[] fileData;
    
    /**
     * Zawartość tekstowa pliku sygnatury
     */
    private String signatureFile;
    
    /**
     * Zawartość tekstowa klucza publicznego
     */
    private String publicKey;
    
    /**
     * Parametry algorytmu MUO delegowanego podpisu cyfrowego - parametry sygnatury i klucza publicznego
     */
    private final BigInteger p, g, y, sp, r, e, eprim;

    public Main(boolean debug, String publicKey_, String fileSignature_, String signedFile_) {
        
        try {
            fileData = getFile(signedFile_);
        } catch (IOException ex) {
            System.out.println("Signed file is wrong! Try again!");
            syntaxError();
        }

        try {
            signatureFile = new String(getFile(fileSignature_), StandardCharsets.UTF_8);
        } catch (IOException ex) {
            System.out.println("File signature is badly formatted! Try again!");
            syntaxError();
        }

        try {
            publicKey = new String(getFile(publicKey_), StandardCharsets.UTF_8);
        } catch (IOException ex) {
            System.out.println("Public key file is wrong! Try again!");
            syntaxError();
        }
        String tmp[] = publicKey.split("#");
        p = new BigInteger(tmp[0], 16);
        g = new BigInteger(tmp[1], 16);
        y = new BigInteger(tmp[3], 16);

        String tmp2[] = signatureFile.split("#");
        sp = new BigInteger(tmp2[0], 16);
        e = new BigInteger(tmp2[1], 16);
        r = new BigInteger(tmp2[2], 16);

        eprim = genEprim(fileData, genValue(g, sp, y, r, e, p));
        
        if(debug) {
            System.out.println("e   = " + e);
            System.out.println("e'  = " + eprim);
            System.out.println("");
        }
        
        if(!e.equals(eprim)) {
            System.out.println("Signature verification FAILED!");
        } else {
            System.out.println("File signature is correct and successfully verified!");
        }

    }

    /**
     * Metoda generująca wartość pomocniczą do utworzenia wartości e',
     * która niezbędna jest do przeprowadzenia weryfikacji sygnatury
     * @param g element Z*p rzędu q (q jak najmniejsza i dodatnia)
     * @param sp część podpisu pełnomocnika
     * @param y klucz publiczny właściciela
     * @param r część klucza proxy pełnomocnika
     * @param e skrót binarnej zawartości pliku i jego konkatenacji z parametrem rp
     * @param p duża liczba pierwsza
     * @return BigInteger value
     */
    public BigInteger genValue(BigInteger g, BigInteger sp, BigInteger y, BigInteger r, BigInteger e, BigInteger p) {
        return g.modPow(sp, p).multiply(y.modPow(e.negate(), p)).multiply(r.modPow(r.multiply(e.negate()), p)).mod(p);
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
     * Generator parametru e'
     * @param m zawartość binarna pliku podpisywanego
     * @param value pomocnicza wartość, którą dopisujemy przez konkatenacje do m.
     * @return BigInteger e'
     */
    public BigInteger genEprim(byte[] m, BigInteger value) {
        byte[] bytes = value.toByteArray();
        byte[] c = new byte[m.length + bytes.length];
        System.arraycopy(m, 0, c, 0, m.length);
        System.arraycopy(bytes, 0, c, m.length, bytes.length);
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
     * Metoda zwracająca poprawne użycie aplikacji
     */
    private static void syntaxError() {
        System.out.println("Correct syntax: java -jar proxyVerifier.jar [-d] publicKey fileSignature signedFile");
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
