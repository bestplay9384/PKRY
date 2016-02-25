package pl.pw.edu.keygen;

import java.io.File;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import pl.pw.edu.keygen.AKS.AKS;
import java.io.IOException;
import java.nio.file.*;

/**
 * Klasa uruchamiająca aplikację
 * Keygen - służy do generacji kluczy (prywatnego i publicznego) dla właściciela.
 */
public final class Main {
    
    /**
     * Duża liczba pierwsza - fragment klucza publicznego
     */
    private final BigInteger p;

    /**
     * Największy czynnik pierwszy liczby (p - 1) - fragment klucza publicznego
     */
    private BigInteger q;

    /**
     * Element grupy cyklicznej Z*p rzędu q (q jak najmniejsza i dodatnia) - fragment klucza publicznego
     */
    private final BigInteger g;

    /**
     * Liczba losowa z przedziału od 1 do p - klucz prywatny
     */
    private final BigInteger x;

    /**
     * g^x mod p - fragment klucza publicznego
     */
    private final BigInteger y;
    
    static Map<BigInteger, List<BigInteger>> factors = new HashMap<>();
    private static final BigInteger TWO = BigInteger.ONE.add(BigInteger.ONE);

    public Main(boolean debug)  {

        p = genP(20);
        q = genQ(p);
        g = genG(p, q);
        //q = genQbyG(p, g, q);
        x = genX(p);
        y = genY(g, x, p);
        
        if(debug) {
            System.out.println("p = " + p);
            System.out.println("q = " + q);
            System.out.println("g = " + g);
            System.out.println("x = " + x);
            System.out.println("y = " + y + "\n");
        }
        
        StringBuilder publicKey = new StringBuilder();
        publicKey.append(p.toString(16)).append("#").append(g.toString(16)).append("#").append(q.toString(16)).append("#").append(y.toString(16));
        try {
            createFile(publicKey.toString(), "public.key");
            System.out.println("Public key file has been generated successfully! Name of a file: public.key");
        } catch (IOException ex) {
            System.out.println("Public key has NOT been saved to file! Try again!");
        }
        
        try {
            createFile(x.toString(16), "private.key");
            System.out.println("Private key file has been generated successfully! Name of a file: private.key");
        } catch (IOException ex) {
            System.out.println("Private key has NOT been saved to file! Try again!");
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
     * Generacja Y (część klucza publicznego)
     * @param g element Z*p rzędu q (q jak najmniejsza i dodatnia)
     * @param x fragment klucza prywatnego
     * @param p duża liczba pierwsza
     * @return BigInteger y
     */
    public BigInteger genY(BigInteger g, BigInteger x, BigInteger p) {
        return g.modPow(x, p);
    }
    
    /**
     * Generacja X (klucz prywatny)
     * @param n liczpa pierwsza
     * @return losowa liczba z przedziału (1,n)
     */
    public BigInteger genX(BigInteger n) {
        Random rand = new Random();
        BigInteger result = new BigInteger(n.bitLength(), rand);
        while (result.compareTo(n.subtract(BigInteger.ONE)) == 1 || result.compareTo(TWO) == -1) {
                result = new BigInteger(n.bitLength(), rand);
        }
        return result;
    }

    /**
     * Generacja G (fragment klucza publicznego)
     * @param p duża liczba pierwsza
     * @param q największy czynnik pierwszy (p-1)
     * @return element Z*p rzędu q
     */
    public BigInteger genG(BigInteger p, BigInteger q) {
        BigInteger num = BigInteger.ONE;
        boolean tmp = false;
        BigInteger pmin1 = p.subtract(BigInteger.ONE);
        while (!tmp || num.equals(pmin1)) {
            num = num.add(BigInteger.ONE);
            BigInteger math = num.modPow(q, p);
            if (math.equals(BigInteger.ONE)) {
                if(genAlowerQ(p, num, q).equals(q)) {
                    tmp = true;
                }
            }
        }
        return num;
    }
    
    /**
     * Weryfikacja generacji parametru q względem znalezionego g (czy najmniejszy możliwy)
     * @param p duża liczba pierwsza
     * @param g element Z*p rzędu q (q jak najmniejsza i dodatnia)
     * @param q największy czynnik pierwszy (p-1)
     * @return BigInteger q
     */
    public BigInteger genAlowerQ(BigInteger p, BigInteger g, BigInteger q) {
        BigInteger a = BigInteger.ONE;
        while(a.compareTo(q) == -1) {
            if(g.modPow(a, p).equals(BigInteger.ONE)) {
                return a; 
            }
            a = a.add(BigInteger.ONE);
        }
        return q;
    }

    /**
     * Generacja Q (część klucza publicznego)
     * @param p duża liczba pierwsza
     * @return największy czynnik pierwszy liczby (p-1)
     */
    public BigInteger genQ(BigInteger p) {
        List<BigInteger> primeFactors = factors(p.subtract(new BigInteger("1")), false);
        return primeFactors.get(primeFactors.size() - 1); // wybieramy ostatnią  - najwiękzy czynnik (MOŻNA ZMIENIĆ!)
    }

    /**
     * Generacja P (część klucza publicznego)
     * @param length ilość bitów jaką ma mieć generowana liczba
     * @return liczba pierwsza o zadanej wielkości bitowej
     */
    public BigInteger genP(int length) {
        BigInteger rand = null;
        boolean isPrime = false;

        while (!isPrime) {
            rand = new BigInteger(length, 100, new Random());
            AKS primeTest = new AKS(rand);
            isPrime = primeTest.isPrime();
        }
        return rand;
    }

    /**
     * Rozkład liczby na czynniki pierwsze
     * @param n liczba rozkładana
     * @param duplicates czy mają być zwracane duplikaty
     * @return listę BigInteger'ów będących liczbami pierwszymi z rozkładu liczby n
     */
    public static List<BigInteger> factors(BigInteger n, boolean duplicates) {
        List<BigInteger> f = factors.get(n);
        if (f == null) {
            f = new ArrayList<>();
            BigInteger last = BigInteger.ZERO;
            for (BigInteger i = TWO; i.compareTo(n.divide(i)) <= 0; i = i.add(BigInteger.ONE)) {
                while (n.mod(i).equals(BigInteger.ZERO)) {
                    if (duplicates || !i.equals(last)) {
                        f.add(i);
                        last = i;
                    }
                    n = n.divide(i);
                }
            }
            if (n.compareTo(BigInteger.ONE) > 0) {
                if (duplicates || n != last) {
                    f.add(n);
                }
            }
            factors.put(n, f);
        }
        return f;
    }

    /**
     *
     * @param args
     */
    public static void main(String[] args) {
        boolean statement = (args.length != 0 && args[0].length() != 0 && args[0].equals("-d"));
        System.out.println("Optional parameter [-d] was " + ((statement) ? "" : "not ") + "used.");
        Main main = new Main(statement);
    }
}
