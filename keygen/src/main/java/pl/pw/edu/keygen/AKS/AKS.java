package pl.pw.edu.keygen.AKS;

import java.math.BigInteger;

/**
 * Klasa zajmująca się badaniem pierwszości liczb
 * Algorytm AKS bazuje na metodzie Rabina-Millera
 * @author https://code.google.com/p/primality-testing/source/browse/Miller-Rabin/src/AKS.java?r=1ac41d0fa8b661ccbea8d2d82bb1b93e0c334e49
 */
public class AKS {

    /**
     *
     */
    public static boolean verbose = false;

    BigInteger n;
    boolean n_isprime;
    BigInteger factor;
    double timeelapsed;

    /**
     *
     * @param n
     */
    public AKS(BigInteger n) {
        this.n = n;
    }

    /**
     *
     * @return
     */
    public boolean isPrimeTimed() {
        double start = System.currentTimeMillis();
        boolean rtn = isPrime();
        timeelapsed = System.currentTimeMillis() - start;
        return rtn;
    }
    
    /**
     *
     * @return
     */
    public boolean isPrime() {
        BigInteger base = BigInteger.valueOf(2);
        BigInteger aSquared;

        do {
            BigInteger result;

            int power = Math.max((int) (log() / log(base) - 2), 1);
            int comparison;

            do {
                power++;
                result = base.pow(power);
                comparison = n.compareTo(result);
            } while (comparison > 0 && power < Integer.MAX_VALUE);

            if (comparison == 0) {
                if (verbose) {
                    System.out.println(n + " is a perfect power of " + base);
                }
                factor = base;
                n_isprime = false;
                return n_isprime;
            }

            if (verbose) {
                System.out.println(n + " is not a perfect power of " + base);
            }

            base = base.add(BigInteger.ONE);
            aSquared = base.pow(2);
        } while (aSquared.compareTo(this.n) <= 0);
        if (verbose) {
            System.out.println(n + " is not a perfect power of any integer less than its square root");
        }
        double log = this.log();
        double logSquared = log * log;
        BigInteger k = BigInteger.ONE;
        BigInteger r = BigInteger.ONE;
        do {
            r = r.add(BigInteger.ONE);
            if (verbose) {
                System.out.println("trying r = " + r);
            }
            k = multiplicativeOrder(r);
        } while (k.doubleValue() < logSquared);
        if (verbose) {
            System.out.println("r is " + r);
        }
        for (BigInteger i = BigInteger.valueOf(2); i.compareTo(r) <= 0; i = i.add(BigInteger.ONE)) {
            BigInteger gcd = n.gcd(i);
            if (verbose) {
                System.out.println("gcd(" + n + "," + i + ") = " + gcd);
            }
            if (gcd.compareTo(BigInteger.ONE) > 0 && gcd.compareTo(n) < 0) {
                factor = i;
                n_isprime = false;
                return false;
            }
        }
        if (n.compareTo(r) <= 0) {
            n_isprime = true;
            return true;
        }
        int limit = (int) (Math.sqrt(totient(r).doubleValue()) * this.log());
        // X^r - 1
        Poly modPoly = new Poly(BigInteger.ONE, r.intValue()).minus(new Poly(BigInteger.ONE, 0));
        // X^n (mod X^r - 1, n)
        Poly partialOutcome = new Poly(BigInteger.ONE, 1).modPow(n, modPoly, n);
        for (int i = 1; i <= limit; i++) {
            Poly polyI = new Poly(BigInteger.valueOf(i), 0);
            // X^n + i (mod X^r - 1, n)
            Poly outcome = partialOutcome.plus(polyI);
            Poly p = new Poly(BigInteger.ONE, 1).plus(polyI).modPow(n, modPoly, n);
            if (!outcome.equals(p)) {
                if (verbose) {
                    System.out.println("(x+" + i + ")^" + n + " (mod x^" + r + " - 1, " + n + ") = " + outcome);
                }
                if (verbose) {
                    System.out.println("x^" + n + " + " + i + " (mod x^" + r + " - 1, " + n + ") = " + p);
                }
                factor = BigInteger.valueOf(i);
                n_isprime = false;
                return n_isprime;
            }
        }

        n_isprime = true;
        return n_isprime;
    }

    BigInteger totient(BigInteger n) {
        BigInteger result = n;

        for (BigInteger i = BigInteger.valueOf(2); n.compareTo(i.multiply(i)) > 0; i = i.add(BigInteger.ONE)) {
            if (n.mod(i).compareTo(BigInteger.ZERO) == 0) {
                result = result.subtract(result.divide(i));
            }

            while (n.mod(i).compareTo(BigInteger.ZERO) == 0) {
                n = n.divide(i);
            }
        }

        if (n.compareTo(BigInteger.ONE) > 0) {
            result = result.subtract(result.divide(n));
        }

        return result;

    }

    BigInteger multiplicativeOrder(BigInteger r) {
        BigInteger k = BigInteger.ZERO;
        BigInteger result;

        do {
            k = k.add(BigInteger.ONE);
            result = this.n.modPow(k, r);
        } while (result.compareTo(BigInteger.ONE) != 0 && r.compareTo(k) > 0);

        if (r.compareTo(k) <= 0) {
            return BigInteger.ONE.negate();
        } else {
            if (verbose) {
                System.out.println(n + "^" + k + " mod " + r + " = " + result);
            }
            return k;
        }
    }

    // Save log n here
    double logSave = -1;

    double log() {
        if (logSave != -1) {
            return logSave;
        }
        
        BigInteger b;

        int temp = n.bitLength() - 1000;
        if (temp > 0) {
            b = n.shiftRight(temp);
            logSave = (Math.log(b.doubleValue()) + temp) * Math.log(2);
        } else {
            logSave = (Math.log(n.doubleValue())) * Math.log(2);
        }

        return logSave;
    }
    
    double log(BigInteger x) {
        BigInteger b;

        int temp = x.bitLength() - 1000;
        if (temp > 0) {
            b = x.shiftRight(temp);
            return (Math.log(b.doubleValue()) + temp) * Math.log(2);
        } else {
            return (Math.log(x.doubleValue()) * Math.log(2));
        }
    }

    /**
     *
     * @return
     */
    public BigInteger getFactor() {
        return factor;
    }

    /**
     *
     * @return
     */
    public double GetElapsedTime() {
        return timeelapsed;
    }

}
