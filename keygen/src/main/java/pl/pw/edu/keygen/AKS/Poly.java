package pl.pw.edu.keygen.AKS;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * Klasa reprezentująca wielomian i pozwalająca dokonywać szczególnych operacji
 * np. dzielenia wielomianów z resztą
 * @author https://code.google.com/p/primality-testing/source/browse/Miller-Rabin/src/Poly.java?r=1ac41d0fa8b661ccbea8d2d82bb1b93e0c334e49
 */
public class Poly {

    BigInteger[] monos;
    int degree;

    static void zero(Poly p) {
        for (int i = 0; i < p.monos.length; i++) {
            p.monos[i] = BigInteger.ZERO;
        }

        p.degree = 0;
    }

    void printMonos() {
        for (int i = 0; i <= this.degree; i++) {
            System.out.println(this.monos[i]);
        }
    }

    /**
     *
     */
    public Poly() {
        this.monos = new BigInteger[10];
        zero(this);
    }

    /**
     *
     * @param size
     */
    public Poly(int size) {
        this.monos = new BigInteger[size + 1];
        zero(this);
    }

    /**
     *
     * @param p
     */
    public Poly(Poly p) {
        this.degree = p.degree;
        this.monos = Arrays.copyOf(p.monos, p.monos.length);
    }

    /**
     *
     * @param coeff
     * @param exp
     */
    public Poly(BigInteger coeff, int exp) {
        this(exp);
        if (coeff.compareTo(BigInteger.ZERO) != 0) {
            monos[exp] = coeff;
            degree = exp;
        }
    }

    /**
     *
     * @return
     */
    public int degree() {
        return this.degree;
    }

    /**
     *
     * @param d
     * @return
     */
    public BigInteger coefficient(int d) {
        return this.monos[d];
    }

    public String toString() {
        String s = "";
        for (int i = this.degree; i >= 1; i--) {
            if (monos[i].compareTo(BigInteger.ZERO) != 0) {
                s += (monos[i].compareTo(BigInteger.ONE) == 0 ? "" : monos[i])
                        + "x^" + i + " + ";
            }
        }

        if (monos[0].compareTo(BigInteger.ZERO) != 0) {
            s += monos[0] + " + ";
        }

        return s == "" ? "0" : s.substring(0, s.length() - 3);
    }

    @Override
    public boolean equals(Object p) {
        if (p == null) {
            return false;
        }
        if (p == this) {
            return true;
        }
        if (this.getClass() != p.getClass()) {
            return false;
        }

        if (this.degree != ((Poly) p).degree) {
            return false;
        }

        for (int i = 0; i <= degree; i++) {
            if (this.monos[i].compareTo(((Poly) p).monos[i]) != 0) {
                return false;
            }
        }

        return true;
    }

    /**
     *
     * @param p
     * @return
     */
    public Poly plus(Poly p) {
        int maxDegree = Math.max(this.degree, p.degree);

        Poly sum = new Poly(maxDegree);
        sum.degree = maxDegree;

        for (int i = 0; i <= maxDegree; i++) {
            sum.monos[i] = (i <= this.degree && i <= p.degree) ? p.monos[i].add(this.monos[i])
                    : (i > this.degree) ? p.monos[i] : this.monos[i];
        }

        return sum;
    }

    /**
     *
     * @param p
     * @return
     */
    public Poly minus(Poly p) {
        int maxDegree = Math.max(this.degree, p.degree);

        Poly difference = new Poly(maxDegree);
        difference.degree = maxDegree;

        for (int i = 0; i <= maxDegree; i++) {
            difference.monos[i] = (i <= this.degree && i <= p.degree) ? this.monos[i].subtract(p.monos[i])
                    : (i > this.degree) ? p.monos[i].negate() : this.monos[i];
        }

        updateDegree(difference);
        return difference;
    }

    static void updateDegree(Poly p) {
        p.degree = p.monos.length - 1;

        while (p.monos[p.degree].compareTo(BigInteger.ZERO) == 0 && p.degree > 0) {
            p.degree--;
        }
    }

    /**
     *
     * @param b
     * @return
     */
    public Poly times(BigInteger b) {
        Poly product = new Poly(this);

        for (int i = 0; i <= product.degree; i++) {
            product.monos[i] = product.monos[i].multiply(b);
        }

        return product;
    }

    /**
     *
     * @param p
     * @return
     */
    public Poly times(Poly p) {
        Poly product = new Poly(this.degree + p.degree);
        product.degree = this.degree + p.degree;

        for (int i = 0; i <= this.degree; i++) {
            for (int j = 0; j <= p.degree; j++) {
                product.monos[i + j] = product.monos[i + j].add(this.monos[i].multiply(p.monos[j]));
            }
        }

        return product;
    }

    /**
     *
     * @param m
     * @return
     */
    public Poly mod(BigInteger m) {
        Poly remainder = new Poly(this);

        for (int i = 0; i <= remainder.degree; i++) {
            remainder.monos[i] = monos[i].mod(m);
        }

        updateDegree(remainder);

        return remainder;
    }

    /**
     *
     * @param m
     * @return
     */
    public Poly mod(Poly m) {
        Poly remainder = new Poly(this);

        while (remainder.degree >= m.degree) {
            int diff = remainder.degree - m.degree;
            Poly sub = new Poly(m).times(new Poly(remainder.coefficient(remainder.degree), diff));
            // System.out.println("sub = " + sub);
            remainder = remainder.minus(sub);
        }

        return remainder;
    }

    /**
     *
     * @param exponent
     * @param mPoly
     * @param mBigInteger
     * @return
     */
    public Poly modPow(BigInteger exponent, Poly mPoly, BigInteger mBigInteger) {

        int maxBits = exponent.bitLength();

        Poly answer = new Poly(BigInteger.ONE, 0);
        for (int bit = 0; bit < maxBits; bit++) {
            // explicitly break apart the multiplication and modulus
            answer = answer.times(answer);
            answer = answer.mod(mPoly);
            answer = answer.mod(mBigInteger);

			// Consider bits from left to right
            // if the bit is set multiply by this
            if (exponent.testBit(maxBits - bit - 1)) {
                // explicitly break apart the multiplication and modulus
                answer = answer.times(this);
                answer = answer.mod(mPoly);
                answer = answer.mod(mBigInteger);
            }

        }

        return answer;
    }

}
