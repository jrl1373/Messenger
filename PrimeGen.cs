/**
 * Author: Jonathon LoTempio
 */

using System.Diagnostics;
using System.Numerics;
using System.Security.Cryptography;

namespace Messenger;

/**
 * Author Jonathon LoTempio
 * prime Class used to check if a number is prime or not.
 */
public static class ProbablyPrimeClass
{
    public static bool isProbablyPrime(this BigInteger n, int k = 10)
    {
        var d = n - 1;
        int r = 0;
        while (d.IsEven)
        {
            d /= 2;
            r++;
        }

        for (int i = 0; i < k; i++)
        {
            BigInteger a;
            if (n.GetBitLength() > 32)
                do
                {
                    a = new BigInteger(RandomNumberGenerator.GetBytes((int)n.GetBitLength() / 8));
                } while (a > n && a <= 2);
            else
                a = RandomNumberGenerator.GetInt32(2, (int)n - 2);

            var x = BigInteger.ModPow(a, d, n);
            if (x == 1 || x == n - 1) continue;

            bool found = false;

            for (int j = 0; j < r - 1; j++)
            {
                x = BigInteger.ModPow(x, 2, n);
                if (x == n - 1) found = true;
            }

            if (found) continue;

            return false;
        }

        return true;
    }
}

public class PrimeFinder
{
    /// <summary>
    ///     checks simple cases to see if a number is
    ///     not prime.
    /// </summary>
    /// <param name="n"></param>
    /// <returns>Returns false if not prime, true if possibly prime</returns>
    public static bool CheckSimpleCases(BigInteger n)
    {
        var primes = FirstPrimes.primes;
        BigInteger remainder;
        if (n < 4 || n.IsEven) return false;

        foreach (var prime in primes)
        {
            if (n == prime) return true;
            BigInteger.DivRem(n, prime, out remainder);
            if (remainder == 0) return false;
        }

        return true;
    }


    /// <summary>
    ///     Randomly Generates BigIntegers until one of them is prime
    /// </summary>
    /// <param name="size">Size of BigInteger in bits</param>
    /// <returns>a prime integer with "size" bits</returns>
    public BigInteger GetPrime(int size)
    {
        BigInteger result = 0;

        Parallel.For(0, int.MaxValue, (i, state) =>
        {
            byte[] randomnumber = RandomNumberGenerator.GetBytes(size / 8);
            var number = new BigInteger(randomnumber);
            if (CheckSimpleCases(number))
                if (number.isProbablyPrime())
                {
                    result = number;
                    state.Stop();
                }

        });
        return result;
    }


    /// <summary>
    ///     Prints a number of primes along with the length of primes,
    ///     and time taken to execute
    /// </summary>
    /// <param name="count">number of primes to generate and print</param>
    /// <param name="size">size of primes in bits</param>
    public void PrintPrimes(int count, int size)
    {
        Console.WriteLine("BitLength: {0} bits", size);
        var timer = new Stopwatch();
        timer.Start();
        for (int i = 1; i <= count; i++)
        {
            var number = GetPrime(size);
            Console.WriteLine("{0}: {1}\n", i, number);

        }

        Console.WriteLine("Time To Generate: {0}", timer.Elapsed);
    }
}
