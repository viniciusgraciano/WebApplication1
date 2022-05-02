/* 
 * Password Hashing With PBKDF2 (http://crackstation.net/hashing-security.htm).
 * Copyright (c) 2013, Taylor Hornby
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, 
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation 
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE 
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
 * POSSIBILITY OF SUCH DAMAGE.
 */

using System;
using System.Text;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace Criptografia.Crypto
{
    /// <summary>
    /// Salted password hashing with Pbkdf2-SHA1.
    /// Author: havoc AT defuse.ca
    /// www: http://crackstation.net/hashing-security.htm
    /// Compatibility: .NET 3.0 and later.
    /// </summary>
    public static class PasswordHash
    {
        // The following constants may be changed without breaking existing hashes.
        public const int SaltByteSize = 16;
        public const int HashByteSize = 32;
        public const int Pbkdf2Iterations = 64000;

        public const int IterationIndex = 0;
        public const int SaltIndex = 1;
        public const int Pbkdf2Index = 2;

        /// <summary>
        /// Creates a salted Pbkdf2 hash of the password and returns a concatanation of the 
        /// iterations, salt and hash that can be stored in, for example, a database field.
        /// </summary>
        /// <param name="password">The password to hash.</param>
        /// <returns>Concatenation of the password hash, iterations and salt</returns>
        public static string CreateHash(string password)
        {
            int iterations;
            string salt;
            var hash = CreateHash(password, out iterations, out salt);
            return iterations + ":" + salt + ":" + hash;
        }

        /// <summary>
        /// Creates a salted Pbkdf2 hash of the password, with the given iteration count.
        /// Generates a random salt.
        /// </summary>
        /// <param name="password"></param>
        /// <param name="iterations"></param>
        /// <returns>Concatenation of the password hash, iterations and salt</returns>
        public static string CreateHash(string password, int iterations)
        {
            var saltBytes = new byte[SaltByteSize];
            RandomUtil.SecureRandomBc.NextBytes(saltBytes);
            var saltString = Convert.ToBase64String(saltBytes);

            var hash = CreateHash(password, iterations, saltString);
            return iterations + ":" + saltString + ":" + hash;
        }

        /// <summary>
        /// Creates a salted Pbkdf2 hash of the password, with the given iteration count.
        /// Generates a random salt.
        /// </summary>
        /// <param name="password"></param>
        /// <param name="iterations"></param>
        /// <param name="salt"></param>
        /// <returns>Base64 encoded hash</returns>
        public static string CreateHash(string password, int iterations, out string salt)
        {
            var saltBytes = new byte[SaltByteSize];
            RandomUtil.SecureRandomBc.NextBytes(saltBytes);
            salt = Convert.ToBase64String(saltBytes);

            var hash = CreateHash(password, iterations, salt);
            return hash;
        }

        /// <summary>
        /// Creates a salted Pbkdf2 hash of the password.
        /// </summary>
        /// <param name="password">The password to hash.</param>
        /// <param name="iterations">The number of iterations used for PBKDF.</param>
        /// <param name="salt">The random salt used for the hash.</param>
        /// <returns>The hash of the password.</returns>
        public static string CreateHash(string password, out int iterations, out string salt)
        {
            // Generate a random salt
            var saltBytes = new byte[SaltByteSize];
            RandomUtil.SecureRandomBc.NextBytes(saltBytes);

            // Hash the password and encode the parameters
            var hash = Pbkdf2(password, saltBytes, Pbkdf2Iterations, HashByteSize);

            iterations = Pbkdf2Iterations;
            salt = Convert.ToBase64String(saltBytes);
            return Convert.ToBase64String(hash);
        }

        /// <summary>
        /// Creates a salted Pbkdf2 hash of the password, with the given iteration count and salt.
        /// </summary>
        /// <param name="password"></param>
        /// <param name="iterations"></param>
        /// <param name="salt"></param>
        /// <returns>Base64 encoded hash.</returns>
        public static string CreateHash(string password, int iterations, string salt)
        {
            var saltBytes = Convert.FromBase64String(salt);
            var hash = Pbkdf2(password, saltBytes, iterations, HashByteSize);
            return Convert.ToBase64String(hash);
        }
        
        /// <summary>
        /// Validates a password given a hash of the correct one.
        /// </summary>
        /// <param name="password">The password to check.</param>
        /// <param name="correctHash">A hash of the correct password.</param>
        /// <returns>True if the password is correct. False otherwise.</returns>
        public static bool ValidatePassword(string password, string correctHash)
        {
            // Extract the parameters from the hash
            char[] delimiter = { ':' };
            string[] split = correctHash.Split(delimiter);
            int iterations = Int32.Parse(split[IterationIndex]);
            byte[] salt = Convert.FromBase64String(split[SaltIndex]);
            byte[] hash = Convert.FromBase64String(split[Pbkdf2Index]);

            byte[] testHash = Pbkdf2(password, salt, iterations, hash.Length);
            return SlowEquals(hash, testHash);
        }

        /// <summary>
        /// Compares two byte arrays in length-constant time. This comparison
        /// method is used so that password hashes cannot be extracted from
        /// on-line systems using a timing attack and then attacked off-line.
        /// </summary>
        /// <param name="a">The first byte array.</param>
        /// <param name="b">The second byte array.</param>
        /// <returns>True if both byte arrays are equal. False otherwise.</returns>
        private static bool SlowEquals(byte[] a, byte[] b)
        {
            uint diff = (uint)a.Length ^ (uint)b.Length;
            for (int i = 0; i < a.Length && i < b.Length; i++)
                diff |= (uint)(a[i] ^ b[i]);
            return diff == 0;
        }

        /// <summary>
        /// Computes the Pbkdf2-SHA512 hash of a password.
        /// </summary>
        /// <param name="password">The password to hash.</param>
        /// <param name="salt">The salt.</param>
        /// <param name="iterations">The Pbkdf2 iteration count.</param>
        /// <param name="outputBytes">The length of the hash to generate, in bytes.</param>
        /// <returns>A hash of the password.</returns>
        private static byte[] Pbkdf2(string password, byte[] salt, int iterations, int outputBytes)
        {
            var digest = new Sha512Digest();
            var gen = new Pkcs5S2ParametersGenerator(digest);

            gen.Init(Encoding.UTF8.GetBytes(password), salt, iterations);

            // * 8 because the keySize is expected in bits. Just wants to be different. Must be a hipster KDF.
            var derivedKey = ((KeyParameter) gen.GenerateDerivedMacParameters(outputBytes * 8)).GetKey();

            return derivedKey;
        }
    }
}