using System;
using System.Text;
using Org.BouncyCastle.Security;

namespace Criptografia.Crypto
{
    public static class RandomUtil
    {
        public static readonly SecureRandom SecureRandomBc = new SecureRandom();

        private const string CharsetUpperCase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        private const string CharsetLowerCase = "abcdefghijklmnopqrstuvwxyz";
        private const string CharsetDigits = "0123456789";
        private const string CharsetSpecial = "~!@#$%^&*()_+-=\\[]{};:,./<>?";

        [Flags]
        public enum StringGeneratorOptions
        {
            UpperCase = 1,
            LowerCase = 2,
            Digits = 4,
            Special = 8
        }
        
        /// <summary>
        /// Generates a random string with uppercase, lowercase and digits.
        /// </summary>
        /// <param name="length"></param>
        /// <returns></returns>
        public static string GenerateRandomString(int length)
        {
            var options = 
                StringGeneratorOptions.UpperCase | 
                StringGeneratorOptions.LowerCase |
                StringGeneratorOptions.Digits;

            return GenerateRandomString(length, options);
        }

        /// <summary>
        /// Generates a random string.
        /// </summary>
        /// <param name="length"></param>
        /// <param name="generatorOptions"></param>
        /// <returns></returns>
        public static string GenerateRandomString(int length, StringGeneratorOptions generatorOptions)
        {
            if (Convert.ToInt32(generatorOptions) == 0)
                throw new Exception("At least one generator option must be specified");

            var charString = "";
            if (generatorOptions.HasFlag(StringGeneratorOptions.UpperCase))
                charString += CharsetUpperCase;
            if (generatorOptions.HasFlag(StringGeneratorOptions.LowerCase))
                charString += CharsetLowerCase;
            if (generatorOptions.HasFlag(StringGeneratorOptions.Digits))
                charString += CharsetDigits;
            if (generatorOptions.HasFlag(StringGeneratorOptions.Special))
                charString += CharsetSpecial;

            var chars = charString.ToCharArray();
            var data = new byte[1];
            var result = new StringBuilder(length);

            SecureRandomBc.NextBytes(data);
            data = new byte[length];
            SecureRandomBc.NextBytes(data);

            foreach (var dataByte in data)
            {
                result.Append(chars[dataByte % chars.Length]);
            }

            return result.ToString();
        }

        /// <summary>
        /// Generates a human-readable random string, missing letter and numbers that may look similar.
        /// </summary>
        /// <param name="length"></param>
        /// <returns></returns>
        public static string GenerateHumanReadableRandomString(int length)
        {
            var chars = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789".ToCharArray();
            var data = new byte[1];
            var result = new StringBuilder(length);

            SecureRandomBc.NextBytes(data);
            data = new byte[length];
            SecureRandomBc.NextBytes(data);

            foreach (var b in data)
            {
                result.Append(chars[b % chars.Length]);
            }

            return result.ToString();
        }


        public static string GenerateRandomByteString(int length)
        {
            var bytes = new byte[length];
            SecureRandomBc.NextBytes(bytes);
            return Convert.ToBase64String(bytes);
        }
    }
}
