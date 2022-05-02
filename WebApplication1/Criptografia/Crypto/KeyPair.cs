namespace Criptografia.Crypto
{
    public class KeyPair
    {
        public static readonly KeyTypes KeyTypeDefault = KeyTypes.Rsa;
        public enum KeyTypes
        {
            Ecc,
            Rsa
        }

        public KeyTypes Type { get; private set; }
        public string PrivatePem { get; private set; }
        public string PublicPem { get; private set; }

        public KeyPair(KeyTypes type, string privatePem, string publicPem)
        {
            Type = type;
            PrivatePem = privatePem;
            PublicPem = publicPem;
        }
    }
}
