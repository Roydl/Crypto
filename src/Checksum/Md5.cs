namespace Roydl.Crypto.Checksum
{
    using System.Numerics;
    using System.Security.Cryptography;

    /// <summary>Provides functionality to compute MD5 hashes.</summary>
    public sealed class Md5 : ChecksumAlgorithmBuiltIn<Md5, BigInteger>
    {
        /// <summary>Initializes a new instance of the <see cref="Md5"/> class.</summary>
        /// <param name="secretKey">The secret key for <see cref="HMAC"/> hashing.</param>
        public Md5(byte[] secretKey = null) : base(HashAlgorithmName.MD5, secretKey) { }

        /// <returns>A newly created <see cref="Md5"/> instance.</returns>
        /// <inheritdoc cref="Md5(byte[])"/>
        public static Md5 Create(byte[] secretKey = null) => new(secretKey);
    }
}
