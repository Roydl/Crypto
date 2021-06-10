namespace Roydl.Crypto.Checksum
{
    using System.Numerics;
    using System.Security.Cryptography;

    /// <summary>Provides functionality to compute SHA-1 hashes.</summary>
    public sealed class Sha1 : ChecksumAlgorithmBuiltIn<Sha1, BigInteger>
    {
        /// <summary>Initializes a new instance of the <see cref="Sha1"/> class.</summary>
        /// <param name="secretKey">The secret key for <see cref="HMAC"/> hashing.</param>
        public Sha1(byte[] secretKey = null) : base(HashAlgorithmName.SHA1, secretKey) { }

        /// <returns>A newly created <see cref="Sha1"/> instance.</returns>
        /// <inheritdoc cref="Sha1(byte[])"/>
        public static Sha1 Create(byte[] secretKey = null) => new(secretKey);
    }
}
