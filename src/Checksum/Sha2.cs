namespace Roydl.Crypto.Checksum
{
    using System.Numerics;
    using System.Security.Cryptography;

    /// <summary>Provides functionality to compute SHA-256 hashes.</summary>
    public sealed class Sha2 : ChecksumAlgorithmBuiltIn<Sha2, BigInteger>
    {
        /// <summary>Initializes a new instance of the <see cref="Sha2"/> class.</summary>
        /// <param name="secretKey">The secret key for <see cref="HMAC"/> hashing.</param>
        public Sha2(byte[] secretKey = null) : base(HashAlgorithmName.SHA256, secretKey) { }

        /// <returns>A newly created <see cref="Sha2"/> instance.</returns>
        /// <inheritdoc cref="Sha2(byte[])"/>
        public static Sha2 Create(byte[] secretKey = null) => new(secretKey);
    }
}
