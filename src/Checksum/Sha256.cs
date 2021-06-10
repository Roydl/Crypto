namespace Roydl.Crypto.Checksum
{
    using System.Numerics;
    using System.Security.Cryptography;

    /// <summary>Provides functionality to compute SHA-256 hashes.</summary>
    public sealed class Sha256 : ChecksumAlgorithmBuiltIn<Sha256, BigInteger>
    {
        /// <summary>Initializes a new instance of the <see cref="Sha256"/> class.</summary>
        /// <param name="secretKey">The secret key for <see cref="HMAC"/> hashing.</param>
        public Sha256(byte[] secretKey = null) : base(HashAlgorithmName.SHA256, secretKey) { }

        /// <returns>A newly created <see cref="Sha256"/> instance.</returns>
        /// <inheritdoc cref="Sha256(byte[])"/>
        public static Sha256 Create(byte[] secretKey = null) => new(secretKey);
    }
}
