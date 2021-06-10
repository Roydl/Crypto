namespace Roydl.Crypto.Checksum
{
    using System.Numerics;
    using System.Security.Cryptography;

    /// <summary>Provides functionality to compute SHA-384 hashes.</summary>
    public sealed class Sha384 : ChecksumAlgorithmBuiltIn<Sha384, BigInteger>
    {
        /// <summary>Initializes a new instance of the <see cref="Sha384"/> class.</summary>
        /// <param name="secretKey">The secret key for <see cref="HMAC"/> hashing.</param>
        public Sha384(byte[] secretKey = null) : base(HashAlgorithmName.SHA384, secretKey) { }

        /// <returns>A newly created <see cref="Sha384"/> instance.</returns>
        /// <inheritdoc cref="Sha384(byte[])"/>
        public static Sha384 Create(byte[] secretKey = null) => new(secretKey);
    }
}
