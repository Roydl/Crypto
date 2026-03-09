namespace Roydl.Crypto.Checksum
{
    using System.Numerics;
    using System.Security.Cryptography;

    /// <summary>Provides functionality to compute SHA-384 hashes.</summary>
    public sealed class Sha2Bit384 : ChecksumAlgorithmBuiltIn<Sha2Bit384, BigInteger>
    {
        /// <summary>Initializes a new instance of the <see cref="Sha2Bit384"/> class.</summary>
        /// <param name="secretKey">The secret key for <see cref="HMAC"/> hashing.</param>
        public Sha2Bit384(byte[] secretKey = null) : base(HashAlgorithmName.SHA384, true, secretKey) { }

        /// <returns>A newly created <see cref="Sha2Bit384"/> instance.</returns>
        /// <inheritdoc cref="Sha2Bit384(byte[])"/>
        public static Sha2Bit384 Create(byte[] secretKey = null) => new(secretKey);
    }
}
