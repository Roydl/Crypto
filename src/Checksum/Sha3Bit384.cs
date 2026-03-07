namespace Roydl.Crypto.Checksum
{
    using System.Numerics;
    using System.Security.Cryptography;

    /// <summary>Provides functionality to compute SHA3-256 hashes.</summary>
    public sealed class Sha3Bit384 : ChecksumAlgorithmBuiltIn<Sha3Bit384, BigInteger>
    {
        /// <summary>Initializes a new instance of the <see cref="Sha3Bit384"/> class.</summary>
        /// <param name="secretKey">The secret key for <see cref="HMAC"/> hashing.</param>
        public Sha3Bit384(byte[] secretKey = null) : base(HashAlgorithmName.SHA3_384, secretKey) { }

        /// <returns>A newly created <see cref="Sha3Bit384"/> instance.</returns>
        /// <inheritdoc cref="Sha3Bit384(byte[])"/>
        public static Sha3Bit384 Create(byte[] secretKey = null) => new(secretKey);
    }
}
