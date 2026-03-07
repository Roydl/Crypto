namespace Roydl.Crypto.Checksum
{
    using System.Numerics;
    using System.Security.Cryptography;

    /// <summary>Provides functionality to compute SHA3-256 hashes.</summary>
    public sealed class Sha3 : ChecksumAlgorithmBuiltIn<Sha3, BigInteger>
    {
        /// <summary>Initializes a new instance of the <see cref="Sha3"/> class.</summary>
        /// <param name="secretKey">The secret key for <see cref="HMAC"/> hashing.</param>
        public Sha3(byte[] secretKey = null) : base(HashAlgorithmName.SHA3_256, secretKey) { }

        /// <returns>A newly created <see cref="Sha3"/> instance.</returns>
        /// <inheritdoc cref="Sha3(byte[])"/>
        public static Sha3 Create(byte[] secretKey = null) => new(secretKey);
    }
}
