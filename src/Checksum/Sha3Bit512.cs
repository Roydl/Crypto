namespace Roydl.Crypto.Checksum
{
    using System.Numerics;
    using System.Security.Cryptography;

    /// <summary>Provides functionality to compute SHA3-512 hashes.</summary>
    public sealed class Sha3Bit512 : ChecksumAlgorithmBuiltIn<Sha3Bit512, BigInteger>
    {
        /// <summary>Initializes a new instance of the <see cref="Sha3Bit512"/> class.</summary>
        /// <param name="secretKey">The secret key for <see cref="HMAC"/> hashing.</param>
        public Sha3Bit512(byte[] secretKey = null) : base(HashAlgorithmName.SHA3_512, secretKey) { }

        /// <returns>A newly created <see cref="Sha3Bit512"/> instance.</returns>
        /// <inheritdoc cref="Sha3Bit512(byte[])"/>
        public static Sha3Bit512 Create(byte[] secretKey = null) => new(secretKey);
    }
}
