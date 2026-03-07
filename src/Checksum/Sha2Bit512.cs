namespace Roydl.Crypto.Checksum
{
    using System.Numerics;
    using System.Security.Cryptography;

    /// <summary>Provides functionality to compute SHA-512 hashes.</summary>
    public sealed class Sha2Bit512 : ChecksumAlgorithmBuiltIn<Sha2Bit512, BigInteger>
    {
        /// <summary>Initializes a new instance of the <see cref="Sha2Bit512"/> class.</summary>
        /// <param name="secretKey">The secret key for <see cref="HMAC"/> hashing.</param>
        public Sha2Bit512(byte[] secretKey = null) : base(HashAlgorithmName.SHA512, secretKey) { }

        /// <returns>A newly created <see cref="Sha2Bit512"/> instance.</returns>
        /// <inheritdoc cref="Sha2Bit512(byte[])"/>
        public static Sha2Bit512 Create(byte[] secretKey = null) => new(secretKey);
    }
}
