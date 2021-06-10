namespace Roydl.Crypto.Checksum
{
    using System.Numerics;
    using System.Security.Cryptography;

    /// <summary>Provides functionality to compute SHA-512 hashes.</summary>
    public sealed class Sha512 : ChecksumAlgorithmBuiltIn<Sha512, BigInteger>
    {
        /// <summary>Initializes a new instance of the <see cref="Sha512"/> class.</summary>
        /// <param name="secretKey">The secret key for <see cref="HMAC"/> hashing.</param>
        public Sha512(byte[] secretKey = null) : base(HashAlgorithmName.SHA512, secretKey) { }

        /// <returns>A newly created <see cref="Sha512"/> instance.</returns>
        /// <inheritdoc cref="Sha512(byte[])"/>
        public static Sha512 Create(byte[] secretKey = null) => new(secretKey);
    }
}
