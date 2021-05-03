namespace Roydl.Crypto.Checksum
{
    using System;
    using System.IO;
    using System.Linq;
    using System.Security.Cryptography;
    using AbstractSamples;

    /// <summary>
    ///     Provides functionality to compute SHA-512 hashes.
    /// </summary>
    public sealed class Sha512 : ChecksumSample, IEquatable<Sha512>
    {
        /// <summary>
        ///     Gets the required hash length.
        /// </summary>
        public const int HashLength = 128;

        /// <summary>
        ///     Initializes a new instance of the <see cref="Sha512"/> class.
        /// </summary>
        public Sha512() { }

        /// <summary>
        ///     Initializes a new instance of the <see cref="Sha512"/> class and encrypts
        ///     the specified stream.
        /// </summary>
        /// <param name="stream">
        ///     The stream to encrypt.
        /// </param>
        public Sha512(Stream stream) =>
            Encrypt(stream);

        /// <summary>
        ///     Initializes a new instance of the <see cref="Sha512"/> class and encrypts
        ///     the specified sequence of bytes.
        /// </summary>
        /// <param name="bytes">
        ///     The sequence of bytes to encrypt
        /// </param>
        public Sha512(byte[] bytes) =>
            Encrypt(bytes);

        /// <summary>
        ///     Initializes a new instance of the <see cref="Sha512"/> class and encrypts
        ///     the specified text or file.
        /// </summary>
        /// <param name="textOrFile">
        ///     The text or file to encrypt
        /// </param>
        /// <param name="strIsFilePath">
        ///     <see langword="true"/> if the specified value is a file path; otherwise,
        ///     <see langword="false"/>
        /// </param>
        public Sha512(string textOrFile, bool strIsFilePath)
        {
            if (strIsFilePath)
            {
                EncryptFile(textOrFile);
                return;
            }
            Encrypt(textOrFile);
        }

        /// <summary>
        ///     Initializes a new instance of the <see cref="Sha512"/> class and encrypts
        ///     the specified text.
        /// </summary>
        /// <param name="str">
        ///     The text to encrypt
        /// </param>
        public Sha512(string str) =>
            Encrypt(str);

        /// <summary>
        ///     Encrypts the specified stream.
        /// </summary>
        /// <param name="stream">
        ///     The stream to encrypt.
        /// </param>
        public override void Encrypt(Stream stream) =>
            Encrypt(stream, new SHA512CryptoServiceProvider());

        /// <summary>
        ///     Encrypts the specified string.
        /// </summary>
        /// <param name="text">
        ///     The string to encrypt.
        /// </param>
        public new void Encrypt(string text)
        {
            var algo = default(SHA512);
            try
            {
                algo = SHA512.Create();
                Encrypt(text, algo);
            }
            finally
            {
                algo?.Dispose();
            }
        }

        /// <summary>
        ///     Determines whether this instance have same values as the specified
        ///     <see cref="Sha512"/> instance.
        /// </summary>
        /// <param name="other">
        ///     The <see cref="Sha512"/> instance to compare.
        /// </param>
        public bool Equals(Sha512 other)
        {
            if (other == null)
                return false;
            if (RawHash == null)
                return other.RawHash == null;
            return RawHash.SequenceEqual(other.RawHash);
        }

        /// <summary>
        ///     Determines whether this instance have same values as the specified
        ///     <see cref="object"/>.
        /// </summary>
        /// <param name="other">
        ///     The  <see cref="object"/> to compare.
        /// </param>
        public override bool Equals(object other) =>
            other is Sha512 item && Equals(item);

        /// <summary>
        ///     Returns the hash code for this instance.
        /// </summary>
        public override int GetHashCode() =>
            GetType().GetHashCode();

        /// <summary>
        ///     Determines whether two specified <see cref="Sha512"/> instances have same
        ///     values.
        /// </summary>
        /// <param name="left">
        ///     The first <see cref="Sha512"/> instance to compare.
        /// </param>
        /// <param name="right">
        ///     The second <see cref="Sha512"/> instance to compare.
        /// </param>
        public static bool operator ==(Sha512 left, Sha512 right) =>
            left?.Equals(right) ?? right is null;

        /// <summary>
        ///     Determines whether two specified <see cref="Sha512"/> instances have
        ///     different values.
        /// </summary>
        /// <param name="left">
        ///     The first <see cref="Sha512"/> instance to compare.
        /// </param>
        /// <param name="right">
        ///     The second <see cref="Sha512"/> instance to compare.
        /// </param>
        public static bool operator !=(Sha512 left, Sha512 right) =>
            !(left == right);
    }
}
