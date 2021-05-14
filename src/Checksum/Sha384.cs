namespace Roydl.Crypto.Checksum
{
    using System;
    using System.IO;
    using System.Security.Cryptography;

    /// <summary>
    ///     Provides functionality to compute SHA-384 hashes.
    /// </summary>
    public sealed class Sha384 : ChecksumAlgorithm, IEquatable<Sha384>
    {
        /// <summary>
        ///     Gets the required hash length.
        /// </summary>
        public override int HashSize => 96;

        /// <summary>
        ///     Initializes a new instance of the <see cref="Sha384"/> class.
        /// </summary>
        public Sha384() { }

        /// <summary>
        ///     Initializes a new instance of the <see cref="Sha384"/> class and encrypts
        ///     the specified stream.
        /// </summary>
        /// <param name="stream">
        ///     The stream to encrypt.
        /// </param>
        public Sha384(Stream stream) =>
            Encrypt(stream);

        /// <summary>
        ///     Initializes a new instance of the <see cref="Sha384"/> class and encrypts
        ///     the specified sequence of bytes.
        /// </summary>
        /// <param name="bytes">
        ///     The sequence of bytes to encrypt.
        /// </param>
        public Sha384(byte[] bytes) =>
            Encrypt(bytes);

        /// <summary>
        ///     Initializes a new instance of the <see cref="Sha384"/> class and encrypts
        ///     the specified text or file.
        /// </summary>
        /// <param name="textOrFile">
        ///     The text or file to encrypt.
        /// </param>
        /// <param name="strIsFilePath">
        ///     <see langword="true"/> if the specified value is a file path; otherwise,
        ///     <see langword="false"/>.
        /// </param>
        public Sha384(string textOrFile, bool strIsFilePath)
        {
            if (strIsFilePath)
            {
                EncryptFile(textOrFile);
                return;
            }
            Encrypt(textOrFile);
        }

        /// <summary>
        ///     Initializes a new instance of the <see cref="Sha384"/> class and encrypts
        ///     the specified text.
        /// </summary>
        /// <param name="str">
        ///     The text to encrypt.
        /// </param>
        public Sha384(string str) =>
            Encrypt(str);

        /// <summary>
        ///     Encrypts the specified stream.
        /// </summary>
        /// <param name="stream">
        ///     The stream to encrypt.
        /// </param>
        public override void Encrypt(Stream stream) =>
            Encrypt(stream, new SHA384CryptoServiceProvider());

        /// <summary>
        ///     Encrypts the specified string.
        /// </summary>
        /// <param name="text">
        ///     The string to encrypt.
        /// </param>
        public new void Encrypt(string text)
        {
            var algo = default(SHA384);
            try
            {
                algo = SHA384.Create();
                Encrypt(text, algo);
            }
            finally
            {
                algo?.Dispose();
            }
        }

        /// <summary>
        ///     Determines whether this instance have same values as the specified
        ///     <see cref="Sha384"/> instance.
        /// </summary>
        /// <param name="other">
        ///     The <see cref="Sha384"/> instance to compare.
        /// </param>
        public bool Equals(Sha384 other) =>
            base.Equals(other);

        /// <summary>
        ///     Determines whether this instance have same values as the specified
        ///     <see cref="object"/>.
        /// </summary>
        /// <param name="other">
        ///     The  <see cref="object"/> to compare.
        /// </param>
        public override bool Equals(object other) =>
            other is Sha384 item && Equals(item);

        /// <summary>
        ///     Returns the hash code for this instance.
        /// </summary>
        public override int GetHashCode() =>
            GetType().GetHashCode();

        /// <summary>
        ///     Determines whether two specified <see cref="Sha384"/> instances have same
        ///     values.
        /// </summary>
        /// <param name="left">
        ///     The first <see cref="Sha384"/> instance to compare.
        /// </param>
        /// <param name="right">
        ///     The second <see cref="Sha384"/> instance to compare.
        /// </param>
        public static bool operator ==(Sha384 left, Sha384 right) =>
            left?.Equals(right) ?? right is null;

        /// <summary>
        ///     Determines whether two specified <see cref="Sha384"/> instances have
        ///     different values.
        /// </summary>
        /// <param name="left">
        ///     The first <see cref="Sha384"/> instance to compare.
        /// </param>
        /// <param name="right">
        ///     The second <see cref="Sha384"/> instance to compare.
        /// </param>
        public static bool operator !=(Sha384 left, Sha384 right) =>
            !(left == right);
    }
}
