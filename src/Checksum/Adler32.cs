namespace Roydl.Crypto.Checksum
{
    using System;
    using System.IO;

    /// <summary>
    ///     Provides functionality to compute Adler-32 hashes.
    /// </summary>
    public sealed class Adler32 : ChecksumAlgorithm, IEquatable<Adler32>
    {
        private const uint AMod = 0xfff1;
        private const uint Mask = 0xffffffffu;

        /// <summary>
        ///     Gets the required hash length.
        /// </summary>
        public override int HashSize => 8;

        /// <summary>
        ///     Initializes a new instance of the <see cref="Adler32"/> class.
        /// </summary>
        public Adler32() { }

        /// <summary>
        ///     Initializes a new instance of the <see cref="Adler32"/> class and encrypts
        ///     the specified stream.
        /// </summary>
        /// <param name="stream">
        ///     The stream to encrypt.
        /// </param>
        public Adler32(Stream stream) =>
            Encrypt(stream);

        /// <summary>
        ///     Initializes a new instance of the <see cref="Adler32"/> class and encrypts
        ///     the specified sequence of bytes.
        /// </summary>
        /// <param name="bytes">
        ///     The sequence of bytes to encrypt.
        /// </param>
        public Adler32(byte[] bytes) =>
            Encrypt(bytes);

        /// <summary>
        ///     Initializes a new instance of the <see cref="Adler32"/> class and encrypts
        ///     the specified text or file.
        /// </summary>
        /// <param name="textOrFile">
        ///     The text or file to encrypt.
        /// </param>
        /// <param name="strIsFilePath">
        ///     <see langword="true"/> if the specified value is a file path; otherwise,
        ///     <see langword="false"/>.
        /// </param>
        public Adler32(string textOrFile, bool strIsFilePath)
        {
            if (strIsFilePath)
            {
                EncryptFile(textOrFile);
                return;
            }
            Encrypt(textOrFile);
        }

        /// <summary>
        ///     Initializes a new instance of the <see cref="Adler32"/> class and encrypts
        ///     the specified text.
        /// </summary>
        /// <param name="str">
        ///     The text to encrypt.
        /// </param>
        public Adler32(string str) =>
            Encrypt(str);

        /// <summary>
        ///     Encrypts the specified stream.
        /// </summary>
        /// <param name="stream">
        ///     The stream to encrypt.
        /// </param>
        /// <exception cref="ArgumentNullException">
        ///     stream is null.
        /// </exception>
        public override void Encrypt(Stream stream)
        {
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));
            var uia = new[]
            {
                1u,
                0u
            };
            int i;
            while ((i = stream.ReadByte()) != -1)
            {
                uia[0] = (uia[0] + (uint)i) % AMod;
                uia[1] = (uia[1] + uia[0]) % AMod;
            }
            HashNumber = ((uia[1] << 16) | uia[0]) & Mask;
            RawHash = CryptoUtils.GetBytesInverted(HashNumber, RawHashSize);
        }

        /// <summary>
        ///     Determines whether this instance have same values as the specified
        ///     <see cref="Adler32"/> instance.
        /// </summary>
        /// <param name="other">
        ///     The <see cref="Adler32"/> instance to compare.
        /// </param>
        public bool Equals(Adler32 other) =>
            base.Equals(other);

        /// <summary>
        ///     Determines whether this instance have same values as the specified
        ///     <see cref="object"/>.
        /// </summary>
        /// <param name="other">
        ///     The  <see cref="object"/> to compare.
        /// </param>
        public override bool Equals(object other) =>
            other is Adler32 item && Equals(item);

        /// <summary>
        ///     Returns the hash code for this instance.
        /// </summary>
        public override int GetHashCode() =>
            GetType().GetHashCode();

        /// <summary>
        ///     Determines whether two specified <see cref="Adler32"/> instances have same
        ///     values.
        /// </summary>
        /// <param name="left">
        ///     The first <see cref="Adler32"/> instance to compare.
        /// </param>
        /// <param name="right">
        ///     The second <see cref="Adler32"/> instance to compare.
        /// </param>
        public static bool operator ==(Adler32 left, Adler32 right) =>
            left?.Equals(right) ?? right is null;

        /// <summary>
        ///     Determines whether two specified <see cref="Adler32"/> instances have
        ///     different values.
        /// </summary>
        /// <param name="left">
        ///     The first <see cref="Adler32"/> instance to compare.
        /// </param>
        /// <param name="right">
        ///     The second <see cref="Adler32"/> instance to compare.
        /// </param>
        public static bool operator !=(Adler32 left, Adler32 right) =>
            !(left == right);
    }
}
