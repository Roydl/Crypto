namespace Roydl.Crypto.Checksum
{
    using System;
    using System.Diagnostics.CodeAnalysis;
    using System.Globalization;
    using System.IO;
    using AbstractSamples;

    /// <summary>
    ///     Provides functionality to compute Adler-32 hashes.
    /// </summary>
    public sealed class Adler32 : ChecksumSample, IEquatable<Adler32>
    {
        /// <summary>
        ///     Gets the required hash length.
        /// </summary>
        public const int HashLength = 8;

        /// <summary>
        ///     Gets the computed hash code value.
        /// </summary>
        public new uint RawHash { get; private set; }

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
        ///     The sequence of bytes to encrypt
        /// </param>
        public Adler32(byte[] bytes) =>
            Encrypt(bytes);

        /// <summary>
        ///     Initializes a new instance of the <see cref="Adler32"/> class and encrypts
        ///     the specified text or file.
        /// </summary>
        /// <param name="textOrFile">
        ///     The text or file to encrypt
        /// </param>
        /// <param name="strIsFilePath">
        ///     <see langword="true"/> if the specified value is a file path; otherwise,
        ///     <see langword="false"/>
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
        ///     The text to encrypt
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
        [SuppressMessage("ReSharper", "ShiftExpressionResultEqualsZero")]
        public override void Encrypt(Stream stream)
        {
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));
            int i;
            var uia = new[]
            {
                1 & 0xffffu,
                (1 >> 16) & 0xffffu
            };
            while ((i = stream.ReadByte()) != -1)
            {
                uia[0] = (uia[0] + (uint)i) % 65521;
                uia[1] = (uia[1] + uia[0]) % 65521;
            }
            RawHash = (uia[1] << 16) | uia[0];
        }

        /// <summary>
        ///     Determines whether this instance have same values as the specified
        ///     <see cref="Adler32"/> instance.
        /// </summary>
        /// <param name="other">
        ///     The <see cref="Adler32"/> instance to compare.
        /// </param>
        public bool Equals(Adler32 other) =>
            other != null && RawHash == other.RawHash;

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
        ///     Converts the <see cref="RawHash"/> of this instance to its equivalent
        ///     string representation.
        /// </summary>
        public override string ToString() =>
            RawHash.ToString("x2", CultureInfo.CurrentCulture).PadLeft(HashLength, '0');

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
