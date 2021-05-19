namespace Roydl.Crypto.Checksum
{
    using System;
    using System.Globalization;
    using System.IO;
    using System.Security.Cryptography;
    using System.Text;
    using Resources;

    /// <summary>
    ///     Represents the base class from which all implementations of checksum
    ///     encryption algorithms must derive.
    /// </summary>
    public abstract class ChecksumAlgorithm : IChecksumAlgorithm, IEquatable<ChecksumAlgorithm>
    {
        /// <inheritdoc/>
        public int HashBits { get; }

        /// <inheritdoc/>
        public int HashSize { get; }

        /// <inheritdoc/>
        public int RawHashSize { get; }

        /// <inheritdoc/>
        public string Hash => ToString();

        /// <inheritdoc/>
        public ReadOnlyMemory<byte> RawHash { get; protected set; }

        /// <inheritdoc/>
        public ulong HashNumber { get; protected set; }

        /// <summary>
        ///     Initializes a new instance of the
        ///     <see cref="ChecksumAlgorithm{THashAlgo}"/> class.
        /// </summary>
        /// <param name="bits">
        ///     The hash size in bits.
        /// </param>
        /// <exception cref="ArgumentOutOfRangeException">
        ///     bits is less than 8, greater than 512, or odd.
        /// </exception>
        protected ChecksumAlgorithm(int bits)
        {
            if (bits is < 8 or > 512 || bits % 2 != 0)
                throw new ArgumentOutOfRangeException(nameof(bits));
            HashBits = bits;
            HashSize = bits / 4;
            RawHashSize = bits / 8;
        }

        /// <inheritdoc cref="IChecksumAlgorithm.Encrypt(Stream)"/>
        public abstract void Encrypt(Stream stream);

        /// <inheritdoc/>
        public void Encrypt(byte[] bytes)
        {
            if (bytes == null)
                throw new ArgumentNullException(nameof(bytes));
            if (bytes.Length < 1)
                throw new ArgumentException(ExceptionMessages.IsEmpty, nameof(bytes));
            using var ms = new MemoryStream(bytes);
            Encrypt(ms);
        }

        /// <inheritdoc/>
        public void Encrypt(string text)
        {
            if (text == null)
                throw new ArgumentNullException(nameof(text));
            if (text.Length < 1)
                throw new ArgumentException(ExceptionMessages.IsEmpty, nameof(text));
            Encrypt(Encoding.UTF8.GetBytes(text));
        }

        /// <inheritdoc/>
        public void EncryptFile(string path)
        {
            if (path == null)
                throw new ArgumentNullException(nameof(path));
            if (path.Length < 1)
                throw new ArgumentException(ExceptionMessages.IsEmpty, nameof(path));
            if (!File.Exists(path))
                throw new FileNotFoundException(ExceptionMessages.FileNotFound, path);
            using var fs = File.OpenRead(path);
            Encrypt(fs);
        }

        /// <summary>
        ///     Determines whether this instance have same values as the specified
        ///     <see cref="ChecksumAlgorithm"/> instance.
        /// </summary>
        /// <param name="other">
        ///     The <see cref="ChecksumAlgorithm"/> instance to compare.
        /// </param>
        public bool Equals(ChecksumAlgorithm other)
        {
            if (other == null || HashSize != other.HashSize)
                return false;
            if (RawHash.IsEmpty)
                return other.RawHash.IsEmpty;
            return HashNumber == other.HashNumber && RawHash.Span.SequenceEqual(other.RawHash.Span);
        }

        /// <inheritdoc/>
        public override bool Equals(object other) =>
            other is ChecksumAlgorithm item && Equals(item);

        /// <inheritdoc cref="Type.GetHashCode()"/>
        public override int GetHashCode() =>
            GetType().GetHashCode();

        /// <inheritdoc/>
        public string ToString(bool uppercase)
        {
            if (RawHash.IsEmpty)
                return string.Empty;
            var sb = new StringBuilder(HashSize);
            foreach (var b in RawHash.Span)
                sb.Append(b.ToString(uppercase ? "X2" : "x2", CultureInfo.CurrentCulture));
            var s = sb.ToString();
            sb.Clear();
            return s.PadLeft(HashSize, '0');
        }

        /// <inheritdoc cref="IChecksumAlgorithm.ToString()"/>
        public sealed override string ToString() =>
            ToString(false);

        /// <summary>
        ///     Encrypts the specified stream with the specified
        ///     <see cref="HashAlgorithm"/>.
        /// </summary>
        /// <typeparam name="THashAlgorithm">
        ///     The type of the algorithm.
        /// </typeparam>
        /// <param name="stream">
        ///     The stream to encrypt.
        /// </param>
        /// <param name="algorithm">
        ///     The algorithm to encrypt.
        /// </param>
        /// <exception cref="ArgumentNullException">
        ///     algorithm is null.
        /// </exception>
        protected void Encrypt<THashAlgorithm>(Stream stream, THashAlgorithm algorithm) where THashAlgorithm : HashAlgorithm
        {
            if (algorithm == null)
                throw new ArgumentNullException(nameof(algorithm));
            using var csp = algorithm;
            RawHash = csp.ComputeHash(stream);
            HashNumber = BitConverter.ToUInt64(csp.Hash);
        }

        /// <summary>
        ///     Encrypts the specified string with the specified
        ///     <see cref="HashAlgorithm"/>.
        /// </summary>
        /// <typeparam name="THashAlgorithm">
        ///     The type of the algorithm.
        /// </typeparam>
        /// <param name="text">
        ///     The string to encrypt.
        /// </param>
        /// <param name="algorithm">
        ///     The algorithm to encrypt.
        /// </param>
        /// <exception cref="ArgumentNullException">
        ///     text or algorithm is null.
        /// </exception>
        protected void Encrypt<THashAlgorithm>(string text, THashAlgorithm algorithm) where THashAlgorithm : HashAlgorithm
        {
            if (text == null)
                throw new ArgumentNullException(nameof(text));
            if (algorithm == null)
                throw new ArgumentNullException(nameof(algorithm));
            var ba = Encoding.UTF8.GetBytes(text);
            using var csp = algorithm;
            RawHash = csp.ComputeHash(ba);
            HashNumber = BitConverter.ToUInt64(csp.Hash);
        }

        /// <summary>
        ///     Determines whether two specified <see cref="ChecksumAlgorithm"/> instances
        ///     have same values.
        /// </summary>
        /// <param name="left">
        ///     The first <see cref="ChecksumAlgorithm"/> instance to compare.
        /// </param>
        /// <param name="right">
        ///     The second <see cref="ChecksumAlgorithm"/> instance to compare.
        /// </param>
        public static bool operator ==(ChecksumAlgorithm left, ChecksumAlgorithm right) =>
            left?.Equals(right) ?? right is null;

        /// <summary>
        ///     Determines whether two specified <see cref="ChecksumAlgorithm"/> instances
        ///     have different values.
        /// </summary>
        /// <param name="left">
        ///     The first <see cref="ChecksumAlgorithm"/> instance to compare.
        /// </param>
        /// <param name="right">
        ///     The second <see cref="ChecksumAlgorithm"/> instance to compare.
        /// </param>
        public static bool operator !=(ChecksumAlgorithm left, ChecksumAlgorithm right) =>
            !(left == right);
    }

    /// <inheritdoc cref="ChecksumAlgorithm"/>
    /// <typeparam name="THashAlgo">
    ///     The hash algorithm type.
    /// </typeparam>
    public abstract class ChecksumAlgorithm<THashAlgo> : ChecksumAlgorithm, IEquatable<THashAlgo> where THashAlgo : IChecksumAlgorithm
    {
        /// <summary>
        ///     Initializes a new instance of the
        ///     <see cref="ChecksumAlgorithm{THashAlgo}"/> class.
        /// </summary>
        /// <inheritdoc cref="ChecksumAlgorithm(int)"/>
        protected ChecksumAlgorithm(int bits) : base(bits) { }

        /// <summary>
        ///     Determines whether this instance have same values as the specified
        ///     <typeparamref name="THashAlgo"/> instance.
        /// </summary>
        /// <param name="other">
        ///     The <typeparamref name="THashAlgo"/> instance to compare.
        /// </param>
        public bool Equals(THashAlgo other)
        {
            if (other == null || HashSize != other.HashSize)
                return false;
            if (RawHash.IsEmpty)
                return other.RawHash.IsEmpty;
            return HashNumber == other.HashNumber && RawHash.Span.SequenceEqual(other.RawHash.Span);
        }

        /// <inheritdoc/>
        public override bool Equals(object other) =>
            other is THashAlgo item && Equals(item);

        /// <inheritdoc cref="Type.GetHashCode()"/>
        public override int GetHashCode() =>
            GetType().GetHashCode();

        /// <summary>
        ///     Determines whether two specified <typeparamref name="THashAlgo"/> instances
        ///     have same values.
        /// </summary>
        /// <param name="left">
        ///     The first <typeparamref name="THashAlgo"/> instance to compare.
        /// </param>
        /// <param name="right">
        ///     The second <typeparamref name="THashAlgo"/> instance to compare.
        /// </param>
        public static bool operator ==(ChecksumAlgorithm<THashAlgo> left, ChecksumAlgorithm<THashAlgo> right) =>
            left?.Equals(right) ?? right is null;

        /// <summary>
        ///     Determines whether two specified <typeparamref name="THashAlgo"/> instances
        ///     have different values.
        /// </summary>
        /// <param name="left">
        ///     The first <typeparamref name="THashAlgo"/> instance to compare.
        /// </param>
        /// <param name="right">
        ///     The second <typeparamref name="THashAlgo"/> instance to compare.
        /// </param>
        public static bool operator !=(ChecksumAlgorithm<THashAlgo> left, ChecksumAlgorithm<THashAlgo> right) =>
            !(left == right);
    }
}
