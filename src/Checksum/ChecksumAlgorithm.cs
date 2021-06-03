namespace Roydl.Crypto.Checksum
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Numerics;
    using System.Security.Cryptography;
    using System.Text;
    using Resources;

    /// <summary>Represents the base class from which all implementations of checksum encryption algorithms must derive.</summary>
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

        /// <summary>Initializes a new instance of the <see cref="ChecksumAlgorithm"/> class.</summary>
        /// <param name="bits">The hash size in bits.</param>
        /// <param name="size">The string size to enforce. This is useful to prevent zero padding for algorithms with odd bits.</param>
        /// <exception cref="ArgumentOutOfRangeException">bits are less than 8.</exception>
        protected ChecksumAlgorithm(int bits, int size = default)
        {
            if (bits < 8)
                throw new ArgumentOutOfRangeException(nameof(bits), bits, null);
            HashBits = bits;
            HashSize = (int)MathF.Ceiling(HashBits / 4f);
            if (HashSize % 2 != 0)
                ++HashSize;
            if (HashSize < 2)
                HashSize = 2;
            RawHashSize = (int)MathF.Ceiling(HashSize / 2f);
            if (size > 0)
                HashSize = size;
        }

        /// <summary>Initializes a new instance of the <see cref="ChecksumAlgorithm"/> class and encrypts the specified sequence of bytes.</summary>
        /// <param name="bits">The hash size in bits.</param>
        /// <param name="bytes">The sequence of bytes to encrypt.</param>
        /// <inheritdoc cref="IChecksumAlgorithm.Encrypt(byte[])"/>
        protected ChecksumAlgorithm(int bits, byte[] bytes) : this(bits) =>
            Encrypt(bytes);

        /// <summary>Initializes a new instance of the <see cref="ChecksumAlgorithm"/> class and encrypts the specified text or file.</summary>
        /// <param name="bits">The hash size in bits.</param>
        /// <param name="textOrFile">The text or file to encrypt.</param>
        /// <param name="strIsFilePath"><see langword="true"/> if the specified value is a file path; otherwise, <see langword="false"/>.</param>
        /// <inheritdoc cref="IChecksumAlgorithm.EncryptFile(string)"/>
        protected ChecksumAlgorithm(int bits, string textOrFile, bool strIsFilePath) : this(bits) =>
            Encrypt(textOrFile, strIsFilePath);

        /// <summary>Initializes a new instance of the <see cref="ChecksumAlgorithm"/> class and encrypts the specified text.</summary>
        /// <param name="bits">The hash size in bits.</param>
        /// <param name="text">The string to encrypt.</param>
        /// <inheritdoc cref="IChecksumAlgorithm.Encrypt(string)"/>
        protected ChecksumAlgorithm(int bits, string text) : this(bits) =>
            Encrypt(text);

        /// <summary>Initializes a new instance of the <see cref="ChecksumAlgorithm"/> class and encrypts the specified file.</summary>
        /// <param name="bits">The hash size in bits.</param>
        /// <param name="fileInfo">The file to encrypt.</param>
        /// <inheritdoc cref="IChecksumAlgorithm.Encrypt(FileInfo)"/>
        protected ChecksumAlgorithm(int bits, FileInfo fileInfo) : this(bits) =>
            Encrypt(fileInfo);

        /// <inheritdoc cref="IChecksumAlgorithm.Encrypt(Stream)"/>
        public abstract void Encrypt(Stream stream);

        /// <inheritdoc/>
        public void Encrypt(byte[] bytes)
        {
            if (bytes == null)
                throw new ArgumentNullException(nameof(bytes));
            if (bytes.Length < 1)
                throw new ArgumentException(ExceptionMessages.ArgumentEmpty, nameof(bytes));
            using var ms = new MemoryStream(bytes);
            Encrypt(ms);
        }

        /// <inheritdoc/>
        public void Encrypt(string textOrFile, bool strIsFilePath)
        {
            if (strIsFilePath)
            {
                EncryptFile(textOrFile);
                return;
            }
            Encrypt(textOrFile);
        }

        /// <inheritdoc/>
        public void Encrypt(string text)
        {
            if (text == null)
                throw new ArgumentNullException(nameof(text));
            if (text.Length < 1)
                throw new ArgumentException(ExceptionMessages.ArgumentEmpty, nameof(text));
            Encrypt(Encoding.UTF8.GetBytes(text));
        }

        /// <inheritdoc/>
        public void Encrypt(FileInfo fileInfo)
        {
            if (fileInfo == null)
                throw new ArgumentNullException(nameof(fileInfo));
            if (!fileInfo.Exists)
                throw new FileNotFoundException(ExceptionMessages.FileNotFound, fileInfo.FullName);
            using var fs = fileInfo.OpenRead();
            Encrypt(fs);
        }

        /// <inheritdoc/>
        public void EncryptFile(string path)
        {
            if (path == null)
                throw new ArgumentNullException(nameof(path));
            if (path.Length < 1)
                throw new ArgumentException(ExceptionMessages.ArgumentEmpty, nameof(path));
            if (!File.Exists(path))
                throw new FileNotFoundException(ExceptionMessages.FileNotFound, path);
            using var fs = File.OpenRead(path);
            Encrypt(fs);
        }

        /// <inheritdoc/>
        public virtual void Reset()
        {
            if (!RawHash.IsEmpty)
                RawHash = default;
        }

        /// <summary>Determines whether this instance have same values as the specified <see cref="ChecksumAlgorithm"/> instance.</summary>
        /// <param name="other">The <see cref="ChecksumAlgorithm"/> instance to compare.</param>
        /// <inheritdoc/>
        public bool Equals(ChecksumAlgorithm other)
        {
            if (other == null || HashSize != other.HashSize)
                return false;
            return RawHash.IsEmpty ? other.RawHash.IsEmpty : RawHash.Span.SequenceEqual(other.RawHash.Span);
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
            var sb = new StringBuilder(RawHashSize * 2);
            foreach (var b in RawHash.Span)
                sb.AppendFormat(uppercase ? "{0:X2}" : "{0:x2}", b);
            while (sb.Length < HashSize)
                sb.Insert(0, '0');
            var str = sb.Length > HashSize ? sb.ToString(sb.Length - HashSize, HashSize) : sb.ToString();
            sb.Clear();
            return str;
        }

        /// <inheritdoc cref="IChecksumAlgorithm.ToString()"/>
        public sealed override string ToString() =>
            ToString(false);

        /// <summary>Encrypts the specified stream with the specified <see cref="HashAlgorithm"/>.</summary>
        /// <typeparam name="THashAlgorithm">The type of the algorithm.</typeparam>
        /// <param name="stream">The stream to encrypt.</param>
        /// <param name="algorithm">The algorithm to encrypt.</param>
        /// <exception cref="ArgumentNullException">stream or algorithm is null.</exception>
        protected void Encrypt<THashAlgorithm>(Stream stream, THashAlgorithm algorithm) where THashAlgorithm : HashAlgorithm
        {
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));
            if (algorithm == null)
                throw new ArgumentNullException(nameof(algorithm));
            using var csp = algorithm;
            RawHash = csp.ComputeHash(stream);
        }

        /// <summary>Encrypts the specified string with the specified <see cref="HashAlgorithm"/>.</summary>
        /// <typeparam name="THashAlgorithm">The type of the algorithm.</typeparam>
        /// <param name="text">The string to encrypt.</param>
        /// <param name="algorithm">The algorithm to encrypt.</param>
        /// <exception cref="ArgumentNullException">text or algorithm is null.</exception>
        protected void Encrypt<THashAlgorithm>(string text, THashAlgorithm algorithm) where THashAlgorithm : HashAlgorithm
        {
            if (text == null)
                throw new ArgumentNullException(nameof(text));
            if (algorithm == null)
                throw new ArgumentNullException(nameof(algorithm));
            var ba = Encoding.UTF8.GetBytes(text);
            using var csp = algorithm;
            RawHash = csp.ComputeHash(ba);
        }

        /// <summary>Determines whether two specified <see cref="ChecksumAlgorithm"/> instances have same values.</summary>
        /// <param name="left">The first <see cref="ChecksumAlgorithm"/> instance to compare.</param>
        /// <param name="right">The second <see cref="ChecksumAlgorithm"/> instance to compare.</param>
        public static bool operator ==(ChecksumAlgorithm left, ChecksumAlgorithm right) =>
            left?.Equals(right) ?? right is null;

        /// <summary>Defines an explicit conversion of <see cref="ChecksumAlgorithm"/> object to <see cref="string"/>.</summary>
        /// <param name="value">The item to convert to <see cref="string"/>.</param>
        /// <returns>The <see cref="string"/> representation of the last computed hash code.</returns>
        public static explicit operator string(ChecksumAlgorithm value) =>
            value.ToString();

        /// <summary>Defines an explicit conversion of <see cref="ChecksumAlgorithm"/> object to <see cref="byte"/> array.</summary>
        /// <param name="value">The item to convert to <see cref="byte"/> array.</param>
        /// <returns>A copy of the last computed hash code.</returns>
        public static explicit operator byte[](ChecksumAlgorithm value) =>
            value.RawHash.Span!.ToArray();

        /// <summary>Determines whether two specified <see cref="ChecksumAlgorithm"/> instances have different values.</summary>
        /// <param name="left">The first <see cref="ChecksumAlgorithm"/> instance to compare.</param>
        /// <param name="right">The second <see cref="ChecksumAlgorithm"/> instance to compare.</param>
        public static bool operator !=(ChecksumAlgorithm left, ChecksumAlgorithm right) =>
            !(left == right);
    }

    /// <typeparam name="TAlgo">The hash algorithm type.</typeparam>
    /// <typeparam name="TCipher">The integral type of <see cref="HashNumber"/>.</typeparam>
    /// <inheritdoc cref="ChecksumAlgorithm"/>
    public abstract class ChecksumAlgorithm<TAlgo, TCipher> : ChecksumAlgorithm, IChecksumAlgorithm<TCipher>, IEquatable<TAlgo> where TAlgo : IChecksumAlgorithm<TCipher> where TCipher : struct, IComparable, IFormattable
    {
        private TCipher _hashNumber;

        /// <inheritdoc/>
        public TCipher HashNumber
        {
            get
            {
                if (RawHash.IsEmpty)
                    return default;
                if (!EqualityComparer<TCipher>.Default.Equals(_hashNumber, default))
                    return _hashNumber;

                // Fallback (should be set from the underlying types if necessary)
                var span = RawHash.Span;
                _hashNumber = _hashNumber switch
                {
                    byte => (TCipher)(object)span[^1..][0],
                    ushort => (TCipher)(object)CryptoUtils.GetUInt16(span),
                    uint => (TCipher)(object)CryptoUtils.GetUInt32(span),
                    ulong => (TCipher)(object)CryptoUtils.GetUInt64(span),
                    BigInteger => (TCipher)(object)new BigInteger(span, true, !BitConverter.IsLittleEndian),
                    _ => throw new InvalidOperationException(ExceptionMessages.InvalidOperationUnsupportedType)
                };
                return _hashNumber;
            }
            protected set => _hashNumber = value;
        }

        /// <summary>Initializes a new instance of the <see cref="ChecksumAlgorithm{TAlgo, TCipher}"/> class.</summary>
        /// <inheritdoc/>
        protected ChecksumAlgorithm(int bits, int size = default) : base(bits, size) { }

        /// <summary>Initializes a new instance of the <see cref="ChecksumAlgorithm{TAlgo, TCipher}"/> class and encrypts the specified sequence of bytes.</summary>
        /// <inheritdoc/>
        protected ChecksumAlgorithm(int bits, byte[] bytes) : base(bits, bytes) { }

        /// <summary>Initializes a new instance of the <see cref="ChecksumAlgorithm{TAlgo, TCipher}"/> class and encrypts the specified text or file.</summary>
        /// <inheritdoc/>
        protected ChecksumAlgorithm(int bits, string textOrFile, bool strIsFilePath) : base(bits, textOrFile, strIsFilePath) { }

        /// <summary>Initializes a new instance of the <see cref="ChecksumAlgorithm{TAlgo, TCipher}"/> class and encrypts the specified text.</summary>
        /// <inheritdoc/>
        protected ChecksumAlgorithm(int bits, string text) : base(bits, text) { }

        /// <summary>Initializes a new instance of the <see cref="ChecksumAlgorithm{TAlgo, TCipher}"/> class and encrypts the specified file.</summary>
        /// <inheritdoc/>
        protected ChecksumAlgorithm(int bits, FileInfo fileInfo) : base(bits, fileInfo) { }

        /// <summary>Determines whether this instance have same values as the specified <typeparamref name="TAlgo"/> instance.</summary>
        /// <param name="other">The <typeparamref name="TAlgo"/> instance to compare.</param>
        /// <inheritdoc/>
        public bool Equals(TAlgo other)
        {
            if (other == null || HashSize != other.HashSize || HashNumber.GetType() != other.HashNumber.GetType())
                return false;
            if (RawHash.IsEmpty)
                return other.RawHash.IsEmpty;
            return EqualityComparer<TCipher>.Default.Equals(HashNumber, other.HashNumber) && RawHash.Span.SequenceEqual(other.RawHash.Span);
        }

        /// <inheritdoc/>
        public override bool Equals(object other) =>
            other is TAlgo item && Equals(item);

        /// <inheritdoc cref="Type.GetHashCode()"/>
        public override int GetHashCode() =>
            GetType().GetHashCode();

        /// <inheritdoc/>
        public override void Reset()
        {
            base.Reset();
            HashNumber = default;
        }

        /// <summary>Determines whether two specified <typeparamref name="TAlgo"/> instances have same values.</summary>
        /// <param name="left">The first <typeparamref name="TAlgo"/> instance to compare.</param>
        /// <param name="right">The second <typeparamref name="TAlgo"/> instance to compare.</param>
        public static bool operator ==(ChecksumAlgorithm<TAlgo, TCipher> left, ChecksumAlgorithm<TAlgo, TCipher> right) =>
            left?.Equals(right) ?? right is null;

        /// <summary>Defines an explicit conversion of <see cref="ChecksumAlgorithm{TAlgo, TCipher}"/> object to <see cref="string"/>.</summary>
        /// <param name="value">The item to convert to <see cref="string"/>.</param>
        /// <returns>The <see cref="string"/> representation of the last computed hash code.</returns>
        public static explicit operator string(ChecksumAlgorithm<TAlgo, TCipher> value) =>
            value.ToString();

        /// <summary>Defines an explicit conversion of <see cref="ChecksumAlgorithm{TAlgo, TCipher}"/> object to <typeparamref name="TCipher"/>.</summary>
        /// <param name="value">The item to convert to <typeparamref name="TCipher"/>.</param>
        /// <returns>The <typeparamref name="TCipher"/> representation of the last computed hash code.</returns>
        public static explicit operator TCipher(ChecksumAlgorithm<TAlgo, TCipher> value) =>
            value.HashNumber;

        /// <summary>Defines an explicit conversion of <see cref="ChecksumAlgorithm{TAlgo, TCipher}"/> object to <see cref="byte"/> array.</summary>
        /// <param name="value">The item to convert to <see cref="byte"/> array.</param>
        /// <returns>A copy of the last computed hash code.</returns>
        public static explicit operator byte[](ChecksumAlgorithm<TAlgo, TCipher> value) =>
            value.RawHash.Span!.ToArray();

        /// <summary>Determines whether two specified <typeparamref name="TAlgo"/> instances have different values.</summary>
        /// <param name="left">The first <typeparamref name="TAlgo"/> instance to compare.</param>
        /// <param name="right">The second <typeparamref name="TAlgo"/> instance to compare.</param>
        public static bool operator !=(ChecksumAlgorithm<TAlgo, TCipher> left, ChecksumAlgorithm<TAlgo, TCipher> right) =>
            !(left == right);
    }
}
