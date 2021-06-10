namespace Roydl.Crypto.Checksum
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Numerics;
    using System.Security.Cryptography;
    using System.Text;
    using Internal;
    using Resources;

    /// <summary>Represents the base class from which all implementations of checksum encryption algorithms must derive.</summary>
    public abstract class ChecksumAlgorithm : IChecksumAlgorithm, IEquatable<ChecksumAlgorithm>
    {
        /// <inheritdoc/>
        public int BitWidth { get; }

        /// <inheritdoc/>
        public int HashSize { get; }

        /// <inheritdoc/>
        public int RawHashSize { get; }

        /// <inheritdoc/>
        public string Hash => ToString();

        /// <inheritdoc/>
        public ReadOnlyMemory<byte> RawHash { get; protected set; }

        /// <summary>Initializes a new instance of the <see cref="ChecksumAlgorithm"/> class.</summary>
        /// <param name="bitWidth">The bit width of a computed hash.</param>
        /// <param name="strSize">The maximum length of the string representation of a computed hash. This is useful to prevent zero padding in algorithms with unusual bit widths.</param>
        /// <exception cref="ArgumentOutOfRangeException">bitWidth is less than 8.</exception>
        protected ChecksumAlgorithm(int bitWidth, int strSize = default)
        {
            if (bitWidth < 8)
                throw new ArgumentOutOfRangeException(nameof(bitWidth), bitWidth, null);
            BitWidth = bitWidth;
            HashSize = (int)MathF.Ceiling(BitWidth / 4f);
            if (HashSize % 2 != 0)
                HashSize++;
            if (HashSize < 2)
                HashSize = 2;
            RawHashSize = (int)MathF.Ceiling(HashSize / 2f);
            if (strSize > 0)
                HashSize = strSize;
        }

        /// <inheritdoc/>
        public abstract void Encrypt(Stream stream);

        /// <inheritdoc/>
        public abstract void Encrypt(byte[] bytes);

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
            if (RawHash.IsEmpty)
                return;
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
        public unsafe string ToString(bool uppercase)
        {
            if (RawHash.IsEmpty)
                return string.Empty;
            string str;
            fixed (byte* raw = &RawHash.Span[0])
            {
                var len = RawHash.Length;
                var sb = new StringBuilder(len * 2);
                for (var i = 0; i < len; i++)
                    sb.AppendFormat(uppercase ? "{0:X2}" : "{0:x2}", raw[i]);
                while (sb.Length < HashSize)
                    sb.Insert(0, '0');
                str = sb.Length > HashSize ? sb.ToString(sb.Length - HashSize, HashSize) : sb.ToString();
                sb.Clear();
            }
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

        /// <summary>Encrypts the specified sequence of bytes with the specified <see cref="HashAlgorithm"/>.</summary>
        /// <typeparam name="THashAlgorithm">The type of the algorithm.</typeparam>
        /// <param name="bytes">The sequence of bytes to encrypt.</param>
        /// <param name="algorithm">The algorithm to encrypt.</param>
        /// <exception cref="ArgumentNullException">stream or algorithm is null.</exception>
        protected void Encrypt<THashAlgorithm>(byte[] bytes, THashAlgorithm algorithm) where THashAlgorithm : HashAlgorithm
        {
            if (bytes == null)
                throw new ArgumentNullException(nameof(bytes));
            if (algorithm == null)
                throw new ArgumentNullException(nameof(algorithm));
            using var csp = algorithm;
            RawHash = csp.ComputeHash(bytes);
        }

        /// <summary>Encrypts the specified string with the specified <see cref="HashAlgorithm"/>.</summary>
        /// <typeparam name="THashAlgorithm">The type of the algorithm.</typeparam>
        /// <param name="text">The string to encrypt.</param>
        /// <param name="algorithm">The algorithm to encrypt.</param>
        /// <exception cref="ArgumentNullException">text or algorithm is null.</exception>
        protected void Encrypt<THashAlgorithm>(string text, THashAlgorithm algorithm) where THashAlgorithm : HashAlgorithm =>
            Encrypt(Encoding.UTF8.GetBytes(text), algorithm);

        /// <summary>Determines whether two specified <see cref="ChecksumAlgorithm"/> instances have same values.</summary>
        /// <param name="left">The first <see cref="ChecksumAlgorithm"/> instance to compare.</param>
        /// <param name="right">The second <see cref="ChecksumAlgorithm"/> instance to compare.</param>
        public static bool operator ==(ChecksumAlgorithm left, ChecksumAlgorithm right) =>
            left?.Equals(right) ?? right is null;

        /// <summary>Determines whether two specified <see cref="ChecksumAlgorithm"/> instances have different values.</summary>
        /// <param name="left">The first <see cref="ChecksumAlgorithm"/> instance to compare.</param>
        /// <param name="right">The second <see cref="ChecksumAlgorithm"/> instance to compare.</param>
        public static bool operator !=(ChecksumAlgorithm left, ChecksumAlgorithm right) =>
            !(left == right);

        /// <summary>Defines an explicit conversion from <see cref="ChecksumAlgorithm"/> to <see cref="byte"/> array.</summary>
        /// <param name="value">The item to convert to <see cref="byte"/> array.</param>
        /// <returns>A <see cref="byte"/> array copy of the last computed hash code.</returns>
        public static explicit operator byte[](ChecksumAlgorithm value) =>
            value.RawHash.Span.ToArray();

        /// <summary>Defines an explicit conversion from <see cref="ChecksumAlgorithm"/> to <see cref="string"/>.</summary>
        /// <param name="value">The item to convert to <see cref="string"/>.</param>
        /// <returns>The <see cref="string"/> representation of the last computed hash code.</returns>
        public static explicit operator string(ChecksumAlgorithm value) =>
            value.ToString();
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
                if (RawHash.IsEmpty || !EqualityComparer<TCipher>.Default.Equals(_hashNumber, default))
                    return _hashNumber;

                // Fallback (should be set from the underlying types if necessary)
                var span = RawHash.Span;
                _hashNumber = _hashNumber switch
                {
                    byte => (TCipher)(object)(!BitConverter.IsLittleEndian ? span[^1] : span[0]),
                    ushort => (TCipher)(object)CryptoUtils.GetUInt16(span, !BitConverter.IsLittleEndian),
                    uint => (TCipher)(object)CryptoUtils.GetUInt32(span, !BitConverter.IsLittleEndian),
                    ulong => (TCipher)(object)CryptoUtils.GetUInt64(span, !BitConverter.IsLittleEndian),
                    BigInteger => (TCipher)(object)new BigInteger(span, true, !BitConverter.IsLittleEndian),
                    _ => throw new InvalidOperationException(ExceptionMessages.InvalidOperationUnsupportedType)
                };
                return _hashNumber;
            }
            protected set => _hashNumber = value;
        }

        /// <summary>Initializes a new instance of the <see cref="ChecksumAlgorithm{TAlgo, TCipher}"/> class.</summary>
        /// <inheritdoc/>
        protected ChecksumAlgorithm(int bitWidth, int strSize = default) : base(bitWidth, strSize) { }

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

        /// <summary>Determines whether two specified <typeparamref name="TAlgo"/> instances have different values.</summary>
        /// <param name="left">The first <typeparamref name="TAlgo"/> instance to compare.</param>
        /// <param name="right">The second <typeparamref name="TAlgo"/> instance to compare.</param>
        public static bool operator !=(ChecksumAlgorithm<TAlgo, TCipher> left, ChecksumAlgorithm<TAlgo, TCipher> right) =>
            !(left == right);

        /// <summary>Defines an explicit conversion from <typeparamref name="TAlgo"/> to <see cref="sbyte"/>.</summary>
        /// <param name="value">The item to convert to <see cref="sbyte"/>.</param>
        /// <returns>The <see cref="sbyte"/> representation of the last computed hash code.</returns>
        public static explicit operator sbyte(ChecksumAlgorithm<TAlgo, TCipher> value) =>
            value.HashNumber.FromTo<TCipher, sbyte>();

        /// <summary>Defines an explicit conversion from <typeparamref name="TAlgo"/> to <see cref="byte"/>.</summary>
        /// <param name="value">The item to convert to <see cref="byte"/>.</param>
        /// <returns>The <see cref="byte"/> representation of the last computed hash code.</returns>
        public static explicit operator byte(ChecksumAlgorithm<TAlgo, TCipher> value) =>
            value.HashNumber.FromTo<TCipher, byte>();

        /// <summary>Defines an explicit conversion from <typeparamref name="TAlgo"/> to <see cref="short"/>.</summary>
        /// <param name="value">The item to convert to <see cref="short"/>.</param>
        /// <returns>The <see cref="short"/> representation of the last computed hash code.</returns>
        public static explicit operator short(ChecksumAlgorithm<TAlgo, TCipher> value) =>
            value.HashNumber.FromTo<TCipher, short>();

        /// <summary>Defines an explicit conversion from <typeparamref name="TAlgo"/> to <see cref="ushort"/>.</summary>
        /// <param name="value">The item to convert to <see cref="ushort"/>.</param>
        /// <returns>The <see cref="ushort"/> representation of the last computed hash code.</returns>
        public static explicit operator ushort(ChecksumAlgorithm<TAlgo, TCipher> value) =>
            value.HashNumber.FromTo<TCipher, ushort>();

        /// <summary>Defines an explicit conversion from <typeparamref name="TAlgo"/> to <see cref="int"/>.</summary>
        /// <param name="value">The item to convert to <see cref="int"/>.</param>
        /// <returns>The <see cref="int"/> representation of the last computed hash code.</returns>
        public static explicit operator int(ChecksumAlgorithm<TAlgo, TCipher> value) =>
            value.HashNumber.FromTo<TCipher, int>();

        /// <summary>Defines an explicit conversion from <typeparamref name="TAlgo"/> to <see cref="uint"/>.</summary>
        /// <param name="value">The item to convert to <see cref="uint"/>.</param>
        /// <returns>The <see cref="uint"/> representation of the last computed hash code.</returns>
        public static explicit operator uint(ChecksumAlgorithm<TAlgo, TCipher> value) =>
            value.HashNumber.FromTo<TCipher, uint>();

        /// <summary>Defines an explicit conversion from <typeparamref name="TAlgo"/> to <see cref="long"/>.</summary>
        /// <param name="value">The item to convert to <see cref="long"/>.</param>
        /// <returns>The <see cref="long"/> representation of the last computed hash code.</returns>
        public static explicit operator long(ChecksumAlgorithm<TAlgo, TCipher> value) =>
            value.HashNumber.FromTo<TCipher, long>();

        /// <summary>Defines an explicit conversion from <typeparamref name="TAlgo"/> to <see cref="ulong"/>.</summary>
        /// <param name="value">The item to convert to <see cref="ulong"/>.</param>
        /// <returns>The <see cref="ulong"/> representation of the last computed hash code.</returns>
        public static explicit operator ulong(ChecksumAlgorithm<TAlgo, TCipher> value) =>
            value.HashNumber.FromTo<TCipher, ulong>();

        /// <summary>Defines an explicit conversion from <typeparamref name="TAlgo"/> to <see cref="IntPtr"/>.</summary>
        /// <param name="value">The item to convert to <see cref="IntPtr"/>.</param>
        /// <returns>The <see cref="IntPtr"/> representation of the last computed hash code.</returns>
        public static explicit operator nint(ChecksumAlgorithm<TAlgo, TCipher> value) =>
            value.HashNumber.FromTo<TCipher, nint>();

        /// <summary>Defines an explicit conversion from <typeparamref name="TAlgo"/> to <see cref="UIntPtr"/>.</summary>
        /// <param name="value">The item to convert to <see cref="UIntPtr"/>.</param>
        /// <returns>The <see cref="IntPtr"/> representation of the last computed hash code.</returns>
        public static explicit operator nuint(ChecksumAlgorithm<TAlgo, TCipher> value) =>
            value.HashNumber.FromTo<TCipher, nuint>();

        /// <summary>Defines an explicit conversion from <typeparamref name="TAlgo"/> to <see cref="BigInteger"/>.</summary>
        /// <param name="value">The item to convert to <see cref="BigInteger"/>.</param>
        /// <returns>The <see cref="BigInteger"/> representation of the last computed hash code.</returns>
        public static explicit operator BigInteger(ChecksumAlgorithm<TAlgo, TCipher> value) =>
            value.HashNumber.FromTo<TCipher, BigInteger>();

        /// <summary>Defines an explicit conversion from <typeparamref name="TAlgo"/> to <see cref="byte"/> array.</summary>
        /// <param name="value">The item to convert to <see cref="byte"/> array.</param>
        /// <returns>A <see cref="byte"/> array copy of the last computed hash code.</returns>
        public static explicit operator byte[](ChecksumAlgorithm<TAlgo, TCipher> value) =>
            value.RawHash.ToArray();

        /// <summary>Defines an explicit conversion from <typeparamref name="TAlgo"/> to <see cref="string"/>.</summary>
        /// <param name="value">The item to convert to <see cref="string"/>.</param>
        /// <returns>The <see cref="string"/> representation of the last computed hash code.</returns>
        public static explicit operator string(ChecksumAlgorithm<TAlgo, TCipher> value) =>
            value.Hash;
    }
}
