namespace Roydl.Crypto.AbstractSamples
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.IO;
    using System.Security.Cryptography;
    using System.Text;
    using Properties;

    /// <summary>
    ///     Represents the base class from which all implementations of checksum
    ///     encryption algorithms must derive.
    /// </summary>
    public abstract class ChecksumSample
    {
        /// <summary>
        ///     Gets the required hash length.
        /// </summary>
        public abstract int HashLength { get; }

        /// <summary>
        ///     Gets the computed hash code value.
        /// </summary>
        public virtual IReadOnlyList<byte> RawHash { get; protected set; }

        /// <summary>
        ///     Gets the string representation of the computed hash code.
        /// </summary>
        public string Hash => ToString();

        /// <summary>
        ///     Encrypts the specified stream.
        /// </summary>
        /// <param name="stream">
        ///     The stream to encrypt.
        /// </param>
        public abstract void Encrypt(Stream stream);

        /// <summary>
        ///     Encrypts the specified sequence of bytes.
        /// </summary>
        /// <param name="bytes">
        ///     The sequence of bytes to encrypt.
        /// </param>
        /// <exception cref="ArgumentNullException">
        ///     bytes is null.
        /// </exception>
        /// <exception cref="ArgumentException">
        ///     bytes is empty.
        /// </exception>
        public void Encrypt(byte[] bytes)
        {
            if (bytes == null)
                throw new ArgumentNullException(nameof(bytes));
            if (bytes.Length < 1)
                throw new ArgumentException(ExceptionMessages.IsEmpty, nameof(bytes));
            using var ms = new MemoryStream(bytes);
            Encrypt(ms);
        }

        /// <summary>
        ///     Encrypts the specified string.
        /// </summary>
        /// <param name="text">
        ///     The string to encrypt.
        /// </param>
        /// <exception cref="ArgumentNullException">
        ///     text is null.
        /// </exception>
        /// <exception cref="ArgumentException">
        ///     text is empty.
        /// </exception>
        public void Encrypt(string text)
        {
            if (text == null)
                throw new ArgumentNullException(nameof(text));
            if (text.Length < 1)
                throw new ArgumentException(ExceptionMessages.IsEmpty, nameof(text));
            Encrypt(Encoding.UTF8.GetBytes(text));
        }

        /// <summary>
        ///     Encrypts the specified file.
        /// </summary>
        /// <param name="path">
        ///     The full path of the file to encrypt.
        /// </param>
        /// <exception cref="ArgumentNullException">
        ///     path is null.
        /// </exception>
        /// <exception cref="ArgumentException">
        ///     path is empty.
        /// </exception>
        /// <exception cref="FileNotFoundException">
        ///     path cannot be found.
        /// </exception>
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
        ///     Returns the hash code for this instance.
        /// </summary>
        public override int GetHashCode() =>
            GetType().GetHashCode();

        /// <summary>
        ///     Converts the <see cref="RawHash"/> of this instance to its equivalent
        ///     string representation.
        /// </summary>
        public override string ToString()
        {
            if (RawHash is not byte[] ba)
                return new string('0', HashLength);
            var sb = new StringBuilder(ba.Length * 2);
            foreach (var b in ba)
                sb.Append(b.ToString("x2", CultureInfo.CurrentCulture));
            var s = sb.ToString();
            sb.Clear();
            return s;
        }

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
        }
    }
}
