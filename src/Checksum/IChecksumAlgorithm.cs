namespace Roydl.Crypto.Checksum
{
    using System;
    using System.IO;

    /// <summary>Represents the interface for checksum encryption algorithms.</summary>
    public interface IChecksumAlgorithm : IChecksumResult
    {
        /// <summary>Gets the bit width of a computed hash.</summary>
        int BitWidth { get; }

        /// <summary>Encrypts the bytes of the specified stream starting at its current position.</summary>
        /// <param name="stream">The stream to encrypt.</param>
        /// <exception cref="ArgumentNullException">stream is null.</exception>
        /// <exception cref="IOException">An I/O error occurs.</exception>
        /// <exception cref="NotSupportedException">stream does not support reading.</exception>
        /// <remarks>For more information, see <see cref="IChecksumResult.Hash">Hash</see>, <see cref="IChecksumResult{TValue}.HashNumber">HashNumber</see> and <see cref="IChecksumResult.RawHash">RawHash</see>.</remarks>
        void Encrypt(Stream stream);

        /// <summary>Encrypts the specified sequence of bytes.</summary>
        /// <param name="bytes">The sequence of bytes to encrypt.</param>
        /// <exception cref="ArgumentNullException">bytes is null.</exception>
        /// <exception cref="ArgumentException">bytes is empty.</exception>
        /// <remarks>For more information, see <see cref="IChecksumResult.Hash">Hash</see>, <see cref="IChecksumResult{TValue}.HashNumber">HashNumber</see> and <see cref="IChecksumResult.RawHash">RawHash</see>.</remarks>
        void Encrypt(byte[] bytes);

        /// <inheritdoc cref="Encrypt(byte[])"/>
        void Encrypt(ReadOnlySpan<byte> bytes);

        /// <summary>Encrypts the specified text or file.</summary>
        /// <param name="textOrFile">The text or file to encrypt.</param>
        /// <param name="strIsFilePath"><see langword="true"/> if the specified value is a file path; otherwise, <see langword="false"/>.</param>
        /// <exception cref="ArgumentNullException">textOrFile is null.</exception>
        /// <exception cref="ArgumentException">textOrFile is empty.</exception>
        /// <exception cref="FileNotFoundException">textOrFile cannot be found.</exception>
        /// <inheritdoc cref="Encrypt(byte[])"/>
        void Encrypt(string textOrFile, bool strIsFilePath);

        /// <summary>Encrypts the specified string.</summary>
        /// <param name="text">The string to encrypt.</param>
        /// <exception cref="ArgumentNullException">text is null.</exception>
        /// <exception cref="ArgumentException">text is empty.</exception>
        /// <inheritdoc cref="Encrypt(byte[])"/>
        void Encrypt(string text);

        /// <summary>Encrypts the specified file.</summary>
        /// <param name="fileInfo">The file to encrypt.</param>
        /// <exception cref="ArgumentNullException">fileInfo is null.</exception>
        /// <exception cref="FileNotFoundException">File cannot be found.</exception>
        /// <remarks>For more information, see <see cref="IChecksumResult.Hash">Hash</see>, <see cref="IChecksumResult{TValue}.HashNumber">HashNumber</see> and <see cref="IChecksumResult.RawHash">RawHash</see>.</remarks>
        void Encrypt(FileInfo fileInfo);

        /// <summary>Encrypts the specified file.</summary>
        /// <param name="path">The full path of the file to encrypt.</param>
        /// <exception cref="ArgumentNullException">path is null.</exception>
        /// <exception cref="ArgumentException">path is empty.</exception>
        /// <exception cref="FileNotFoundException">path cannot be found.</exception>
        /// <inheritdoc cref="Encrypt(FileInfo)"/>
        void EncryptFile(string path);

        /// <summary>Converts the <see cref="IChecksumResult.RawHash">RawHash</see> of this instance to its equivalent string representation.</summary>
        /// <param name="uppercase"><see langword="true"/> to convert letters to uppercase; otherwise, <see langword="false"/>.</param>
        /// <returns>The string representation of the last computed hash code.</returns>
        string ToString(bool uppercase);

        /// <inheritdoc cref="ToString(bool)"/>
        string ToString();
    }

    /// <summary>Represents the interface for checksum encryption algorithms.</summary>
    /// <typeparam name="TCipher">The integral type of <see cref="IChecksumResult{TValue}.HashNumber"/>.</typeparam>
    public interface IChecksumAlgorithm<out TCipher> : IChecksumAlgorithm, IChecksumResult<TCipher> where TCipher : struct, IComparable, IFormattable { }
}
