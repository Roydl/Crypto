namespace Roydl.Crypto.Checksum
{
    using System;
    using System.IO;

    /// <summary>Represents the interface for checksum encryption algorithms.</summary>
    public interface IChecksumAlgorithm : IChecksumResult
    {
        /// <summary>Gets the algorithm name.</summary>
        string AlgorithmName { get; }

        /// <summary>Gets the bit width of a computed hash.</summary>
        int BitWidth { get; }

        /// <summary>Computes the hash from the bytes of the specified stream starting at its current position.</summary>
        /// <param name="stream">The stream to hash.</param>
        /// <exception cref="ArgumentNullException">stream is null.</exception>
        /// <exception cref="IOException">An I/O error occurs.</exception>
        /// <exception cref="NotSupportedException">stream does not support reading.</exception>
        /// <remarks>For more information, see <see cref="IChecksumResult.Hash">Hash</see>, <see cref="IChecksumResult{TValue}.CipherHash">HashNumber</see> and <see cref="IChecksumResult.RawHash">RawHash</see>.</remarks>
        void ComputeHash(Stream stream);

        /// <summary>Computes the hash from the specified sequence of bytes.</summary>
        /// <param name="bytes">The sequence of bytes to hash.</param>
        /// <exception cref="ArgumentException">bytes is empty.</exception>
        /// <remarks>For more information, see <see cref="IChecksumResult.Hash">Hash</see>, <see cref="IChecksumResult{TValue}.CipherHash">HashNumber</see> and <see cref="IChecksumResult.RawHash">RawHash</see>.</remarks>
        void ComputeHash(ReadOnlySpan<byte> bytes);

        /// <summary>Computes the hash from the specified text or file.</summary>
        /// <param name="textOrFile">The text or file to hash.</param>
        /// <param name="strIsFilePath"><see langword="true"/> if the specified value is a file path; otherwise, <see langword="false"/>.</param>
        /// <exception cref="ArgumentNullException">textOrFile is null.</exception>
        /// <exception cref="ArgumentException">textOrFile is empty.</exception>
        /// <exception cref="FileNotFoundException">textOrFile cannot be found.</exception>
        /// <inheritdoc cref="ComputeHash(ReadOnlySpan{byte})"/>
        void ComputeHash(string textOrFile, bool strIsFilePath);

        /// <summary>Computes the hash from the specified text.</summary>
        /// <param name="text">The string to hash.</param>
        /// <exception cref="ArgumentNullException">text is null.</exception>
        /// <exception cref="ArgumentException">text is empty.</exception>
        /// <inheritdoc cref="ComputeHash(ReadOnlySpan{byte})"/>
        void ComputeHash(string text);

        /// <summary>Computes the hash from the specified file.</summary>
        /// <param name="fileInfo">The file to hash.</param>
        /// <exception cref="ArgumentNullException">fileInfo is null.</exception>
        /// <exception cref="FileNotFoundException">File cannot be found.</exception>
        /// <remarks>For more information, see <see cref="IChecksumResult.Hash">Hash</see>, <see cref="IChecksumResult{TValue}.CipherHash">HashNumber</see> and <see cref="IChecksumResult.RawHash">RawHash</see>.</remarks>
        void ComputeHash(FileInfo fileInfo);

        /// <summary>Computes the hash from the specified file.</summary>
        /// <param name="path">The full path of the file to hash.</param>
        /// <exception cref="ArgumentNullException">path is null.</exception>
        /// <exception cref="ArgumentException">path is empty.</exception>
        /// <exception cref="FileNotFoundException">path cannot be found.</exception>
        /// <inheritdoc cref="ComputeHash(FileInfo)"/>
        void ComputeFileHash(string path);
    }

    /// <summary>Represents the interface for checksum encryption algorithms.</summary>
    /// <typeparam name="TCipher">The integral type of <see cref="IChecksumResult{TValue}.CipherHash"/>.</typeparam>
    public interface IChecksumAlgorithm<out TCipher> : IChecksumAlgorithm, IChecksumResult<TCipher> where TCipher : struct, IComparable, IFormattable { }
}
