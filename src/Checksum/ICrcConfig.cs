namespace Roydl.Crypto.Checksum
{
    using System;
    using System.IO;
    using System.Numerics;

    /// <summary>Represents the interface for CRC configuration structures.</summary>
    /// <typeparam name="TValue">The integral type of the hash code. Should be <see cref="byte"/>, <see cref="ushort"/>, <see cref="uint"/>, <see cref="ulong"/>, or <see cref="BigInteger"/>.</typeparam>
    public interface ICrcConfig<TValue> where TValue : struct, IComparable, IFormattable
    {
        /// <summary>Gets the bit width of a computed hash.</summary>
        int BitWidth { get; }

        /// <summary>Gets the test value that is used to check whether the algorithm is working correctly.</summary>
        TValue Check { get; }

        /// <summary>Gets the mask, which is mostly the maximum type value.</summary>
        TValue Mask { get; }

        /// <summary>Gets the polynomial used to generate the CRC hash table.</summary>
        /// <remarks>Used to create the <see cref="Table">Table</see> once.</remarks>
        TValue Poly { get; }

        /// <summary>Gets the seed from which the CRC register should be initialized at beginning of the calculation.</summary>
        /// <remarks>Only automatically used in <see langword="ComputeHash"/> (<see cref="ComputeHash(ReadOnlySpan{byte}, out TValue)">Span</see> and <see cref="ComputeHash(Stream, out TValue)">Stream</see>) functions with <see langword="out"/> parameter.</remarks>
        TValue Init { get; }

        /// <summary>Gets the value that determines whether the input bytes are processed in big-endian bit order for the calculation.</summary>
        /// <remarks>Used in all <see langword="ComputeHash"/> functions.</remarks>
        bool RefIn { get; }

        /// <summary>Gets the value that determines whether the bits of the calculated hash code are reversed.</summary>
        /// <remarks>Used in <see cref="FinalizeHash(ref TValue)"/>.</remarks>
        bool RefOut { get; }

        /// <summary>The value to xor with the calculated hash code.</summary>
        /// <remarks>Used in <see cref="FinalizeHash(ref TValue)">FinalizeHash</see>, which is only automatically called in <see langword="ComputeHash"/> (<see cref="ComputeHash(ReadOnlySpan{byte}, out TValue)">Span</see> and <see cref="ComputeHash(Stream, out TValue)">Stream</see>) functions with <see langword="out"/> parameter.</remarks>
        TValue XorOut { get; }

        /// <summary>Gets the generated hash table of the configured CRC algorithm.</summary>
        /// <remarks>When using the <see cref="CrcOptions.Crc32.Default">standard</see> configuration, the table is empty if SSE 4.2 is supported by the CPU .</remarks>
        ReadOnlyMemory<TValue> Table { get; }

        /// <summary>Computes the hash from the data of the specified stream using the configured CRC algorithm.</summary>
        /// <param name="stream">The stream with the data to hash.</param>
        /// <param name="hash">The fully computed hash code.</param>
        /// <exception cref="ArgumentNullException">stream is null.</exception>
        /// <exception cref="IOException">An I/O error occurs.</exception>
        /// <exception cref="NotSupportedException">stream does not support reading.</exception>
        /// <remarks><see cref="Init">Init</see>, <see cref="RefIn">RefIn</see>, <see cref="RefOut">RefOut</see> and <see cref="XorOut">XorOut</see> are used.</remarks>
        void ComputeHash(Stream stream, out TValue hash);

        /// <summary>Computes the hash from the specified sequence of bytes using the configured CRC algorithm.</summary>
        /// <param name="bytes">The sequence of bytes to hash.</param>
        /// <param name="hash">The fully computed hash code.</param>
        /// <exception cref="ArgumentException">bytes is empty.</exception>
        /// <remarks><see cref="Init">Init</see>, <see cref="RefIn">RefIn</see>, <see cref="RefOut">RefOut</see> and <see cref="XorOut">XorOut</see> are used.</remarks>
        void ComputeHash(ReadOnlySpan<byte> bytes, out TValue hash);

        /// <summary>Computes the hash from the specified sequence of bytes using the configured CRC algorithm.</summary>
        /// <param name="bytes">The sequence of bytes to hash.</param>
        /// <param name="len">The number of bytes to hash.</param>
        /// <param name="hash">The hash code to be computed or its computation that will be continued.</param>
        /// <remarks>Only <see cref="RefIn">RefIn</see> is used.</remarks>
        /// <inheritdoc cref="ComputeHash(ReadOnlySpan{byte}, out TValue)"/>
        void AppendData(ReadOnlySpan<byte> bytes, int len, ref TValue hash);

        /// <summary>Computes the hash from the specified byte value using the CRC algorithm.</summary>
        /// <param name="value">The byte value to hash.</param>
        /// <param name="hash">The hash code to be computed or its computation that will be continued.</param>
        /// <remarks>Only <see cref="RefIn">RefIn</see> is used.</remarks>
        void AppendData(byte value, ref TValue hash);

        /// <summary>Finalizes the computed hash code.</summary>
        /// <param name="hash">The computed hash code to be finalized.</param>
        /// <remarks><see cref="RefOut">RefOut</see> and <see cref="XorOut">XorOut</see> are used.</remarks>
        void FinalizeHash(ref TValue hash);

        /// <summary>Check whether the current algorithm is working correctly.</summary>
        /// <param name="current">The computed value that is compared to <see cref="Check"/>.</param>
        /// <remarks><see cref="Check">Check</see> is used.</remarks>
        bool IsValid(out TValue current);

        /// <inheritdoc cref="IsValid(out TValue)"/>
        bool IsValid();
    }
}
