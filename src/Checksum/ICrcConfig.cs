namespace Roydl.Crypto.Checksum
{
    using System;
    using System.IO;
    using System.Numerics;

    /// <summary>Represents a CRC configuration structure.</summary>
    /// <typeparam name="TValue">The integral type of the hash code. Should be <see cref="byte"/>, <see cref="ushort"/>, <see cref="uint"/>, <see cref="ulong"/>, or <see cref="BigInteger"/>.</typeparam>
    public interface ICrcConfig<TValue> where TValue : struct, IComparable, IFormattable
    {
        /// <summary>Gets the hash size in bits.</summary>
        int Bits { get; }

        /// <summary>Gets the test value that is used to check whether the algorithm is working correctly.</summary>
        TValue Check { get; }

        /// <summary>Gets the mask, which is mostly the maximum type value.</summary>
        TValue Mask { get; }

        /// <summary>Gets the polynomial used to generate the CRC hash table.</summary>
        /// <remarks>Used to create the <see cref="Table">Table</see> once.</remarks>
        TValue Poly { get; }

        /// <summary>Gets the seed from which the CRC register should be initialized at beginning of the calculation.</summary>
        /// <remarks>Only automatically used in <see cref="Stream"/> based <see cref="ComputeHash(Stream, out TValue)">ComputeHash</see>.</remarks>
        TValue Init { get; }

        /// <summary>Gets the value that determines whether the input bytes are processed in big-endian bit order for the calculation.</summary>
        /// <remarks>Used in <see langword="ComputeHash"/> <see cref="ComputeHash(byte, ref TValue)">here</see> and <see cref="ComputeHash(Stream, out TValue)">here</see>.</remarks>
        bool RefIn { get; }

        /// <summary>Gets the value that determines whether the bits of the calculated hash code are reversed.</summary>
        /// <remarks>Used in <see cref="FinalizeHash(ref TValue)"/>.</remarks>
        bool RefOut { get; }

        /// <summary>The value to xor with the calculated hash code.</summary>
        /// <remarks>Used in <see cref="FinalizeHash(ref TValue)"/>.</remarks>
        TValue XorOut { get; }

        /// <summary>Gets the generated hash table of the configured CRC algorithm.</summary>
        /// <remarks>For more information, see <see cref="Poly">Poly</see>.</remarks>
        ReadOnlyMemory<TValue> Table { get; }

        /// <summary>Computes the hash of stream data using the configured CRC algorithm.</summary>
        /// <param name="stream">The stream with the data to encrypt.</param>
        /// <param name="hash">The fully computed hash code.</param>
        /// <exception cref="ArgumentNullException">stream is null.</exception>
        /// <remarks>For more information, see <see cref="Init">Init</see>, <see cref="RefIn">RefIn</see>, <see cref="RefOut">RefOut</see> and <see cref="XorOut">XorOut</see>.</remarks>
        void ComputeHash(Stream stream, out TValue hash);

        /// <summary>Computes the hash of the byte value using the CRC algorithm.</summary>
        /// <param name="value">The byte value to encrypt.</param>
        /// <param name="hash">The hash code to be computed or its computation that will be continued.</param>
        /// <remarks>For more information, see <see cref="RefIn">RefIn</see>.</remarks>
        void ComputeHash(byte value, ref TValue hash);

        /// <summary>Finalizes the computed hash code.</summary>
        /// <param name="hash">The computed hash code to be finalized.</param>
        /// <remarks>For more information, see <see cref="RefOut">RefOut</see> and <see cref="XorOut">XorOut</see>.</remarks>
        void FinalizeHash(ref TValue hash);

        /// <summary>Check whether the current algorithm is working correctly.</summary>
        /// <param name="current">The computed value that is compared to <see cref="Check"/>.</param>
        /// <remarks>For more information, see <see cref="Check">Check</see>.</remarks>
        bool IsValid(out TValue current);

        /// <inheritdoc cref="IsValid(out TValue)"/>
        bool IsValid();
    }
}
