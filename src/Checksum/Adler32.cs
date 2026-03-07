namespace Roydl.Crypto.Checksum
{
    using System;
    using System.IO;
    using System.Runtime.CompilerServices;
    using System.Runtime.Intrinsics;
    using System.Runtime.Intrinsics.X86;
    using Internal;
    using Resources;

    /// <summary>Provides functionality to compute Adler-32 hashes.</summary>
    public sealed class Adler32 : ChecksumAlgorithm<Adler32, uint>
    {
        private const uint ModAdler = 0xfff1u;

        /// <summary>Initializes a new instance of the <see cref="Adler32"/> class.</summary>
        public Adler32() : base(32) => AlgorithmName = nameof(Adler32);

        /// <returns>A newly created <see cref="Adler32"/> instance.</returns>
        public static Adler32 Create() => new();

        /// <inheritdoc/>
        public override unsafe void ComputeHash(Stream stream)
        {
            Reset();
            ArgumentNullException.ThrowIfNull(stream);
            if (!stream.CanRead)
                throw new NotSupportedException(ExceptionMessages.NotSupportedStreamRead);
            var sum1 = 1u;
            var sum2 = 0u;
            Span<byte> bytes = stackalloc byte[stream.GetBufferSize()];
            fixed (byte* input = bytes)
            {
                int len;
                while ((len = stream.Read(bytes)) > 0)
                    AppendData(input, len, ref sum1, ref sum2);
            }
            FinalizeHash(sum1, sum2);
        }

        /// <inheritdoc/>
        public override unsafe void ComputeHash(ReadOnlySpan<byte> bytes)
        {
            Reset();
            if (bytes.IsEmpty)
                throw new ArgumentException(ExceptionMessages.ArgumentEmpty, nameof(bytes));
            var sum1 = 1u;
            var sum2 = 0u;
            fixed (byte* input = bytes)
                AppendData(input, bytes.Length, ref sum1, ref sum2);
            FinalizeHash(sum1, sum2);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private unsafe static void AppendData(byte* input, int len, ref uint hash1, ref uint hash2)
        {
            var sum1 = hash1;
            var sum2 = hash2;

            if (Avx512BW.IsSupported && len >= 64)
            {
                // Weights for sum2: byte at position i gets weight (64 - i)
                var vtap = Vector512.Create(64, 63, 62, 61, 60, 59, 58, 57, 56, 55, 54, 53, 52, 51, 50, 49,
                                            48, 47, 46, 45, 44, 43, 42, 41, 40, 39, 38, 37, 36, 35, 34, 33,
                                            32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17,
                                            16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1);
                var vzero = Vector512<byte>.Zero;
                var vones = Vector512.Create((short)1);

                // NMAX=5552, 5552/64=86
                const int maxBlocks = 5552 / 64;

                while (len >= 64)
                {
                    var blocks = Math.Min(len / 64, maxBlocks);

                    var vs1 = Vector512<uint>.Zero;
                    var vs1Prev = Vector512<uint>.Zero;
                    var vs2 = Vector512<uint>.Zero;

                    for (var i = 0; i < blocks; i++)
                    {
                        var vdata = Avx512F.LoadVector512(input + i * 64);

                        // Weighted sum via vpmaddubsw + vpmaddwd
                        var vprod = Avx512BW.MultiplyAddAdjacent(vdata, vtap);
                        vs2 = Avx512F.Add(vs2, Avx512BW.MultiplyAddAdjacent(vprod, vones).AsUInt32());

                        vs1Prev = Avx512F.Add(vs1Prev, vs1);

                        // Byte sum via vpsadbw against zero
                        vs1 = Avx512F.Add(vs1, Avx512BW.SumAbsoluteDifferences(vdata, vzero).AsUInt32());
                    }

                    input += blocks * 64;
                    len -= blocks * 64;

                    ulong s2 = sum2;
                    s2 += (ulong)64 * (uint)blocks * sum1;
                    s2 += (ulong)64 * HorizontalSum512(vs1Prev);
                    s2 += HorizontalSum512(vs2);

                    sum1 = (sum1 + HorizontalSum512(vs1)) % ModAdler;
                    sum2 = (uint)(s2 % ModAdler);
                }
            }
            else if (Avx2.IsSupported && len >= 32)
            {
                // Weights for sum2: byte at position i gets weight (32 - i)
                var vtap = Vector256.Create(32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17,
                                            16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1);
                var vzero = Vector256<byte>.Zero;
                var vones = Vector256.Create((short)1);

                // NMAX=5552, 5552/32=173
                const int maxBlocks = 5552 / 32;

                while (len >= 32)
                {
                    var blocks = Math.Min(len / 32, maxBlocks);

                    var vs1 = Vector256<uint>.Zero;
                    var vs1Prev = Vector256<uint>.Zero;
                    var vs2 = Vector256<uint>.Zero;

                    for (var i = 0; i < blocks; i++)
                    {
                        var vdata = Avx.LoadVector256(input + i * 32);

                        // Weighted sum via pmaddubsw + pmaddwd
                        var vprod = Avx2.MultiplyAddAdjacent(vdata, vtap);
                        vs2 = Avx2.Add(vs2, Avx2.MultiplyAddAdjacent(vprod, vones).AsUInt32());

                        vs1Prev = Avx2.Add(vs1Prev, vs1);

                        // Byte sum via psadbw against zero
                        vs1 = Avx2.Add(vs1, Avx2.SumAbsoluteDifferences(vdata, vzero).AsUInt32());
                    }

                    input += blocks * 32;
                    len -= blocks * 32;

                    ulong s2 = sum2;
                    s2 += (ulong)32 * (uint)blocks * sum1;
                    s2 += (ulong)32 * HorizontalSum256(vs1Prev);
                    s2 += HorizontalSum256(vs2);

                    sum1 = (sum1 + HorizontalSum256(vs1)) % ModAdler;
                    sum2 = (uint)(s2 % ModAdler);
                }
            }
            else if (Ssse3.IsSupported && len >= 16)
            {
                // Weights for sum2: byte at position i gets weight (16 - i)
                var vtap = Vector128.Create(16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1);
                var vzero = Vector128<byte>.Zero;
                var vones = Vector128.Create((short)1);

                // NMAX=5552, 5552/16=347
                const int maxBlocks = 5552 / 16;

                while (len >= 16)
                {
                    var blocks = Math.Min(len / 16, maxBlocks);

                    var vs1 = Vector128<uint>.Zero;
                    var vs1Prev = Vector128<uint>.Zero;
                    var vs2 = Vector128<uint>.Zero;

                    for (var i = 0; i < blocks; i++)
                    {
                        var vdata = Sse2.LoadVector128(input + i * 16);

                        // Weighted sum via pmaddubsw + pmaddwd
                        var vprod = Ssse3.MultiplyAddAdjacent(vdata, vtap);
                        vs2 = Sse2.Add(vs2, Sse2.MultiplyAddAdjacent(vprod, vones).AsUInt32());

                        vs1Prev = Sse2.Add(vs1Prev, vs1);

                        // Byte sum via psadbw against zero
                        vs1 = Sse2.Add(vs1, Sse2.SumAbsoluteDifferences(vdata, vzero).AsUInt32());
                    }

                    input += blocks * 16;
                    len -= blocks * 16;

                    ulong s2 = sum2;
                    s2 += (ulong)16 * (uint)blocks * sum1;
                    s2 += (ulong)16 * HorizontalSum128(vs1Prev);
                    s2 += HorizontalSum128(vs2);

                    sum1 = (sum1 + HorizontalSum128(vs1)) % ModAdler;
                    sum2 = (uint)(s2 % ModAdler);
                }
            }

            // Scalar tail for remaining bytes
            const int scalarMax = 5552;
            while (len > 0)
            {
                var n = Math.Min(len, scalarMax);
                len -= n;
                while (--n >= 0)
                {
                    sum1 += *input++;
                    sum2 += sum1;
                }
                sum1 %= ModAdler;
                sum2 %= ModAdler;
            }

            hash1 = sum1;
            hash2 = sum2;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint HorizontalSum512(Vector512<uint> v)
        {
            var lo = v.GetLower();
            var hi = v.GetUpper();
            return HorizontalSum256(Avx2.Add(lo, hi));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint HorizontalSum256(Vector256<uint> v)
        {
            var lo = v.GetLower();
            var hi = v.GetUpper();
            return HorizontalSum128(Sse2.Add(lo, hi));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint HorizontalSum128(Vector128<uint> v)
        {
            var sum = Sse2.Add(v, Sse2.Shuffle(v, 0b_0100_1110)); // Swap 64-bit halves
            sum = Sse2.Add(sum, Sse2.Shuffle(sum, 0b_1011_0001)); // Swap adjacent 32-bit pairs
            return sum.GetElement(0);
        }

        private void FinalizeHash(uint hash1, uint hash2) =>
            Update((hash2 << 16 | hash1) & uint.MaxValue);
    }
}
