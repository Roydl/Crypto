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
            // Hardware-accelerated SIMD dispatch for Adler-32 computation.
            //
            // We attempt to use the widest available SIMD instruction set in descending order:
            //
            //   AVX-512 (512-bit): Processes 64 bytes per iteration using ZMM registers.
            //                      Requires Intel Skylake-X / Ice Lake or AMD Zen 4 and newer.
            //                      Offers the highest throughput but is not universally available.
            //
            //   AVX2   (256-bit): Processes 32 bytes per iteration using YMM registers.
            //                     Available on Intel Haswell (2013) / AMD Ryzen (2017) and newer.
            //                     Good balance between availability and throughput.
            //
            //   SSSE3  (128-bit): Processes 16 bytes per iteration using XMM registers.
            //                     Available on virtually all x86-64 CPUs since ~2007.
            //                     Used as a safe minimum baseline for SIMD acceleration.
            //
            //   Scalar:           Processes one byte at a time. No SIMD dependency whatsoever.
            //                     Applied to any remaining bytes after the SIMD block, or
            //                     exclusively when no SIMD instruction set is available.
            //
            // Each SIMD path uses pmaddubsw (u8 × s8 → s16 pair-sum) combined with psadbw
            // (absolute difference sum against zero) to compute the weighted sum2 and byte
            // sum1 accumulations respectively, deferring the modulo reduction to NMAX-sized
            // block boundaries to minimize the number of expensive mod operations.
            //
            // Note: Although the three SIMD blocks are structurally similar, they are kept
            // as separate, explicit code paths intentionally. Abstracting them into a single
            // generic or delegate-based method would introduce indirect calls, virtual dispatch,
            // or lambda overhead that the JIT cannot reliably eliminate — directly undermining
            // the very performance gains SIMD is supposed to provide. The code duplication
            // is an acceptable and deliberate trade-off for zero-overhead hot path execution.

            const int scalarMax = 5552;
            
            var sum1 = hash1;
            var sum2 = hash2;

            // SIMD dispatch: AVX-512BW (64 B/iter) → AVX2 (32 B/iter) → SSSE3 (16 B/iter), scalar tail handles the rest.
            if (Avx512BW.IsSupported && len >= 64)
            {
                var vtap = Tap512.Value;
                var vzero = Vector512<byte>.Zero;
                var vones = Vector512.Create((short)1);

                while (len >= 64)
                {
                    var blocks = Math.Min(len / 64, scalarMax / 64);

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
                    s2 += 64uL * (uint)blocks * sum1;
                    s2 += 64uL * HorizontalSum512(vs1Prev);
                    s2 += HorizontalSum512(vs2);

                    sum1 = (sum1 + HorizontalSum512(vs1)) % ModAdler;
                    sum2 = (uint)(s2 % ModAdler);
                }
            }
            else if (Avx2.IsSupported && len >= 32)
            {
                var vtap = Tap256.Value;
                var vzero = Vector256<byte>.Zero;
                var vones = Vector256.Create((short)1);

                while (len >= 32)
                {
                    var blocks = Math.Min(len / 32, scalarMax / 32);

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
                    s2 += 32uL * (uint)blocks * sum1;
                    s2 += 32uL * HorizontalSum256(vs1Prev);
                    s2 += HorizontalSum256(vs2);

                    sum1 = (sum1 + HorizontalSum256(vs1)) % ModAdler;
                    sum2 = (uint)(s2 % ModAdler);
                }
            }
            else if (Ssse3.IsSupported && len >= 16)
            {
                var vtap = Tap128.Value;
                var vzero = Vector128<byte>.Zero;
                var vones = Vector128.Create((short)1);

                while (len >= 16)
                {
                    var blocks = Math.Min(len / 16, scalarMax / 16);

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
                    s2 += 16uL * (uint)blocks * sum1;
                    s2 += 16uL * HorizontalSum128(vs1Prev);
                    s2 += HorizontalSum128(vs2);

                    sum1 = (sum1 + HorizontalSum128(vs1)) % ModAdler;
                    sum2 = (uint)(s2 % ModAdler);
                }
            }

            // Scalar tail for remaining bytes
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

        private static class Tap512
        {
            internal static readonly Vector512<sbyte> Value = NumericHelper.CreateDescendingByteVector<Vector512<sbyte>>();
        }

        private static class Tap256
        {
            internal static readonly Vector256<sbyte> Value = NumericHelper.CreateDescendingByteVector<Vector256<sbyte>>();
        }

        private static class Tap128
        {
            internal static readonly Vector128<sbyte> Value = NumericHelper.CreateDescendingByteVector<Vector128<sbyte>>();
        }
    }
}
