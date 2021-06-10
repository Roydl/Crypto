namespace Roydl.Crypto.Internal
{
    using System;
    using System.Collections;
    using System.Diagnostics.CodeAnalysis;
    using System.Globalization;
    using System.IO;
    using System.Linq;
    using System.Numerics;

    internal static class Helper
    {
        internal static void DestroyElement<TElement>(ref TElement element) where TElement : class
        {
            if (element == null)
                return;
            var isCollection = false;
            switch (element)
            {
                case ICollection:
                    isCollection = element is not Array;
                    break;
                case IDisposable disposable:
                    disposable.Dispose();
                    break;
            }
            var generation = GC.GetGeneration(element);
            element = null;
            GC.Collect(generation, GCCollectionMode.Forced);
            if (isCollection)
                GC.Collect();
        }

        internal static int GetBufferSize(this Stream stream)
        {
            const int m256 = 0x10000000;
            const int k128 = 0x20000;
            const int k64 = 0x10000;
            const int k32 = 0x8000;
            const int k16 = 0x4000;
            const int k8 = 0x2000;
            const int k4 = 0x1000;
            return stream switch
            {
                null => 0,
                BufferedStream => k4,
                MemoryStream ms => (int)Math.Min(ms.Length, m256),
                _ => (int)Math.Floor(stream.Length / 1.5d) switch
                {
                    > k128 => k128,
                    > k64 => k64,
                    > k32 => k32,
                    > k16 => k16,
                    > k8 => k8,
                    _ => k4
                }
            };
        }

        internal static T CreateBitMask<T>(int bitWidth) where T : struct, IComparable, IFormattable
        {
            var size = (int)MathF.Ceiling(bitWidth / 8f);
            switch (0xff.FromTo<int, T>())
            {
                case byte x:
                {
                    var mask = x;
                    for (var i = 1; i < size; i++)
                        mask ^= (byte)(0xff << (8 * i));
                    return (T)(object)mask;
                }
                case short x:
                {
                    var mask = x;
                    for (var i = 1; i < size; i++)
                        mask ^= (short)(0xff << (8 * i));
                    return (T)(object)mask;
                }
                case ushort x:
                {
                    var mask = x;
                    for (var i = 1; i < size; i++)
                        mask ^= (ushort)(0xff << (8 * i));
                    return (T)(object)mask;
                }
                case int x:
                {
                    var mask = x;
                    for (var i = 1; i < size; i++)
                        mask ^= 0xff << (8 * i);
                    return (T)(object)mask;
                }
                case uint x:
                {
                    var mask = x;
                    for (var i = 1; i < size; i++)
                        mask ^= 0xffu << (8 * i);
                    return (T)(object)mask;
                }
                case long x:
                {
                    var mask = x;
                    for (var i = 1; i < size; i++)
                        mask ^= 0xffL << (8 * i);
                    return (T)(object)mask;
                }
                case ulong x:
                {
                    var mask = x;
                    for (var i = 1; i < size; i++)
                        mask ^= 0xffuL << (8 * i);
                    return (T)(object)mask;
                }
                case BigInteger x:
                {
                    var mask = x;
                    BigInteger b = 0xff;
                    for (var i = 1; i < size; i++)
                        mask ^= b << (8 * i);
                    return (T)(object)mask;
                }
                default:
                    throw new NotSupportedException();
            }
        }

        internal static T ReverseBits<T>(this T value) where T : struct, IComparable, IFormattable
        {
            // String conversion is slower than shifting bits,
            // but it more accurate for some unusual bit widths.
            var bits = value switch
            {
                sbyte x => Convert.ToString(x, 2),
                byte x => Convert.ToString(x, 2),
                short x => Convert.ToString(x, 2),
                ushort x => Convert.ToString(x, 2),
                int x => Convert.ToString(x, 2),
                uint x => Convert.ToString(x, 2),
                long x => Convert.ToString(x, 2),
                ulong x => Convert.ToString((long)x, 2),
                _ => throw new NotSupportedException()
            };
            var size = bits.Length;
            while (size % 4 != 0)
                size++;
            if (bits.Length < size)
                bits = bits.PadLeft(size, '0');
            bits = new string(bits.Reverse().ToArray());
            return value switch
            {
                sbyte => (T)(object)Convert.ToSByte(bits, 2),
                byte => (T)(object)Convert.ToByte(bits, 2),
                short => (T)(object)Convert.ToInt16(bits, 2),
                ushort => (T)(object)Convert.ToUInt16(bits, 2),
                int => (T)(object)Convert.ToInt32(bits, 2),
                uint => (T)(object)Convert.ToUInt32(bits, 2),
                long => (T)(object)Convert.ToInt64(bits, 2),
                _ => (T)(object)Convert.ToUInt64(bits, 2)
            };
        }

        internal static TOut FromTo<TIn, TOut>(this TIn value) where TIn : struct where TOut : struct
        {
            if (typeof(TIn) == typeof(TOut))
                return (TOut)(object)value;

            // unchecked assignment
            return default(TOut) switch
            {
                sbyte => value switch
                {
                    byte x => (TOut)(object)(sbyte)x,
                    short x => (TOut)(object)(sbyte)x,
                    ushort x => (TOut)(object)(sbyte)x,
                    int x => (TOut)(object)(sbyte)x,
                    uint x => (TOut)(object)(sbyte)x,
                    long x => (TOut)(object)(sbyte)x,
                    ulong x => (TOut)(object)(sbyte)x,
                    nint x => (TOut)(object)(sbyte)x,
                    nuint x => (TOut)(object)(sbyte)x,
                    BigInteger x => (TOut)(object)(sbyte)(x & sbyte.MaxValue),
                    _ => throw new NotSupportedException()
                },
                byte => value switch
                {
                    sbyte x => (TOut)(object)(byte)x,
                    short x => (TOut)(object)(byte)x,
                    ushort x => (TOut)(object)(byte)x,
                    int x => (TOut)(object)(byte)x,
                    uint x => (TOut)(object)(byte)x,
                    long x => (TOut)(object)(byte)x,
                    ulong x => (TOut)(object)(byte)x,
                    nint x => (TOut)(object)(byte)x,
                    nuint x => (TOut)(object)(byte)x,
                    BigInteger x => (TOut)(object)(byte)(x & byte.MaxValue),
                    _ => throw new NotSupportedException()
                },
                short => value switch
                {
                    sbyte x => (TOut)(object)(short)x,
                    byte x => (TOut)(object)(short)x,
                    ushort x => (TOut)(object)(short)x,
                    int x => (TOut)(object)(short)x,
                    uint x => (TOut)(object)(short)x,
                    long x => (TOut)(object)(short)x,
                    ulong x => (TOut)(object)(short)x,
                    nint x => (TOut)(object)(short)x,
                    nuint x => (TOut)(object)(short)x,
                    BigInteger x => (TOut)(object)(short)(x & short.MaxValue),
                    _ => throw new NotSupportedException()
                },
                ushort => value switch
                {
                    sbyte x => (TOut)(object)(ushort)x,
                    byte x => (TOut)(object)(ushort)x,
                    short x => (TOut)(object)(ushort)x,
                    int x => (TOut)(object)(ushort)x,
                    uint x => (TOut)(object)(ushort)x,
                    long x => (TOut)(object)(ushort)x,
                    ulong x => (TOut)(object)(ushort)x,
                    nint x => (TOut)(object)(ushort)x,
                    nuint x => (TOut)(object)(ushort)x,
                    BigInteger x => (TOut)(object)(ushort)(x & ushort.MaxValue),
                    _ => throw new NotSupportedException()
                },
                int => value switch
                {
                    sbyte x => (TOut)(object)(int)x,
                    byte x => (TOut)(object)(int)x,
                    short x => (TOut)(object)(int)x,
                    ushort x => (TOut)(object)(int)x,
                    uint x => (TOut)(object)(int)x,
                    long x => (TOut)(object)(int)x,
                    ulong x => (TOut)(object)(int)x,
                    nint x => (TOut)(object)(int)x,
                    nuint x => (TOut)(object)(int)x,
                    BigInteger x => (TOut)(object)(int)(x & int.MaxValue),
                    _ => throw new NotSupportedException()
                },
                uint => value switch
                {
                    sbyte x => (TOut)(object)(uint)x,
                    byte x => (TOut)(object)(uint)x,
                    short x => (TOut)(object)(uint)x,
                    ushort x => (TOut)(object)(uint)x,
                    int x => (TOut)(object)(uint)x,
                    long x => (TOut)(object)(uint)x,
                    ulong x => (TOut)(object)(uint)x,
                    nint x => (TOut)(object)(uint)x,
                    nuint x => (TOut)(object)(uint)x,
                    BigInteger x => (TOut)(object)(uint)(x & uint.MaxValue),
                    _ => throw new NotSupportedException()
                },
                long => value switch
                {
                    sbyte x => (TOut)(object)(long)x,
                    byte x => (TOut)(object)(long)x,
                    short x => (TOut)(object)(long)x,
                    ushort x => (TOut)(object)(long)x,
                    int x => (TOut)(object)(long)x,
                    uint x => (TOut)(object)(long)x,
                    ulong x => (TOut)(object)(long)x,
                    nint x => (TOut)(object)(long)x,
                    nuint x => (TOut)(object)(long)x,
                    BigInteger x => (TOut)(object)(long)(x & long.MaxValue),
                    _ => throw new NotSupportedException()
                },
                ulong => value switch
                {
                    sbyte x => (TOut)(object)(ulong)x,
                    byte x => (TOut)(object)(ulong)x,
                    short x => (TOut)(object)(ulong)x,
                    ushort x => (TOut)(object)(ulong)x,
                    int x => (TOut)(object)(ulong)x,
                    uint x => (TOut)(object)(ulong)x,
                    long x => (TOut)(object)(ulong)x,
                    nint x => (TOut)(object)(ulong)x,
                    nuint x => (TOut)(object)(ulong)x,
                    BigInteger x => (TOut)(object)(ulong)(x & ulong.MaxValue),
                    _ => throw new NotSupportedException()
                },
                nint => value switch
                {
                    sbyte x => (TOut)(object)(nint)x,
                    byte x => (TOut)(object)(nint)x,
                    short x => (TOut)(object)(nint)x,
                    ushort x => (TOut)(object)(nint)x,
                    int x => (TOut)(object)(nint)x,
                    uint x => (TOut)(object)(nint)x,
                    long x => (TOut)(object)(nint)x,
                    ulong x => (TOut)(object)(nint)x,
                    nuint x => (TOut)(object)(nint)x,
                    BigInteger x => (TOut)(object)(nint)(IntPtr.Size switch
                    {
                        sizeof(long) => (long)(x & long.MaxValue),
                        sizeof(int) => (int)(x & int.MaxValue),
                        _ => throw new ArithmeticException()
                    }),
                    _ => throw new NotSupportedException()
                },
                nuint => value switch
                {
                    sbyte x => (TOut)(object)(nuint)x,
                    byte x => (TOut)(object)(nuint)x,
                    short x => (TOut)(object)(nuint)x,
                    ushort x => (TOut)(object)(nuint)x,
                    int x => (TOut)(object)(nuint)x,
                    uint x => (TOut)(object)(nuint)x,
                    long x => (TOut)(object)(nuint)x,
                    ulong x => (TOut)(object)(nuint)x,
                    nint x => (TOut)(object)(nuint)x,
                    BigInteger x => (TOut)(object)(nuint)(UIntPtr.Size switch
                    {
                        sizeof(ulong) => (ulong)(x & ulong.MaxValue),
                        sizeof(uint) => (uint)(x & uint.MaxValue),
                        _ => throw new ArithmeticException()
                    }),
                    _ => throw new NotSupportedException()
                },
                BigInteger => value switch
                {
                    sbyte x => (TOut)(object)(BigInteger)x,
                    byte x => (TOut)(object)(BigInteger)x,
                    short x => (TOut)(object)(BigInteger)x,
                    ushort x => (TOut)(object)(BigInteger)x,
                    int x => (TOut)(object)(BigInteger)x,
                    uint x => (TOut)(object)(BigInteger)x,
                    long x => (TOut)(object)(BigInteger)x,
                    ulong x => (TOut)(object)(BigInteger)x,
                    _ => throw new NotSupportedException()
                },
                _ => throw new NotSupportedException()
            };
        }

        internal static string ToHexStr<T>(this T num, int padding, bool prefix) where T : struct, IComparable, IFormattable
        {
            var str = num.ToString("x2", null);
            if (padding > 2)
                str = str.PadLeft(padding, '0');
            if (prefix)
                str = $"0x{str}";
            return str;
        }

        internal static BigInteger ToBigInt([AllowNull] this string value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return BigInteger.Zero;
            var flags = value.StartsWith("0x") ? NumberStyles.HexNumber : NumberStyles.Any;
            if (flags == NumberStyles.HexNumber)
                value = value[2..];
            return BigInteger.TryParse(value, flags, null, out var result) ? result : BigInteger.Zero;
        }
    }
}
